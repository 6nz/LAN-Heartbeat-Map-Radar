#!/usr/bin/env python3
"""
LAN Heartbeat Map (Radar) – local-first network presence + latency visualizer.

- Periodically sweeps your private IPv4 subnet using OS ping (no admin needed).
- Parses ARP table to attach MAC addresses to discovered IPs.
- Stores history (devices, samples, events) in SQLite.
- Detects "power outage" events (heuristic on mass simultaneous drops).
- Tracks device flapping across sweeps.
- Serves a live dashboard (FastAPI + ECharts) and JSON endpoints.

Author: 6nz
License: MIT
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import os
import platform
import re
import socket
import sys
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Tuple

import aiosqlite
import psutil
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.middleware import CORSMiddleware
import uvicorn

# =========================
# Config (tweak as desired)
# =========================
DB_PATH = "lan_heartbeat.sqlite"
SCAN_INTERVAL_SEC = 30
PING_TIMEOUT_MS = 600
MAX_HOSTS_TO_SCAN = 512  # cap scans for huge subnets
MANUAL_CIDR: Optional[str] = None  # e.g., "192.168.1.0/24" to override autodetect

# Outage heuristic: mark an outage event if >=50% of previously-up devices drop
OUTAGE_DROP_FRACTION = 0.5
OUTAGE_MIN_PREV_UP = 8  # avoid noise on tiny nets

# Consider device "up" if seen within this many seconds
FRESHNESS_SEC = SCAN_INTERVAL_SEC * 2

APP_TITLE = "LAN Heartbeat Map (Radar)"

# Default bind; Windows firewalls sometimes block 0.0.0.0
DEFAULT_HOST = os.getenv("LHM_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("LHM_PORT", "8000"))

# =========================================================
# Platform helpers for ping + arp
# =========================================================

def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def ping_command(ip: str) -> List[str]:
    if is_windows():
        # -n 1 (one echo) -w timeout(ms)
        return ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    else:
        # -c 1 (one echo) -W timeout(seconds)
        timeout_s = max(1, int((PING_TIMEOUT_MS + 999) // 1000))
        return ["ping", "-c", "1", "-W", str(timeout_s), ip]


_LAT_REGEXES = [
    re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE),
    re.compile(r"Average\s*=\s*(\d+)\s*ms", re.IGNORECASE),  # Windows summary
]

def parse_latency_ms(ping_output: str) -> Optional[float]:
    for rx in _LAT_REGEXES:
        m = rx.search(ping_output)
        if m:
            try:
                return float(m.group(1))
            except:
                pass
    return None


async def run_ping(ip: str) -> Tuple[bool, Optional[float]]:
    # Call OS ping via subprocess for non-admin compatibility
    try:
        proc = await asyncio.create_subprocess_exec(
            *ping_command(ip),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=(PING_TIMEOUT_MS/1000 + 2))
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except:
                pass
            return (False, None)

        out = stdout.decode(errors="ignore")
        ok = (proc.returncode == 0) or ("TTL=" in out.upper())
        latency = parse_latency_ms(out) if ok else None
        return (ok, latency)
    except Exception:
        return (False, None)


async def get_arp_table() -> Dict[str, str]:
    """
    Return {ip: mac} in lowercase with ':' separators where possible.
    Tries platform-specific commands in order.
    """
    candidates = []
    if is_windows():
        candidates.append(["arp", "-a"])
    else:
        candidates.append(["ip", "neigh"])
        candidates.append(["arp", "-an"])

    mapping: Dict[str, str] = {}

    async def run_and_parse(cmd: List[str]):
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
            )
            out, _ = await proc.communicate()
            text = out.decode(errors="ignore")
        except Exception:
            return

        if is_windows() and "arp" in cmd[0]:
            # Example: "  192.168.1.1           00-11-22-33-44-55     dynamic"
            for line in text.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ip = parts[0]
                    mac = parts[1].strip().lower().replace("-", ":")
                    if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac):
                        mapping[ip] = mac
        else:
            # Linux/mac `ip neigh` OR `arp -an`
            # Examples:
            # "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            # "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            for line in text.splitlines():
                m1 = re.search(r"(\d+\.\d+\.\d+\.\d+).+lladdr\s+([0-9a-f:]{17})", line, re.IGNORECASE)
                m2 = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line, re.IGNORECASE)
                if m1:
                    ip, mac = m1.group(1), m1.group(2)
                    mapping[ip] = mac.lower()
                elif m2:
                    ip, mac = m2.group(1), m2.group(2)
                    mapping[ip] = mac.lower()

    for cmd in candidates:
        await run_and_parse(cmd)
        if mapping:
            break

    return mapping


# =========================================================
# Network detection
# =========================================================

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def _is_private(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in _PRIVATE_NETS)

def autodetect_cidr() -> Optional[ipaddress.IPv4Network]:
    # choose first active interface with private IPv4
    for name, addrs in psutil.net_if_addrs().items():
        try:
            stats = psutil.net_if_stats().get(name)
            if not stats or not stats.isup:
                continue
        except Exception:
            pass

        for addr in addrs:
            if getattr(addr, "family", None) == socket.AF_INET:
                ip_str = addr.address
                mask = getattr(addr, "netmask", None)
                try:
                    ip = ipaddress.IPv4Address(ip_str)
                except Exception:
                    continue
                if not _is_private(ip):
                    continue
                try:
                    if mask:
                        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    else:
                        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    return net
                except Exception:
                    continue
    return None


def pick_scan_hosts(net: ipaddress.IPv4Network) -> List[str]:
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > MAX_HOSTS_TO_SCAN:
        hosts = hosts[:MAX_HOSTS_TO_SCAN]
    return hosts


# =========================================================
# Persistence
# =========================================================

CREATE_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    hostname TEXT,
    first_seen INTEGER,
    last_seen INTEGER,
    flaps INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS samples (
    ts INTEGER,        -- epoch seconds
    ip TEXT,
    up INTEGER,        -- 1/0
    latency_ms REAL
);

CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_ip ON samples(ip);

CREATE TABLE IF NOT EXISTS events (
    ts INTEGER,
    type TEXT,         -- 'outage'
    data TEXT          -- JSON payload
);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);
"""

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_SQL)
        await db.commit()


async def upsert_device(db: aiosqlite.Connection, ip: str, mac: Optional[str], hostname: Optional[str], up: bool, now: int):
    # Insert or update device, manage first_seen/last_seen and flap count
    cur = await db.execute("SELECT last_seen FROM devices WHERE ip = ?", (ip,))
    row = await cur.fetchone()
    if row is None:
        await db.execute(
            "INSERT INTO devices(ip,mac,hostname,first_seen,last_seen,flaps) VALUES (?,?,?,?,?,?)",
            (ip, mac, hostname, now if up else None, now if up else None, 0)
        )
    else:
        prev_last_seen = row[0]
        was_up = False
        if prev_last_seen is not None:
            was_up = (now - int(prev_last_seen)) <= FRESHNESS_SEC
        flap_inc = 1 if (was_up and not up) or (not was_up and up) else 0

        await db.execute(
            "UPDATE devices SET mac=COALESCE(?, mac), hostname=COALESCE(?, hostname), "
            "last_seen=CASE WHEN ?=1 THEN ? ELSE last_seen END, "
            "first_seen=CASE WHEN first_seen IS NULL AND ?=1 THEN ? ELSE first_seen END, "
            "flaps=flaps+? WHERE ip=?",
            (mac, hostname, 1 if up else 0, now, 1 if up else 0, now, flap_inc, ip)
        )


async def add_sample(db: aiosqlite.Connection, ts: int, ip: str, up: bool, latency_ms: Optional[float]):
    await db.execute(
        "INSERT INTO samples(ts,ip,up,latency_ms) VALUES (?,?,?,?)",
        (ts, ip, 1 if up else 0, latency_ms)
    )


async def add_event(db: aiosqlite.Connection, ts: int, typ: str, payload: dict):
    await db.execute(
        "INSERT INTO events(ts,type,data) VALUES (?,?,?)",
        (ts, typ, json.dumps(payload))
    )


# =========================================================
# Scanner
# =========================================================

class Scanner:
    def __init__(self):
        self.net: Optional[ipaddress.IPv4Network] = None
        self.hosts: List[str] = []
        self.prev_up: set[str] = set()  # Previously up (from last sweep)
        self.running = False
        self._task: Optional[asyncio.Task] = None

    async def setup(self):
        if MANUAL_CIDR:
            self.net = ipaddress.IPv4Network(MANUAL_CIDR, strict=False)
        else:
            self.net = autodetect_cidr()
        if not self.net:
            raise RuntimeError("Failed to detect a private IPv4 network. Set MANUAL_CIDR.")

        self.hosts = pick_scan_hosts(self.net)
        await init_db()

    async def resolve_hostname(self, ip: str) -> Optional[str]:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=0.5
            )
        except Exception:
            return None

    async def sweep_once(self):
        now = int(dt.datetime.utcnow().timestamp())
        tasks = [run_ping(ip) for ip in self.hosts]
        results = await asyncio.gather(*tasks)

        up_now: set[str] = set()
        latencies: Dict[str, Optional[float]] = {}

        for ip, (ok, lat) in zip(self.hosts, results):
            if ok:
                up_now.add(ip)
            latencies[ip] = lat

        # Refresh ARP after pings to get IP->MAC
        arp_map = await get_arp_table()

        # Outage detection (compare vs prev_up)
        dropped = self.prev_up - up_now
        outage_event = False
        if len(self.prev_up) >= OUTAGE_MIN_PREV_UP:
            frac = len(dropped) / max(1, len(self.prev_up))
            if frac >= OUTAGE_DROP_FRACTION:
                outage_event = True

        async with aiosqlite.connect(DB_PATH) as db:
            # Record all samples
            for ip in self.hosts:
                await add_sample(db, now, ip, ip in up_now, latencies.get(ip))

            # Update devices table (+flaps)
            for ip in self.hosts:
                mac = arp_map.get(ip)
                hostname = None
                if ip in up_now:
                    try:
                        r = await asyncio.wait_for(self.resolve_hostname(ip), timeout=0.25)
                        if isinstance(r, tuple) and r:
                            hostname = r[0]
                    except Exception:
                        hostname = None
                await upsert_device(db, ip, mac, hostname, ip in up_now, now)

            # Add outage event if triggered
            if outage_event:
                await add_event(db, now, "outage", {
                    "prev_up": len(self.prev_up),
                    "dropped": len(dropped),
                    "fraction": round(len(dropped) / max(1, len(self.prev_up)), 3),
                })

            await db.commit()

        self.prev_up = up_now

    async def run(self):
        self.running = True
        try:
            while self.running:
                try:
                    await self.sweep_once()
                except Exception as e:
                    print(f"[scanner] sweep error: {e}", file=sys.stderr)
                await asyncio.sleep(SCAN_INTERVAL_SEC)
        except asyncio.CancelledError:
            # graceful stop
            pass

scanner = Scanner()

# =========================================================
# API + UI (with lifespan)
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await scanner.setup()
    task = asyncio.create_task(scanner.run())
    try:
        yield
    finally:
        scanner.running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

app = FastAPI(title=APP_TITLE, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

@app.get("/api/summary")
async def api_summary():
    now = int(dt.datetime.utcnow().timestamp())
    cutoff = now - FRESHNESS_SEC

    async with aiosqlite.connect(DB_PATH) as db:
        # Latest outage event
        cur = await db.execute("SELECT ts, data FROM events WHERE type='outage' ORDER BY ts DESC LIMIT 1")
        row = await cur.fetchone()
        outage = None
        if row:
            outage = {"ts": row[0], **json.loads(row[1])}

        # Current devices (fresh)
        cur = await db.execute("""
            SELECT ip, mac, hostname, first_seen, last_seen, flaps
            FROM devices
            WHERE last_seen IS NOT NULL AND last_seen >= ?
            ORDER BY ip
        """, (cutoff,))
        devices = []
        async for ip, mac, hostname, first_seen, last_seen, flaps in cur:
            # get last sample latency for this IP
            c2 = await db.execute("""
                SELECT latency_ms FROM samples WHERE ip=? ORDER BY ts DESC LIMIT 1
            """, (ip,))
            r2 = await c2.fetchone()
            latency = r2[0] if r2 else None
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "flaps": flaps,
                "latency_ms": latency
            })

        # Latency buckets
        buckets = {"<=20":0, "21-50":0, "51-100":0, ">100":0}
        for d in devices:
            lat = d["latency_ms"]
            if lat is None:
                continue
            if lat <= 20: buckets["<=20"] += 1
            elif lat <= 50: buckets["21-50"] += 1
            elif lat <= 100: buckets["51-100"] += 1
            else: buckets[">100"] += 1

        # History sparkline (last 60 mins, up count per sweep)
        since = now - 3600
        cur = await db.execute("""
            SELECT ts, SUM(up) FROM samples
            WHERE ts >= ?
            GROUP BY ts
            ORDER BY ts ASC
        """, (since,))
        history = [{"ts": ts, "up": upcnt} for ts, upcnt in await cur.fetchall()]

    subnet = str(scanner.net) if scanner.net else "unknown"
    total_hosts = len(scanner.hosts)
    current_up = len(devices)

    return JSONResponse({
        "now": now,
        "subnet": subnet,
        "total_hosts": total_hosts,
        "current_up": current_up,
        "buckets": buckets,
        "devices": devices,
        "outage": outage,
        "history": history,
    })


@app.get("/", response_class=HTMLResponse)
async def ui_root():
    # Minimal modern UI + ECharts; pulls from /api/summary every 5s
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{APP_TITLE}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/echarts@5"></script>
<style>
:root {{
  --bg: #0f1115; --card:#171922; --muted:#8b90a0; --fg:#e9ecf1; --accent:#6ae3ff; --ok:#66e39a; --warn:#ffd166; --bad:#ff6b6b;
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  background: radial-gradient(1000px 500px at 20% 0%, #151826 0%, #0f1115 70%);
  color: var(--fg);
  margin: 0; padding: 24px;
}}
h1 {{ font-size: 24px; margin: 0 0 12px 0; letter-spacing: 0.3px; }}
.topbar {{
  display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom: 18px;
}}
.statgrid {{ display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:12px; margin: 16px 0 24px; }}
.card {{
  background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01));
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 14px; padding: 14px 16px;
  backdrop-filter: blur(6px);
}}
.kv {{ font-size:12px; color: var(--muted); }}
.v  {{ font-size:20px; font-weight:700; }}
.grid {{ display:grid; grid-template-columns: 1.8fr 1.2fr; gap: 12px; }}
.table-wrap {{ overflow:auto; max-height: 56vh; }}
table {{ width:100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ text-align:left; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.06); }}
th {{ position: sticky; top:0; background: #131520; z-index:1; }}
.badge {{ padding: 4px 8px; border-radius: 999px; font-size: 12px; display:inline-block; }}
.lat-g {{ background: rgba(102,227,154,0.14); color: #7af0b3; border:1px solid rgba(102,227,154,0.4);}}
.lat-y {{ background: rgba(255,209,102,0.14); color: #ffd166; border:1px solid rgba(255,209,102,0.4);}}
.lat-o {{ background: rgba(255,153,85,0.12); color: #ff9955; border:1px solid rgba(255,153,85,0.35);}}
.lat-r {{ background: rgba(255,107,107,0.12); color: #ff8d8d; border:1px solid rgba(255,107,107,0.35);}}
.banner {{
  border-left: 4px solid var(--bad); padding: 8px 12px; background: rgba(255,107,107,0.08);
  color:#ffb3b3; border-radius: 8px; margin: 8px 0 14px;
}}
footer {{ color: var(--muted); margin-top: 14px; font-size: 12px; opacity: 0.8; }}
</style>
</head>
<body>
  <div class="topbar">
    <h1>🌐 {APP_TITLE}</h1>
    <div class="kv" id="meta"></div>
  </div>

  <div id="banner"></div>

  <div class="statgrid">
    <div class="card">
      <div class="kv">Subnet</div>
      <div class="v" id="subnet">—</div>
    </div>
    <div class="card">
      <div class="kv">Hosts Scanned</div>
      <div class="v" id="total">—</div>
    </div>
    <div class="card">
      <div class="kv">Currently Up</div>
      <div class="v" id="up">—</div>
    </div>
    <div class="card">
      <div class="kv">Updated</div>
      <div class="v" id="updated">—</div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div style="height: 46vh;" id="latChart"></div>
    </div>
    <div class="card">
      <div style="height: 46vh;" id="sparkChart"></div>
    </div>
  </div>

  <div class="card" style="margin-top:12px;">
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>IP</th><th>Hostname</th><th>MAC</th>
          <th>Latency</th><th>Last Seen</th><th>Flaps</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

  <footer>Local-first. No cloud. /api/summary available for integrations.</footer>

<script>
const latChart = echarts.init(document.getElementById('latChart'));
const sparkChart = echarts.init(document.getElementById('sparkChart'));

function fmtTs(ts){{
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}}
function bucketBadge(ms){{
  if (ms == null) return '<span class="badge lat-r">–</span>';
  if (ms <= 20) return '<span class="badge lat-g">' + ms.toFixed(0) + ' ms</span>';
  if (ms <= 50) return '<span class="badge lat-y">' + ms.toFixed(0) + ' ms</span>';
  if (ms <= 100) return '<span class="badge lat-o">' + ms.toFixed(0) + ' ms</span>';
  return '<span class="badge lat-r">' + ms.toFixed(0) + ' ms</span>';
}}

function draw(summary){{
  document.getElementById('subnet').textContent = summary.subnet;
  document.getElementById('total').textContent = summary.total_hosts;
  document.getElementById('up').textContent = summary.current_up;
  document.getElementById('updated').textContent = fmtTs(summary.now);
  document.getElementById('meta').textContent = 'Devices seen in last ' + {FRESHNESS_SEC} + 's are considered UP';

  // Banner
  const banner = document.getElementById('banner');
  banner.innerHTML = '';
  if (summary.outage && (summary.now - summary.outage.ts) < 300) {{
    banner.innerHTML = '<div class="banner">⚠️ Potential outage at '
      + fmtTs(summary.outage.ts) + ': dropped ' + summary.outage.dropped
      + ' / ' + summary.outage.prev_up + ' devices (' + (summary.outage.fraction*100).toFixed(0) + '%)</div>';
  }}

  // Latency buckets chart (donut)
  const bk = summary.buckets;
  latChart.setOption({{
    backgroundColor: 'transparent',
    tooltip: {{ trigger: 'item' }},
    title: {{ text: 'Latency Buckets', left: 'center', top: 4, textStyle: {{ color:'#cfd6e6', fontSize: 14 }} }},
    series: [{{
      type: 'pie', radius: ['45%','70%'],
      data: [
        {{value: bk['<=20'], name: '<=20ms'}},
        {{value: bk['21-50'], name: '21–50ms'}},
        {{value: bk['51-100'], name: '51–100ms'}},
        {{value: bk['>100'], name: '>100ms'}}
      ],
      label: {{ color:'#cfd6e6' }},
      itemStyle: {{
        color: (p) => ['#66e39a','#ffd166','#ff9955','#ff6b6b'][p.dataIndex]
      }}
    }}]
  }});

  // Sparkline chart (up count over time)
  const xs = summary.history.map(p => new Date(p.ts*1000).toLocaleTimeString());
  const ys = summary.history.map(p => p.up);
  sparkChart.setOption({{
    backgroundColor: 'transparent',
    title: {{ text: 'Up Devices (Last Hour)', left: 'center', top: 4, textStyle: {{ color:'#cfd6e6', fontSize: 14 }} }},
    xAxis: {{ type:'category', data: xs, axisLabel: {{ color:'#9aa3b9' }} }},
    yAxis: {{ type:'value', axisLabel: {{ color:'#9aa3b9' }} }},
    grid: {{ left: 30, right: 10, top: 36, bottom: 24 }},
    series: [{{
      data: ys,
      type: 'line',
      smooth: true,
      areaStyle: {{ opacity: 0.2 }},
      lineStyle: {{ width: 2, color: '#6ae3ff' }},
      itemStyle: {{ color: '#6ae3ff' }}
    }}]
  }});

  // Table
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  summary.devices.forEach(d => {{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${{d.ip}}</td>
      <td>${{d.hostname || '—'}}</td>
      <td>${{d.mac || '—'}}</td>
      <td>${{bucketBadge(d.latency_ms)}}</td>
      <td>${{d.last_seen ? fmtTs(d.last_seen) : '—'}}</td>
      <td>${{d.flaps}}</td>
    `;
    tbody.appendChild(tr);
  }});
}}

async function refresh(){{
  try {{
    const r = await fetch('/api/summary');
    const js = await r.json();
    draw(js);
  }} catch(e) {{
    console.error(e);
  }}
}}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""
    return HTMLResponse(html)


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


def port_available(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        return True
    except OSError:
        return False


def pick_host_port() -> Tuple[str, int]:
    host = DEFAULT_HOST
    port = DEFAULT_PORT
    if port_available(host, port):
        return host, port
    for p in (8001, 8080, 5000, 3000):
        if port_available(host, p):
            return host, p
    return host, 0  # OS will pick an ephemeral port


def main():
    host, port = pick_host_port()
    print(f"→ Starting {APP_TITLE}")
    print("   DB:", os.path.abspath(DB_PATH))
    if port == 0:
        print("   Scan every", SCAN_INTERVAL_SEC, "seconds. (Ephemeral port)")
    else:
        print("   Scan every", SCAN_INTERVAL_SEC, "seconds.")
    try:
        uvicorn.run(app, host=host, port=port, log_level="info")
    except OSError as e:
        # Final fallback: loopback + ephemeral port
        print(f"[warn] uvicorn bind failed on {host}:{port} ({e}). Retrying on 127.0.0.1:0 …")
        uvicorn.run(app, host="127.0.0.1", port=0, log_level="info")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
