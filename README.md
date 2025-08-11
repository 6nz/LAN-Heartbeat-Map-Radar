# LAN Heartbeat Map (Radar)

LAN Heartbeat Map is a local-first network presence and latency visualizer. It periodically sweeps your private IPv4 subnet, captures response times, and serves a live dashboard to help you understand what is online on your LAN.

## Features

- **Zero-dependency scanning** – uses the operating system's `ping` utility; no root required.
- **ARP table parsing** to attach MAC addresses to discovered hosts.
- **SQLite storage** for device information, latency samples and outage events.
- **Outage detection** – heuristic marks potential power outages when many devices drop simultaneously.
- **Flap tracking** – counts how often a device disappears and reappears across sweeps.
- **FastAPI dashboard** – interactive web UI powered by ECharts with JSON endpoints for integrations.
- **Local-first** – all data stays on your machine.

## Requirements

- Python 3.10+
- `aiosqlite`
- `psutil`
- `fastapi`
- `uvicorn`

Install dependencies with:

```bash
pip install aiosqlite psutil fastapi uvicorn[standard]
```

## Usage

```bash
python lan_heartbeat_map.py
```

By default the server binds to `127.0.0.1:8000`. Open the URL in a browser to view the dashboard. The script automatically detects a private IPv4 subnet and begins scanning every 30 seconds.

Environment variables:

- `LHM_HOST` – override bind host (defaults to `127.0.0.1`).
- `LHM_PORT` – override bind port (defaults to `8000`).

The SQLite database is stored in `lan_heartbeat.sqlite` in the working directory.

### API

- `GET /api/summary` – JSON summary of current devices, latency buckets, and recent outage information.
- `GET /` – interactive dashboard.
- `GET /healthz` – simple health check endpoint.

## Potential Improvements

- Package as an installable CLI with configuration file support.
- Add IPv6 scanning and visualization.
- Expose additional analytics such as historical latency charts per device.
- Provide authentication options for the dashboard.
- Add tests and CI workflows.

## License

MIT
