# Network Monitor

A Python network monitor that tracks local network devices, logs traffic usage, performs geolocation lookup, sends email alerts, and can block devices that exceed configured data limits.

## Features

- Detects and monitors devices on your local subnet
- Tracks per-device traffic usage
- Sends email alerts when usage exceeds alert threshold
- Blocks devices when usage exceeds block threshold
- Auto-detects network interface and subnet
- Cross-platform launch scripts for Linux/Raspberry Pi and Windows

## Requirements

- Python 3
- OS permissions for packet capture and firewall actions (administrator/root recommended)

Install dependencies from:

- `/home/runner/work/network-monitor/network-monitor/requirements.txt`

## Quick Start

### Linux / Raspberry Pi

1. Open a terminal in `/home/runner/work/network-monitor/network-monitor`
2. Run:

```bash
chmod +x run_monitor.sh
./run_monitor.sh
```

What the script does:
- Creates `.venv` if missing
- Installs dependencies
- Creates `known_devices.json` if missing
- Creates `.env` from `.env.example` on first run
- Launches the monitor (with `sudo` when needed)

### Windows

1. Open Command Prompt in `/home/runner/work/network-monitor/network-monitor`
2. Run:

```bat
run_monitor.bat
```

The script creates the virtual environment, installs dependencies, prepares `.env`, and starts the monitor.

## Configuration

Copy and edit environment settings:

- Source template: `/home/runner/work/network-monitor/network-monitor/.env.example`
- Active file: `.env` (ignored by git)

Key settings:

- `SMTP_USERNAME`, `SMTP_PASSWORD`, `ALERT_EMAIL_TO`
- `DATA_LIMIT_ALERT_BYTES` (default 1 GB)
- `DATA_LIMIT_BLOCK_BYTES` (default 3 GB)
- Optional overrides: `INTERFACE`, `NETWORK_SUBNET`

## Run Directly

You can also run directly after environment setup:

```bash
python main.py
```

Main entry point:

- `/home/runner/work/network-monitor/network-monitor/main.py`

## Notes

- `__pycache__` and `.pyc` files are generated automatically and are not required in the repository.
- Keep `.env` private and never commit real credentials.
