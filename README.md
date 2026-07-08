# Home Network Monitor

Shows every device on your network with its IP, MAC, bandwidth used, and
ports in use — no whitelist needed. Optionally, add known devices to a
whitelist to also get "unauthorized device" alerts for anything new.

## What it does
- Scans your LAN (ARP) to see every connected device, live — including
  ones that haven't generated measurable traffic yet.
- Dashboard shows, per device: **IP, MAC, bandwidth used (highest first),
  and the actual ports it's talking on** (e.g. `443(HTTPS)`, `53(DNS)`),
  timestamped with when the snapshot was taken. Works out of the box with
  an empty `known_devices.json` — no setup required to just see what's on
  your network.
- *Optional*: if you add entries to `known_devices.json`, anything that
  connects and ISN'T on that list triggers an immediate email alert
  ("unauthorized device detected") with its IP, MAC, ports, and location
  info (see limitations below). Leave the file empty (`{}`, the default)
  and this step is simply skipped — plain visibility, no alerts.
- Tracks bytes transferred per device in a rolling window (default: 1 GB /
  10 minutes) and emails you when crossed, regardless of whitelist status.
- On trigger, closes the **specific offending port** by default (not the
  whole device) — set `BLOCK_MODE = "device"` in `config.py` if you'd
  rather it cut the device off entirely. Controlled by `AUTO_BLOCK_ENABLED`
  either way (starts off/log-only).
- Every alert email links to that device's full activity log.
- Logs everything per-device with timestamps: connects/disconnects, domains
  visited, and trigger events, in `device_logs/<mac>.log`.
- Counts how many times each device has joined the network in the last 24
  hours (rolling window, not a hard reset).

## IMPORTANT — read before deploying
To see traffic for *every* device on the network (not just this monitoring
machine's own traffic), this needs to run somewhere that actually sees that
traffic:
- **Best**: on the router/gateway itself (e.g. a Raspberry Pi set up as
  your gateway, or a router running OpenWrt/pfSense you can put this on).
- **Also works**: connected to a switch port configured to mirror/SPAN
  all LAN traffic, if your switch supports it.
- **If neither is available**: device discovery (who's on the network,
  unauthorized-device alerts) still works fine from any device on the
  LAN — ARP scanning doesn't need special positioning. But bandwidth
  totals will only be accurate for traffic to/from the monitoring
  machine itself, not other devices' traffic to the internet.

Only deploy this on a network and devices you own or are authorized to
monitor. If it's a shared network (roommates, coworkers, etc.), make sure
you're covered — expectations and rules on this vary by relationship and
local law.

## Setup
1. `pip install -r requirements.txt` (needs scapy + requests). If pip
   refuses with an "externally managed environment" error, add
   `--break-system-packages`, or use a virtual environment.
2. Edit `config.py`:
   - `NETWORK_SUBNET` — your LAN, e.g. `192.168.1.0/24`
   - `INTERFACE` — your network interface (`ip a` on Linux to list them)
   - `SMTP_*` / `ALERT_EMAIL_*` — your email settings. For Gmail, use an
     App Password (Google Account -> Security -> App Passwords), not your
     normal password.
   - `DATA_TRIGGER_BYTES` / `TRIGGER_WINDOW_SECONDS` — tune once you've
     watched the dashboard for a few days and know your normal usage.
   - `AUTO_BLOCK_ENABLED` — starts `False` (log-only) on purpose. Flip to
     `True` once you trust the tuning; until then it just prints what it
     *would* have blocked.
   - `BLOCK_MODE` — `"port"` (default) closes just the port responsible for
     the spike; `"device"` blocks the IP entirely.
3. `known_devices.json` starts empty (`{}`) — leave it that way to just get
   the plain dashboard with no whitelist. To also enable "unauthorized
   device" alerts, add trusted devices as MAC address -> name. Find MAC
   addresses on your router's admin page, or run this tool once and check
   the dashboard for MACs to whitelist.
4. Run as root (needed for packet capture, ARP, and firewall rules):
   `sudo python3 main.py`

## Files
- `main.py` — orchestration loop
- `device_scanner.py` — ARP-based device discovery
- `traffic_monitor.py` — bandwidth + connection + DNS tracking (background thread)
- `geolocation.py` — IP geolocation for external destinations
- `alerter.py` — email notifications
- `blocker.py` — firewall blocking (iptables)
- `logger.py` — per-device timestamped activity logs
- `config.py` — all settings
- `known_devices.json` — optional device whitelist (empty by default)

## Notes
- Websites visited are logged at the domain level (e.g. `example.com`),
  not full URLs — HTTPS encrypts the page path, so that's as much detail
  as network-level monitoring can see without decrypting traffic.
- Written for Linux (Raspberry Pi is a common choice). It's syntax-checked
  but not tested against a live network — test with `AUTO_BLOCK_ENABLED`
  off first. A Windows version would need `blocker.py` rewritten around
  Windows Firewall (`netsh`) and Npcap installed for scapy — ask if you
  want that version.
