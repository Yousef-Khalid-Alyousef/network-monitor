"""
Main orchestration loop:
  1. ARP-scans the LAN every SCAN_INTERVAL_SECONDS to discover who's connected,
     showing IP, MAC, bandwidth, and ports in use for every device.
  2. If known_devices.json has entries, flags devices NOT on that list as
     unauthorized.  Leave it empty ({}) for plain visibility with no alerts.
  3. Watches per-device bandwidth (via traffic_monitor's sniffer thread) and
     fires when a device crosses DATA_TRIGGER_BYTES within the trigger window.
  4. Emails alerts (rate-limited), logs everything with timestamps, and
     optionally closes the specific offending port or blocks the device entirely.

Run as root: sudo python3 main.py

Race-condition summary
──────────────────────
- ip_to_mac is updated atomically via state.set_ip_to_mac() before any reads
  in the sniffer thread, preventing torn reads.
- previously_present, alerted_*, last_window are only ever touched by the main
  loop (single thread) so they need no locking.
- Traffic counters are accessed via snapshot methods that copy-under-lock.
- Graceful shutdown via SIGTERM / KeyboardInterrupt calls blocker.clear_rules()
  to leave the firewall clean.
"""

import datetime
import json
import logging
import logging.config
import os
import signal
import sys
import threading
import time
from typing import Dict, Set

import alerter
import blocker
import config
import device_scanner
import geolocation
import logger as device_logger
import traffic_monitor

# ---------------------------------------------------------------------------
# Logging setup (stdlib logging to stdout + rotating file for the monitor itself)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
_log = logging.getLogger("network_monitor.main")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_known_devices() -> Dict[str, str]:
    if not os.path.exists(config.KNOWN_DEVICES_FILE):
        return {}
    try:
        with open(config.KNOWN_DEVICES_FILE, encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            _log.error("known_devices.json must be a JSON object (got %s)", type(raw).__name__)
            return {}
        return {str(mac).lower(): str(name) for mac, name in raw.items()}
    except (json.JSONDecodeError, OSError) as exc:
        _log.error("Failed to load known_devices.json: %s", exc)
        return {}


def _format_ports(ports, limit: int = 10) -> str:
    if not ports:
        return "none recorded yet"
    shown = ports[:limit]
    text = ", ".join(
        f"{proto} {traffic_monitor.port_label(port)}" for proto, port in shown
    )
    if len(ports) > limit:
        text += f", +{len(ports) - limit} more"
    return text


def print_dashboard(known_devices: Dict[str, str], mac_to_ip: Dict[str, str]) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = traffic_monitor.state.dashboard_rows(known_devices, mac_to_ip)
    print(f"\n=== Snapshot: {now} ===")
    print(f"{'IP':16} {'MAC':18} {'Name':22} {'Bytes (window)':>16} {'Joins (24h)':>13}")
    print("-" * 90)
    for r in rows:
        joins = device_logger.count_connections(r["mac"])
        print(
            f"{r['ip']:16} {r['mac']:18} {r['name']:22} {r['bytes']:>16,} {joins:>13}"
        )
        print(f"    Ports: {_format_ports(r['ports'])}")


# ---------------------------------------------------------------------------
# Alert handlers
# ---------------------------------------------------------------------------

def handle_unauthorized(mac: str, ip: str) -> None:
    geo = geolocation.geolocate_ip(ip)
    location = (
        "On your local network (private IP has no external location)"
        if not geo
        else f"{geo['city']}, {geo['region']}, {geo['country']} (ISP: {geo['isp']})"
    )
    ports_note = _format_ports(traffic_monitor.state.ports_in_use(mac))

    # Write alert inline in this device's timeline log
    device_logger.log_alert(
        mac, ip, "UNAUTHORIZED_DEVICE",
        f"location={location} | ports={ports_note} | log={device_logger.log_file_path(mac)}",
    )

    body = alerter.build_alert_body(
        {"ip": ip, "mac": mac, "known_name": "UNKNOWN / UNAUTHORIZED"},
        reason="A device not on your known-devices list joined the network",
        extra=(
            f"Location: {location}\n"
            f"Ports in use: {ports_note}\n"
            f"Full activity log: {device_logger.log_file_path(mac)}"
        ),
    )
    alerter.send_alert("Unauthorized device detected on your network", body)


def _apply_block(ip: str, top_port) -> str:
    """Block according to config.BLOCK_MODE. Returns a human-readable note."""
    live = config.AUTO_BLOCK_ENABLED
    suffix = "blocked" if live else "log-only, not actually blocked"
    if config.BLOCK_MODE == "port" and top_port:
        proto, port = top_port
        blocker.block_ip_port(ip, port, proto.lower())
        return f"Closed port {port}/{proto} for {ip} ({suffix})"
    blocker.block_ip(ip)
    return f"Blocked all traffic from {ip} ({suffix})"


def handle_data_trigger(
    mac: str, ip: str, bytes_used: int, known_devices: Dict[str, str]
) -> None:
    geo_lines = []
    for remote_ip in list(traffic_monitor.state.get_remote_ips_snapshot(mac))[:5]:
        geo = geolocation.geolocate_ip(remote_ip)
        if geo:
            geo_lines.append(
                f"  {remote_ip} -> {geo['city']}, {geo['country']} ({geo['isp']})"
            )

    action_note = _apply_block(ip, traffic_monitor.state.top_port_for_mac(mac))

    extra = (
        f"Bytes used: {bytes_used:,}\n"
        f"Ports in use: {_format_ports(traffic_monitor.state.ports_in_use(mac))}\n"
        f"Action taken: {action_note}\n"
        f"Full activity log: {device_logger.log_file_path(mac)}"
    )
    if geo_lines:
        extra += "\nRecent external destinations:\n" + "\n".join(geo_lines)

    # Write alert inline in this device's timeline log so it appears in context
    device_logger.log_alert(
        mac, ip, "DATA_TRIGGER",
        f"bytes={bytes_used:,} | action={action_note} | ports={_format_ports(traffic_monitor.state.ports_in_use(mac))}",
    )

    body = alerter.build_alert_body(
        {"ip": ip, "mac": mac, "known_name": known_devices.get(mac, "UNKNOWN")},
        reason=(
            f"Data usage crossed {config.DATA_TRIGGER_BYTES:,} bytes "
            f"within {config.TRIGGER_WINDOW_SECONDS}s"
        ),
        extra=extra,
    )
    alerter.send_alert("High data usage detected", body)


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_event: threading.Event = threading.Event()


def _handle_signal(signum, frame) -> None:
    _log.info("Received signal %s — shutting down.", signum)
    _shutdown_event.set()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    known_devices = load_known_devices()
    previously_present: Set[str] = set()
    alerted_unauthorized: Set[str] = set()
    alerted_data_trigger: Set[str] = set()
    last_window_start: float = traffic_monitor.state.get_window_start()

    # Start the packet sniffer in a background daemon thread
    sniffer_thread = threading.Thread(
        target=traffic_monitor.start_sniffing,
        daemon=True,
        name="PacketSniffer",
    )
    sniffer_thread.start()
    _log.info("Network monitor running. Press Ctrl+C or send SIGTERM to stop.")

    try:
        while not _shutdown_event.is_set():
            # --- Discover devices ---
            try:
                devices = device_scanner.scan_network()
            except Exception as exc:
                _log.error("Unexpected error during network scan: %s", exc)
                _shutdown_event.wait(timeout=config.SCAN_INTERVAL_SECONDS)
                continue

            current: Dict[str, str] = {d["mac"]: d["ip"] for d in devices}

            # Atomically update ip→mac so the sniffer thread sees a consistent view
            traffic_monitor.state.set_ip_to_mac(
                {ip: mac for mac, ip in current.items()}
            )

            # --- Detect joins / departures ---
            joined = set(current) - previously_present
            left = previously_present - set(current)

            for mac in joined:
                ip = current[mac]
                # Log entry point: which interface and (if detectable) gateway
                device_logger.log_network_entry(
                    mac, ip,
                    interface=config.INTERFACE,
                    gateway_mac="see-router-arp-table",  # ARP doesn't expose gateway MAC directly
                )
                if (
                    known_devices
                    and mac not in known_devices
                    and mac not in alerted_unauthorized
                ):
                    alerted_unauthorized.add(mac)
                    try:
                        handle_unauthorized(mac, ip)
                    except Exception as exc:
                        _log.error("Error handling unauthorized device %s: %s", mac, exc)

            for mac in left:
                device_logger.log_disconnected(mac, "-")

            previously_present = set(current)

            # --- Reset per-window alert tracking when the window rolls over ---
            current_window_start = traffic_monitor.state.get_window_start()
            if current_window_start != last_window_start:
                alerted_data_trigger.clear()
                last_window_start = current_window_start

            # --- Check bandwidth triggers ---
            # Use a snapshot to avoid "dict changed size during iteration"
            byte_snapshot = traffic_monitor.state.get_byte_counts_snapshot()
            for mac, bytes_used in byte_snapshot.items():
                if (
                    bytes_used >= config.DATA_TRIGGER_BYTES
                    and mac not in alerted_data_trigger
                ):
                    alerted_data_trigger.add(mac)
                    try:
                        handle_data_trigger(
                            mac, current.get(mac, "unknown"), bytes_used, known_devices
                        )
                    except Exception as exc:
                        _log.error("Error handling data trigger for %s: %s", mac, exc)

            # --- Dashboard ---
            try:
                print_dashboard(known_devices, current)
            except Exception as exc:
                _log.error("Dashboard render error: %s", exc)

            _shutdown_event.wait(timeout=config.SCAN_INTERVAL_SECONDS)

    finally:
        _log.info("Cleaning up firewall rules…")
        try:
            blocker.clear_rules()
        except Exception as exc:
            _log.error("Error clearing firewall rules: %s", exc)
        _log.info("Stopped.")


if __name__ == "__main__":
    main()
