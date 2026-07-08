"""
Per-device, timestamped activity logs (one .log file per MAC address).

Design goals (based on user requirements)
──────────────────────────────────────────
Each device gets a single file:  device_logs/<mac>.log

Every entry in that file is a timestamped record so you can reconstruct
the device's complete history inside the network:

  CONNECTED        — when/where the device appeared (interface, gateway)
  NEW_CONN         — every new src→dst:port/proto path (connection trajectory)
  DOMAIN_VISIT     — DNS lookups (domain-level, HTTPS content is encrypted)
  ALERT            — full alert context written inline (type, bytes, action)
  DISCONNECTED     — when the device left the network

This means opening a single device log gives you the full story:
  "Device joined via eth0 at 10:00, opened HTTPS to 1.2.3.4:443, then
   triggered a 1 GB data alert at 10:07 which closed port 443."

Thread safety
─────────────
Each device has its own threading.Lock.  Both the sniffer thread (DNS/NEW_CONN)
and the main loop (CONNECTED, ALERT, DISCONNECTED) write to the same file;
the per-device lock prevents interleaved or corrupt lines.

Log rotation
────────────
RotatingFileHandler: 10 MB per file, 5 backups kept.
"""

import datetime
import logging
import os
import threading
from logging.handlers import RotatingFileHandler
from typing import Optional

import config

# ---------------------------------------------------------------------------
# Internal logger for this module's own messages
# ---------------------------------------------------------------------------
_internal_log = logging.getLogger("network_monitor.logger")

# ---------------------------------------------------------------------------
# Rotation settings
# ---------------------------------------------------------------------------
LOG_MAX_BYTES: int = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
LOG_BACKUP_COUNT: int = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

# ---------------------------------------------------------------------------
# Per-device lock registry
# ---------------------------------------------------------------------------
_locks_lock: threading.Lock = threading.Lock()
_file_locks: dict[str, threading.Lock] = {}

_loggers_lock: threading.Lock = threading.Lock()
_device_loggers: dict[str, logging.Logger] = {}

# Keep track of connections we've already logged per device so we only emit
# NEW_CONN once per unique (src_ip, dst_ip, dst_port, proto) 4-tuple.
# Protected by the per-device lock.
_seen_connections: dict[str, set] = {}


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _device_log_path(mac: str) -> str:
    """Return the log file path for a given MAC, guarded against path traversal."""
    safe = "".join(c for c in mac.lower() if c in "0123456789abcdef:")
    safe = safe.replace(":", "-")
    return os.path.join(config.LOG_DIR, f"{safe}.log")


def log_file_path(mac: str) -> str:
    """Public accessor — where a device's activity/history log lives."""
    return _device_log_path(mac)


# ---------------------------------------------------------------------------
# Locking helpers
# ---------------------------------------------------------------------------

def _get_lock(mac: str) -> threading.Lock:
    with _locks_lock:
        if mac not in _file_locks:
            _file_locks[mac] = threading.Lock()
        return _file_locks[mac]


def _get_device_logger(mac: str) -> logging.Logger:
    """Return (and lazily create) a RotatingFileHandler logger for this device."""
    with _loggers_lock:
        if mac not in _device_loggers:
            os.makedirs(config.LOG_DIR, exist_ok=True)
            logger = logging.getLogger(f"device.{mac}")
            logger.setLevel(logging.DEBUG)
            logger.propagate = False
            handler = RotatingFileHandler(
                _device_log_path(mac),
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
            _device_loggers[mac] = logger
    return _device_loggers[mac]


# ---------------------------------------------------------------------------
# Core write primitive
# ---------------------------------------------------------------------------

def _write(mac: str, line: str) -> None:
    """Write a single log line under the per-device lock."""
    lock = _get_lock(mac)
    with lock:
        try:
            _get_device_logger(mac).info(line)
        except Exception as exc:
            _internal_log.warning("Log write failed for %s: %s", mac, exc)


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sanitise(text: str) -> str:
    """Remove newlines and other control characters to prevent log injection."""
    return "".join(c if c.isprintable() and c not in "\r\n" else " " for c in text)


# ---------------------------------------------------------------------------
# Public logging API
# ---------------------------------------------------------------------------

def log_network_entry(mac: str, ip: str, interface: str, gateway_mac: str = "unknown") -> None:
    """Log when and where a device entered the network.

    Called immediately on CONNECTED so the log starts with entry context:
      [timestamp] CONNECTED ip=X.X.X.X interface=eth0 gateway_mac=aa:bb:...
    """
    iface = _sanitise(interface)
    gw = _sanitise(gateway_mac)
    _write(mac, f"[{_ts()}] CONNECTED        ip={ip} interface={iface} gateway_mac={gw}")


def log_disconnected(mac: str, ip: str) -> None:
    _write(mac, f"[{_ts()}] DISCONNECTED     ip={ip}")


def log_connection_path(
    mac: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
) -> None:
    """Log a new connection path (src→dst:port/proto) for this device.

    Only logs each unique 4-tuple once per session to avoid flooding the log
    with thousands of identical lines for persistent connections.
    """
    key = (src_ip, dst_ip, dst_port, proto)
    lock = _get_lock(mac)
    with lock:
        if mac not in _seen_connections:
            _seen_connections[mac] = set()
        if key in _seen_connections[mac]:
            return
        _seen_connections[mac].add(key)
        # Write inside the lock since we already hold it
        try:
            line = (
                f"[{_ts()}] NEW_CONN         "
                f"{src_ip} → {dst_ip}:{dst_port}/{proto.upper()}"
            )
            _get_device_logger(mac).info(line)
        except Exception as exc:
            _internal_log.warning("NEW_CONN log failed for %s: %s", mac, exc)


def log_domain_visit(mac: str, ip: str, domain: str) -> None:
    """Log a DNS lookup made by this device."""
    safe_domain = _sanitise(domain)
    _write(mac, f"[{_ts()}] DOMAIN_VISIT     ip={ip} domain={safe_domain}")


def log_alert(mac: str, ip: str, alert_type: str, details: str = "") -> None:
    """Write a full alert event inline in the device's timeline log.

    This is the key entry for reconstructing 'what triggered the alert':
      [timestamp] ALERT:DATA_TRIGGER  ip=... bytes=1073741824 action=port 443/TCP blocked
    """
    safe_type = _sanitise(alert_type)
    safe_details = _sanitise(details)
    separator = "-" * 72
    block = (
        f"{separator}\n"
        f"[{_ts()}] ALERT:{safe_type:<18} ip={ip}\n"
        f"           {safe_details}\n"
        f"{separator}"
    )
    _write(mac, block)


def log_event(mac: str, ip: str, event_type: str, detail: str = "") -> None:
    """Generic event log entry (kept for backward compatibility).

    Prefer the specialised functions above for new call sites.
    """
    safe_event = _sanitise(event_type)
    safe_detail = _sanitise(detail)
    _write(mac, f"[{_ts()}] {safe_event:<16} ip={ip} {safe_detail}")


# ---------------------------------------------------------------------------
# Connection count (for dashboard "Joins (24h)" column)
# ---------------------------------------------------------------------------

def _line_timestamp(line: str) -> Optional[datetime.datetime]:
    if not line.startswith("["):
        return None
    end = line.find("]")
    if end == -1:
        return None
    try:
        return datetime.datetime.strptime(line[1:end], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def count_connections(mac: str, hours: Optional[int] = None) -> int:
    """How many times this device has joined the network in the trailing N hours.

    Rolling window — always 'now minus N hours', stays accurate across restarts.
    """
    hours = hours if hours is not None else config.CONNECTION_COUNT_WINDOW_HOURS
    path = _device_log_path(mac)
    if not os.path.exists(path):
        return 0
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
    count = 0
    lock = _get_lock(mac)
    try:
        with lock, open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if "CONNECTED" not in line:
                    continue
                ts = _line_timestamp(line)
                if ts and ts >= cutoff:
                    count += 1
    except OSError as exc:
        _internal_log.warning("Could not read log for %s: %s", mac, exc)
    return count
