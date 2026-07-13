import ipaddress
import logging
import os
import socket
from typing import Dict, List, Optional

import psutil
from dotenv import load_dotenv

# Load settings from .env file
load_dotenv()

_log = logging.getLogger("network_monitor.config")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_interfaces() -> List[Dict]:
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    results = []

    for iface_name, addr_list in addrs.items():
        if iface_name in stats and not stats[iface_name].isup:
            continue
        ipv4 = netmask = None
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ipv4 = addr.address
                netmask = addr.netmask
        if not ipv4 or not netmask or ipv4.startswith("127."):
            continue
        try:
            network = ipaddress.ip_network(f"{ipv4}/{netmask}", strict=False)
            subnet = str(network)
        except ValueError:
            subnet = f"{ipv4}/24"
        results.append({
            "name": iface_name,
            "ipv4": ipv4,
            "subnet": subnet,
        })
    return results

def _score_interface(iface: Dict) -> int:
    name = iface["name"].lower()
    score = 0
    if name.startswith(("eth", "en")): score += 100
    elif name.startswith("wlan") or name.startswith("wl"): score += 80
    elif name.startswith("usb"): score += 60
    elif name.startswith(("br", "bond")): score += 40
    try:
        if ipaddress.ip_address(iface["ipv4"]).is_private:
            score += 50
    except ValueError:
        pass
    return score

def _auto_select_interface() -> tuple[str, str]:
    interfaces = _detect_interfaces()
    if not interfaces:
        return "eth0", "192.168.1.0/24"
    interfaces.sort(key=_score_interface, reverse=True)
    best = interfaces[0]
    return best["name"], best["subnet"]

# ---------------------------------------------------------------------------
# Network Setup
# ---------------------------------------------------------------------------
_auto_iface, _auto_subnet = _auto_select_interface()
INTERFACE: str = os.environ.get("INTERFACE", _auto_iface)
NETWORK_SUBNET: str = os.environ.get("NETWORK_SUBNET", _auto_subnet)

# ---------------------------------------------------------------------------
# Data Limits (Bytes)
# ---------------------------------------------------------------------------
# Limit 1: 1 GB
DATA_LIMIT_ALERT_BYTES: int = int(os.environ.get("DATA_LIMIT_ALERT_BYTES", "1073741824"))
# Limit 2: 3 GB
DATA_LIMIT_BLOCK_BYTES: int = int(os.environ.get("DATA_LIMIT_BLOCK_BYTES", "3221225472"))

# ---------------------------------------------------------------------------
# Email Configuration
# ---------------------------------------------------------------------------
SMTP_SERVER: str = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))

SMTP_USERNAME: str = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD: str = os.environ.get("SMTP_PASSWORD", "").strip()
EMAIL_ALERTS_ENABLED: bool = bool(SMTP_USERNAME and SMTP_PASSWORD)

ALERT_EMAIL_FROM: str = os.environ.get("ALERT_EMAIL_FROM", SMTP_USERNAME).strip()
ALERT_EMAIL_TO: str = os.environ.get("ALERT_EMAIL_TO", ALERT_EMAIL_FROM).strip()

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
DB_FILE: str = "monitor_history.db"
MMDB_FILE: str = "GeoLite2-City.mmdb"
