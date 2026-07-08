"""
ARP-based device discovery: find every device currently on the LAN.

Security improvements:
  - Validates returned IP and MAC strings before passing them upstream.
  - Catches and logs scapy exceptions so the main loop keeps running on
    transient errors (e.g. a momentary interface failure).
  - Subnet is read from config (validated at import time as a proper CIDR).
"""

import logging
import re
from typing import List, Optional

from scapy.all import ARP, Ether, srp

import config

_log = logging.getLogger("network_monitor.device_scanner")

# Pre-compiled patterns for a simple sanity check on scapy's output
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_IP_RE  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def _valid_ip(ip: str) -> bool:
    return bool(_IP_RE.match(ip))


def scan_network(subnet: Optional[str] = None, iface: Optional[str] = None) -> List[dict]:
    """Return a list of {'ip': ..., 'mac': ...} for every device that answers
    an ARP request on the given subnet.

    Works from anywhere on the LAN — ARP scanning doesn't require the monitor
    to be positioned at the router.  Returns an empty list on error.
    """
    subnet = subnet or config.NETWORK_SUBNET
    iface = iface or config.INTERFACE

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(packet, timeout=3, iface=iface, verbose=0)
    except Exception as exc:
        _log.error("ARP scan failed (iface=%s, subnet=%s): %s", iface, subnet, exc)
        return []

    results: List[dict] = []
    for _, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc.lower()
        if not _valid_ip(ip) or not _valid_mac(mac):
            _log.warning("Skipping ARP reply with unexpected IP/MAC: ip=%r mac=%r", ip, mac)
            continue
        results.append({"ip": ip, "mac": mac})
    return results
