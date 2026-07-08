"""
Tracks per-device (per-MAC) bandwidth usage, live connections, and remote
destinations by passively sniffing traffic on the configured interface.

Race-condition mitigations
──────────────────────────
The original code stored all state in bare module-level dicts shared between
the sniffer thread (writer) and the main orchestration loop (reader). Any
mutation during iteration — or two threads mutating simultaneously — could
produce:
  - RuntimeError: dictionary changed size during iteration
  - Silently wrong byte totals (torn reads of concurrent increments)
  - `KeyError` from a key appearing between `in` check and `[]` access

All state is now encapsulated in `MonitorState`, whose public methods acquire
a `threading.RLock` before every mutation or snapshot.  Using an RLock (vs a
plain Lock) lets the same thread re-enter safely if needed (e.g. a method
calls another method on the same instance).

The `ip_to_mac` mapping that was written from the main thread while being read
in the sniffer thread is also covered by the same lock.

Note: this only sees traffic that actually reaches THIS machine's network
interface. On a normal switched Wi-Fi/LAN, that means traffic to/from this
host. To see traffic for every device on the network, run this on the
router/gateway itself, or connect it to a switch port configured for
mirroring (SPAN port). See README.md for details.
"""

import ipaddress
import logging
import threading
import time
from collections import defaultdict
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from scapy.all import sniff, IP, TCP, UDP, DNSQR

import config
import logger as device_logger

_log = logging.getLogger("network_monitor.traffic_monitor")

# ---------------------------------------------------------------------------
# Well-known port names
# ---------------------------------------------------------------------------
COMMON_PORTS: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 6881: "BitTorrent", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


def port_label(port: int) -> str:
    name = COMMON_PORTS.get(port)
    return f"{port}({name})" if name else str(port)


# ---------------------------------------------------------------------------
# Thread-safe state container
# ---------------------------------------------------------------------------

class MonitorState:
    """All mutable traffic-monitoring state, protected by a single RLock.

    Public methods are the only safe way to read or write state.  Do NOT
    access the private `_*` attributes from outside this class.
    """

    def __init__(self) -> None:
        self._lock: threading.RLock = threading.RLock()

        # bytes per MAC in the current window
        self._byte_counts: Dict[str, int] = defaultdict(int)
        # bytes per (mac, proto, dport) — used to find the "top offending port"
        self._port_byte_counts: Dict[Tuple[str, str, int], int] = defaultdict(int)
        # set of (proto, sport, dst_ip, dport) tuples per MAC
        self._connections_by_mac: Dict[str, Set[Tuple]] = defaultdict(set)
        # remote public IPs contacted by each MAC
        self._remote_ips_by_mac: Dict[str, Set[str]] = defaultdict(set)
        # IP → MAC mapping, refreshed by the main loop after every ARP scan
        self._ip_to_mac: Dict[str, str] = {}
        self._window_start: float = time.monotonic()

    # -----------------------------------------------------------------------
    # ip_to_mac property — writable by main thread, readable by sniffer thread
    # -----------------------------------------------------------------------

    def set_ip_to_mac(self, mapping: Dict[str, str]) -> None:
        """Atomically replace the IP→MAC mapping after an ARP scan."""
        with self._lock:
            self._ip_to_mac = dict(mapping)

    def get_mac_for_ip(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._ip_to_mac.get(ip)

    # -----------------------------------------------------------------------
    # Packet handling
    # -----------------------------------------------------------------------

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    def _reset_window_if_needed(self) -> None:
        """Reset byte counters when the trigger window has elapsed.
        Caller must already hold self._lock.
        """
        if time.monotonic() - self._window_start > config.TRIGGER_WINDOW_SECONDS:
            self._byte_counts.clear()
            self._port_byte_counts.clear()
            self._window_start = time.monotonic()

    def handle_packet(self, pkt) -> None:
        """Process a single captured packet.  Called from the sniffer thread."""
        if IP not in pkt:
            return

        src_ip: str = pkt[IP].src
        dst_ip: str = pkt[IP].dst
        pkt_len: int = len(pkt)

        with self._lock:
            self._reset_window_if_needed()
            mac = self._ip_to_mac.get(src_ip)
            if not mac:
                return

            self._byte_counts[mac] += pkt_len

            proto = sport = dport = None
            if TCP in pkt:
                proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport

            if proto:
                conn_key = (proto, sport, dst_ip, dport)
                is_new_conn = conn_key not in self._connections_by_mac[mac]
                self._connections_by_mac[mac].add(conn_key)
                self._port_byte_counts[(mac, proto, dport)] += pkt_len
            else:
                is_new_conn = False

            if not self._is_private(dst_ip):
                self._remote_ips_by_mac[mac].add(dst_ip)

        # Log new connection paths and DNS queries outside the main lock
        # to avoid holding it during disk I/O.
        if is_new_conn and proto:
            try:
                device_logger.log_connection_path(mac, src_ip, dst_ip, dport, proto)
            except Exception as exc:
                _log.debug("NEW_CONN log error: %s", exc)

        if pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                device_logger.log_domain_visit(mac, src_ip, domain)
            except Exception as exc:
                _log.debug("DNS log error: %s", exc)

    # -----------------------------------------------------------------------
    # Read-only snapshots (safe to call from any thread)
    # -----------------------------------------------------------------------

    def get_byte_counts_snapshot(self) -> Dict[str, int]:
        """Return a shallow copy of byte_counts — safe for iteration."""
        with self._lock:
            return dict(self._byte_counts)

    def get_remote_ips_snapshot(self, mac: str) -> FrozenSet[str]:
        with self._lock:
            return frozenset(self._remote_ips_by_mac.get(mac, set()))

    def ports_in_use(self, mac: str) -> List[Tuple[str, int]]:
        """Distinct (protocol, remote port) pairs this device has talked to."""
        with self._lock:
            conns = frozenset(self._connections_by_mac.get(mac, set()))
        pairs = {(proto, dport) for proto, _sport, _dst, dport in conns}
        return sorted(pairs, key=lambda x: x[1])

    def top_port_for_mac(self, mac: str) -> Optional[Tuple[str, int]]:
        """Return (proto, port) responsible for the most bytes in the current
        window for this device, or None if nothing has been recorded yet.
        """
        with self._lock:
            candidates = {k: v for k, v in self._port_byte_counts.items() if k[0] == mac}
        if not candidates:
            return None
        (_, proto, port), _ = max(candidates.items(), key=lambda kv: kv[1])
        return proto, port

    def dashboard_rows(self, known_devices: Dict[str, str], mac_to_ip: Optional[Dict[str, str]] = None) -> List[dict]:
        """Every currently-visible device, sorted by highest data use first.
        Takes a snapshot under the lock to avoid RuntimeError during iteration.
        """
        mac_to_ip = mac_to_ip or {}
        with self._lock:
            byte_snapshot = dict(self._byte_counts)

        all_macs = set(mac_to_ip) | set(byte_snapshot)
        rows = []
        for mac in all_macs:
            rows.append({
                "mac": mac,
                "ip": mac_to_ip.get(mac, "-"),
                "name": known_devices.get(mac, "UNKNOWN"),
                "bytes": byte_snapshot.get(mac, 0),
                "ports": self.ports_in_use(mac),
            })
        rows.sort(key=lambda r: -r["bytes"])
        return rows

    def get_window_start(self) -> float:
        with self._lock:
            return self._window_start


# ---------------------------------------------------------------------------
# Module-level singleton — import this from other modules
# ---------------------------------------------------------------------------
state: MonitorState = MonitorState()


# ---------------------------------------------------------------------------
# Sniffer thread entry point
# ---------------------------------------------------------------------------

def start_sniffing(iface: Optional[str] = None) -> None:
    """Blocking call — run this in a background daemon thread.

    Restarts the sniffer automatically on transient errors rather than
    crashing the whole monitor.
    """
    iface = iface or config.INTERFACE
    while True:
        try:
            _log.info("Starting packet sniffer on interface '%s'.", iface)
            sniff(iface=iface, prn=state.handle_packet, store=False)
        except Exception as exc:
            _log.error("Sniffer crashed (%s: %s) — restarting in 5 s.", type(exc).__name__, exc)
            time.sleep(5)
