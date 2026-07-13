import logging
import subprocess
import threading
from typing import Set

_log = logging.getLogger("network_monitor.blocker")

_block_lock = threading.Lock()
_blocked_ips: Set[str] = set()
_blocked_ports: Set[tuple[str, int, str]] = set() # ip, port, proto

def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        _log.warning("iptables not found. Are you running on Linux/Raspberry Pi as root?")
        return False

def block_device(ip: str) -> None:
    with _block_lock:
        if ip in _blocked_ips:
            return
        _log.warning(f"Blocking ALL traffic for IP {ip}")
        # Block incoming and outgoing
        _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        _run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        _blocked_ips.add(ip)

def block_port(ip: str, port: int, proto: str) -> None:
    proto = proto.lower()
    with _block_lock:
        if (ip, port, proto) in _blocked_ports:
            return
        _log.warning(f"Blocking {proto.upper()} Port {port} for IP {ip}")
        # Block outgoing traffic to that port for the IP
        _run(["iptables", "-A", "FORWARD", "-s", ip, "-p", proto, "--dport", str(port), "-j", "DROP"])
        # Also block incoming if it's local
        _run(["iptables", "-A", "INPUT", "-s", ip, "-p", proto, "--dport", str(port), "-j", "DROP"])
        _blocked_ports.add((ip, port, proto))

def clear_all_blocks() -> None:
    with _block_lock:
        for ip in _blocked_ips:
            _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            _run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        for ip, port, proto in _blocked_ports:
            _run(["iptables", "-D", "FORWARD", "-s", ip, "-p", proto, "--dport", str(port), "-j", "DROP"])
            _run(["iptables", "-D", "INPUT", "-s", ip, "-p", proto, "--dport", str(port), "-j", "DROP"])
        _blocked_ips.clear()
        _blocked_ports.clear()
