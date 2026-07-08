"""
Firewall blocking via iptables.

Security improvements over the original:
  - Before inserting a rule, we test with `iptables -C` to ensure we never
    add duplicates (which could cause denial-of-service on the rule table and
    make removal unreliable).
  - All subprocess calls use list arguments (no shell=True) — immune to
    shell injection regardless of what appears in `ip` or `port`.
  - IP and port values are validated before being passed to iptables.
  - `clear_rules()` collects the specific rules we inserted so they can be
    atomically removed on clean shutdown.
  - LOG-ONLY mode is the safe default (AUTO_BLOCK_ENABLED = False).
"""

import ipaddress
import logging
import subprocess
import threading
from typing import Tuple

import config

_log = logging.getLogger("network_monitor.blocker")

# ---------------------------------------------------------------------------
# Track inserted rules for clean removal on shutdown
# ---------------------------------------------------------------------------
_rules_lock: threading.Lock = threading.Lock()
_inserted_rules: list[Tuple[str, ...]] = []  # each entry is the iptables args list


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> str:
    """Return the IP if valid, raise ValueError otherwise."""
    return str(ipaddress.ip_address(ip))  # raises ValueError on bad input


def _validate_port(port: int) -> int:
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} out of valid range 1–65535")
    return port


def _validate_proto(proto: str) -> str:
    allowed = {"tcp", "udp"}
    proto = proto.lower()
    if proto not in allowed:
        raise ValueError(f"Protocol '{proto}' not in {allowed}")
    return proto


def _run_iptables(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run an iptables command, logging the call for auditability."""
    _log.debug("iptables %s", " ".join(args))
    return subprocess.run(
        ["iptables"] + args,
        capture_output=True,
        text=True,
        check=check,
    )


def _rule_exists(chain: str, extra_args: list[str]) -> bool:
    """Return True if an equivalent iptables rule already exists (uses -C)."""
    result = _run_iptables(["-C", chain] + extra_args, check=False)
    return result.returncode == 0


def _insert_rule(chain: str, extra_args: list[str]) -> bool:
    """Insert a rule if it does not already exist. Returns True if inserted."""
    if _rule_exists(chain, extra_args):
        _log.info("Rule already exists, skipping: iptables -A %s %s", chain, " ".join(extra_args))
        return False
    _run_iptables(["-A", chain] + extra_args)
    with _rules_lock:
        _inserted_rules.append(tuple([chain] + extra_args))
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def block_ip(ip: str) -> None:
    """Block all forwarded and inbound traffic from an IP address."""
    if not config.AUTO_BLOCK_ENABLED:
        _log.info("[LOG-ONLY] Would block %s — set AUTO_BLOCK_ENABLED=true to activate.", ip)
        return
    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        _log.error("block_ip: invalid IP '%s': %s", ip, exc)
        return

    rule_args = ["-s", ip, "-j", "DROP"]
    inserted_forward = _insert_rule("FORWARD", rule_args)
    inserted_input = _insert_rule("INPUT", rule_args)
    if inserted_forward or inserted_input:
        _log.info("Blocked all traffic from %s.", ip)


def block_ip_port(ip: str, port: int, proto: str = "tcp") -> None:
    """Block a specific port/protocol for a device instead of cutting it off entirely."""
    if not config.AUTO_BLOCK_ENABLED:
        _log.info("[LOG-ONLY] Would block %s:%s/%s — set AUTO_BLOCK_ENABLED=true to activate.", ip, port, proto)
        return
    try:
        ip = _validate_ip(ip)
        port = _validate_port(port)
        proto = _validate_proto(proto)
    except ValueError as exc:
        _log.error("block_ip_port: invalid argument — %s", exc)
        return

    rule_args = ["-s", ip, "-p", proto, "--dport", str(port), "-j", "DROP"]
    if _insert_rule("FORWARD", rule_args):
        _log.info("Blocked %s:%s/%s.", ip, port, proto)


def unblock_ip(ip: str) -> None:
    """Remove FORWARD and INPUT DROP rules for an IP (if they exist)."""
    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        _log.error("unblock_ip: invalid IP '%s': %s", ip, exc)
        return

    rule_args = ["-s", ip, "-j", "DROP"]
    for chain in ("FORWARD", "INPUT"):
        if _rule_exists(chain, rule_args):
            _run_iptables(["-D", chain] + rule_args, check=False)
            _log.info("Removed DROP rule for %s from %s.", ip, chain)


def clear_rules() -> None:
    """Remove every rule that was inserted during this session.

    Call this on shutdown to leave the firewall clean.
    """
    with _rules_lock:
        rules = list(_inserted_rules)

    for rule_tuple in rules:
        chain, *args = rule_tuple
        if _rule_exists(chain, args):
            _run_iptables(["-D", chain] + args, check=False)
            _log.info("Removed session rule from %s: %s", chain, " ".join(args))

    with _rules_lock:
        _inserted_rules.clear()
