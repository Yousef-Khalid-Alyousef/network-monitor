"""
Central configuration for the network monitor.

SECURITY: Credentials are loaded from environment variables, never hard-coded.
Set the following env vars before running:
    export SMTP_USERNAME="youraddress@gmail.com"
    export SMTP_PASSWORD="your-app-password"

Optionally also set:
    export ALERT_EMAIL_TO="recipient@example.com"

All other values below can be edited directly.
"""

import ipaddress
import os
import sys


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_env(name: str) -> str:
    """Return the value of an environment variable or abort with a clear message."""
    value = os.environ.get(name, "").strip()
    if not value:
        print(
            f"[CONFIG ERROR] Required environment variable '{name}' is not set.\n"
            f"  Set it before running:  export {name}='<value>'",
            file=sys.stderr,
        )
        sys.exit(1)
    return value


def _validate_cidr(subnet: str) -> str:
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        print(f"[CONFIG ERROR] NETWORK_SUBNET '{subnet}' is not a valid CIDR: {exc}", file=sys.stderr)
        sys.exit(1)
    return subnet


def _validate_block_mode(mode: str) -> str:
    allowed = {"port", "device"}
    if mode not in allowed:
        print(
            f"[CONFIG ERROR] BLOCK_MODE must be one of {allowed}, got '{mode}'",
            file=sys.stderr,
        )
        sys.exit(1)
    return mode


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
NETWORK_SUBNET: str = _validate_cidr(
    os.environ.get("NETWORK_SUBNET", "192.168.1.0/24")
)
INTERFACE: str = os.environ.get("INTERFACE", "eth0")
SCAN_INTERVAL_SECONDS: int = int(os.environ.get("SCAN_INTERVAL_SECONDS", "30"))

# ---------------------------------------------------------------------------
# Data-usage trigger
# 1 GB in 10 minutes is a safe starting point — adjust after observing normal use.
# ---------------------------------------------------------------------------
DATA_TRIGGER_BYTES: int = int(
    os.environ.get("DATA_TRIGGER_BYTES", str(1 * 1024 * 1024 * 1024))
)
TRIGGER_WINDOW_SECONDS: int = int(os.environ.get("TRIGGER_WINDOW_SECONDS", "600"))

# Rolling connection-count window (e.g. "how many times joined in the last 24h")
CONNECTION_COUNT_WINDOW_HOURS: int = int(
    os.environ.get("CONNECTION_COUNT_WINDOW_HOURS", "24")
)

# ---------------------------------------------------------------------------
# Email alerts — credentials MUST come from environment variables
# ---------------------------------------------------------------------------
SMTP_SERVER: str = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))

# These two are required — the program will refuse to start without them.
SMTP_USERNAME: str = _require_env("SMTP_USERNAME")
SMTP_PASSWORD: str = _require_env("SMTP_PASSWORD")

ALERT_EMAIL_FROM: str = os.environ.get("ALERT_EMAIL_FROM", SMTP_USERNAME)
ALERT_EMAIL_TO: str = os.environ.get("ALERT_EMAIL_TO", SMTP_USERNAME)

# Maximum number of alert emails per hour across all alert types.
# Set high (50) so alerts fire freely during an incident; only suppress
# if something is clearly misbehaving and sending spam.
MAX_ALERTS_PER_HOUR: int = int(os.environ.get("MAX_ALERTS_PER_HOUR", "50"))

# ---------------------------------------------------------------------------
# Response actions
# ---------------------------------------------------------------------------
AUTO_BLOCK_ENABLED: bool = os.environ.get("AUTO_BLOCK_ENABLED", "false").lower() == "true"
BLOCK_MODE: str = _validate_block_mode(
    os.environ.get("BLOCK_MODE", "port")
)

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
KNOWN_DEVICES_FILE: str = os.environ.get("KNOWN_DEVICES_FILE", "known_devices.json")
LOG_DIR: str = os.environ.get("LOG_DIR", "device_logs")

# ---------------------------------------------------------------------------
# Geolocation (free tier — ~45 requests / min)
# ---------------------------------------------------------------------------
GEOLOCATION_API: str = "http://ip-api.com/json/{ip}"
GEOLOCATION_TIMEOUT_SECONDS: int = 3
