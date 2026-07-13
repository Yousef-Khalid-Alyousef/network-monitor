"""
Thread-safe, rate-limited email alerting.

Race-condition mitigations:
  - _alert_times is protected by _alert_lock so concurrent callers can't
    each independently decide "we're under the rate limit" and both send.
  - SMTP credentials are never written to logs or exception messages.

Rate limiting:
  - At most MAX_ALERTS_PER_HOUR alert emails are sent in any rolling
    60-minute window.  Suppressed alerts are logged to stderr instead.
"""

import collections
import datetime
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from typing import Deque

import config

_log = logging.getLogger("network_monitor.alerter")

# ---------------------------------------------------------------------------
# Rate-limiting state — all mutations must hold _alert_lock
# ---------------------------------------------------------------------------
_alert_lock: threading.Lock = threading.Lock()
_alert_times: Deque[datetime.datetime] = collections.deque()


def _prune_old_alerts(now: datetime.datetime) -> None:
    """Remove timestamps older than 1 hour from the deque.
    Caller must already hold _alert_lock.
    """
    cutoff = now - datetime.timedelta(hours=1)
    while _alert_times and _alert_times[0] < cutoff:
        _alert_times.popleft()


def _rate_limit_ok(now: datetime.datetime) -> bool:
    """Return True if we are allowed to send another alert right now.
    Caller must already hold _alert_lock.
    """
    _prune_old_alerts(now)
    return len(_alert_times) < config.MAX_ALERTS_PER_HOUR


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_alert_body(device_info: dict, reason: str, extra: str = "") -> str:
    """Build a plain-text alert body. No credentials or secrets appear here."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"Time: {timestamp}",
        f"Reason: {reason}",
        f"IP: {device_info.get('ip', 'unknown')}",
        f"MAC: {device_info.get('mac', 'unknown')}",
        f"Known as: {device_info.get('known_name', 'UNKNOWN')}",
    ]
    if extra:
        lines.append(extra)
    return "\n".join(lines)


def send_alert(subject: str, body: str) -> bool:
    """Send an alert email, honouring the per-hour rate limit.

    Returns True if the email was sent, False if suppressed or failed.
    Credentials are loaded directly from config and are never logged.
    """
    if not config.EMAIL_ALERTS_ENABLED:
        _log.info("Email alerts disabled (SMTP_USERNAME/SMTP_PASSWORD not configured).")
        return False

    now = datetime.datetime.now()

    # --- Rate-limit check (atomic: check + record under lock) ---
    with _alert_lock:
        if not _rate_limit_ok(now):
            _log.warning(
                "Alert suppressed (rate limit: %d/hr): %s",
                config.MAX_ALERTS_PER_HOUR,
                subject,
            )
            return False
        # Record intent to send before releasing lock so no concurrent call
        # sneaks through between the check and the actual SMTP call.
        _alert_times.append(now)

    # --- Send (outside the lock so SMTP latency doesn't block other threads) ---
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config.ALERT_EMAIL_FROM
    msg["To"] = config.ALERT_EMAIL_TO

    try:
        with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            server.send_message(msg)
        _log.info("Alert email sent: %s", subject)
        return True
    except smtplib.SMTPAuthenticationError:
        # Don't log credentials or the full exception repr which may contain them
        _log.error("SMTP authentication failed — check SMTP_USERNAME / SMTP_PASSWORD env vars.")
    except Exception as exc:
        _log.error("Failed to send alert email '%s': %s", subject, type(exc).__name__)
    return False
