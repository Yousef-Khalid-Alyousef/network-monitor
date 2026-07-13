import logging
import smtplib
from email.mime.text import MIMEText

import config

_log = logging.getLogger("network_monitor.alerter")

def build_alert_body(
    mac: str,
    ip: str,
    name: str,
    reason: str,
    data_usage_mb: float,
    entry_point: str,
    connection_count: int,
    recent_domains: list[str]
) -> str:
    
    lines = [
        "Network Monitor Alert",
        "=====================",
        f"Reason: {reason}",
        "",
        "Device Details:",
        f"- Device Name: {name}",
        f"- MAC Address: {mac}",
        f"- Current IP: {ip}",
        f"- Entry Point (Interface/Subnet): {entry_point}",
        f"- Connections (Last 24h): {connection_count}",
        f"- Data Used (This Session): {data_usage_mb:.2f} MB",
        "",
        "Recent Browsing History (DNS Domains):"
    ]
    
    if not recent_domains:
        lines.append("- (No domains captured yet)")
    else:
        for domain in recent_domains:
            lines.append(f"- {domain}")
            
    lines.append("")
    lines.append("Note: HTTPS encrypts exact URLs. Only domain names are visible.")
    
    return "\n".join(lines)

def send_alert(subject: str, body: str) -> bool:
    if not config.EMAIL_ALERTS_ENABLED:
        _log.error("Email alerts are disabled (missing SMTP_USERNAME or SMTP_PASSWORD in .env).")
        return False
        
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
        return True
    except Exception as e:
        _log.error(f"Failed to send email: {e}")
    
    return False
