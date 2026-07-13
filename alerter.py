import logging
import smtplib
from email.mime.text import MIMEText

import config

_log = logging.getLogger("network_monitor.alerter")

def build_alert_body(
    mac: str,
    ip: str,
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
        f"- MAC Address: {mac}",
        f"- Current IP: {ip}",
        f"- Entry Point (Interface/Subnet): {entry_point}",
        f"- Lifetime Connections: {connection_count}",
        f"- Data Used this Session: {data_usage_mb:.2f} MB",
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
        _log.warning("Email alerts are disabled (missing SMTP_USERNAME or SMTP_PASSWORD in .env). Alert not sent.")
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
        _log.info(f"Alert email successfully sent: {subject}")
        return True
    except smtplib.SMTPAuthenticationError:
        _log.error("SMTP Authentication failed! Check your App Password in the .env file.")
    except Exception as e:
        _log.error(f"Failed to send email: {e}")
    
    return False
