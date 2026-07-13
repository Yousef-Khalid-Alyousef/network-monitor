import json
import logging
import os
import threading
import time
from typing import Dict, List

from scapy.all import ARP, Ether, srp

import config
import db
import geolocation
import blocker
import traffic_monitor
import alerter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
_log = logging.getLogger("network_monitor.main")

def load_known_devices() -> Dict[str, str]:
    if not os.path.exists(config.KNOWN_DEVICES_FILE):
        return {}
    try:
        with open(config.KNOWN_DEVICES_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def scan_network() -> Dict[str, str]:
    """Returns dict of MAC -> IP for currently active devices."""
    arp_request = ARP(pdst=config.NETWORK_SUBNET)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send packets and capture responses
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=config.INTERFACE)[0]

    devices = {}
    for element in answered_list:
        mac = element[1].hwsrc.lower()
        ip = element[1].psrc
        devices[mac] = ip
    return devices

def main():
    _log.info("Starting Network Monitor V4...")
    _log.info(f"Interface: {config.INTERFACE} | Subnet: {config.NETWORK_SUBNET}")
    _log.info(f"Limit 1 (Alert): {config.DATA_LIMIT_ALERT_BYTES / (1024**3):.2f} GB")
    _log.info(f"Limit 2 (Block): {config.DATA_LIMIT_BLOCK_BYTES / (1024**3):.2f} GB")
    _log.info(f"Email Alerts: {'ENABLED' if config.EMAIL_ALERTS_ENABLED else 'DISABLED (Check .env)'}")
    
    # Init subsystems
    db.init_db()
    geolocation.init_geolocation()
    blocker.clear_all_blocks()
    
    known_devices = load_known_devices()
    _alerted_unauthorized = set()
    
    # Start sniffer
    sniffer_thread = threading.Thread(target=traffic_monitor.start_sniffing, daemon=True)
    sniffer_thread.start()
    
    _log.info("Beginning ARP scan loop...")
    entry_point = f"{config.INTERFACE} / {config.NETWORK_SUBNET}"
    
    try:
        while True:
            current_devices = scan_network()
            
            # Synchronize active devices with the traffic monitor (starts/ends sessions)
            traffic_monitor.sync_active_devices(current_devices, entry_point)
            
            # Check for unauthorized devices
            for mac, ip in current_devices.items():
                if mac not in known_devices and mac not in _alerted_unauthorized:
                    _alerted_unauthorized.add(mac)
                    _log.warning(f"Unauthorized device detected: {mac} ({ip})")
                    
                    body = alerter.build_alert_body(
                        mac=mac, ip=ip,
                        reason="Unauthorized device joined the network.",
                        data_usage_mb=0, entry_point=entry_point,
                        connection_count=db.get_connection_count(mac),
                        recent_domains=[]
                    )
                    alerter.send_alert("⚠️ Unauthorized Device Detected", body)
            
            time.sleep(30) # Scan every 30 seconds
    except KeyboardInterrupt:
        _log.info("Shutting down...")
    finally:
        blocker.clear_all_blocks()
        _log.info("Shutdown complete.")

if __name__ == "__main__":
    main()
