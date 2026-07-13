import logging
import threading
import time
from scapy.all import ARP, Ether, srp

import config
import traffic_monitor

_log = logging.getLogger("network_monitor.engine")
_stop_event = threading.Event()

def scan_network() -> dict[str, str]:
    """Returns dict of MAC -> IP for currently active devices."""
    arp_request = ARP(pdst=config.NETWORK_SUBNET)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    try:
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False, iface=config.INTERFACE)[0]
    except Exception:
        return {}

    devices = {}
    for element in answered_list:
        mac = element[1].hwsrc.lower()
        ip = element[1].psrc
        devices[mac] = ip
    return devices

def _arp_loop():
    entry_point = f"{config.INTERFACE} / {config.NETWORK_SUBNET}"
    while not _stop_event.is_set():
        current_devices = scan_network()
        traffic_monitor.sync_active_devices(current_devices, entry_point)
        _stop_event.wait(30)

def start_background_tasks():
    _stop_event.clear()
    
    # Start sniffer
    t1 = threading.Thread(target=traffic_monitor.start_sniffing, daemon=True)
    t1.start()
    
    # Start ARP scanner
    t2 = threading.Thread(target=_arp_loop, daemon=True)
    t2.start()

def stop_background_tasks():
    _stop_event.set()
