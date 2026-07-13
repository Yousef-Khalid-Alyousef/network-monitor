import logging
import threading
import socket
from typing import Dict, Tuple, List

from scapy.all import sniff, IP, TCP, UDP, DNSQR
import config
import db
import alerter
import blocker
import geolocation

_log = logging.getLogger("network_monitor.traffic")

class DeviceState:
    def __init__(self, mac: str, ip: str, name: str):
        self.mac = mac
        self.ip = ip
        self.name = name
        self.bytes_used_run = 0
        self.alerted_stage1 = False
        self.alerted_stage2 = False
        self.current_session_id = None
        self.ports = {} # (proto, port) -> bytes

_sessions_lock = threading.Lock()
_devices: Dict[str, DeviceState] = {}
_ip_to_mac: Dict[str, str] = {}

def _resolve_hostname(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return "Unknown"

def sync_active_devices(current_devices: Dict[str, str], entry_point: str) -> None:
    """Main loop calls this periodically to start/stop sessions and sync IP mapping."""
    global _ip_to_mac
    with _sessions_lock:
        _ip_to_mac = {ip: mac for mac, ip in current_devices.items()}
        
        # Check for disconnected devices
        active_macs = set(current_devices.keys())
        for mac, state in _devices.items():
            if mac not in active_macs and state.current_session_id is not None:
                db.end_session(state.current_session_id, state.bytes_used_run) # Approx, but good enough for history
                state.current_session_id = None
                
        # Check for new connections
        for mac, ip in current_devices.items():
            if mac not in _devices:
                # First time seeing this device this run
                name = db.get_device_name(mac)
                if name == "Unknown":
                    name = _resolve_hostname(ip)
                    if name != "Unknown":
                        db.save_device_name(mac, name)
                _devices[mac] = DeviceState(mac, ip, name)
                
            state = _devices[mac]
            state.ip = ip # Update IP if it changed
            if state.current_session_id is None:
                # Started a new session
                sess_id = db.start_session(mac, entry_point)
                state.current_session_id = sess_id

def get_dashboard_data() -> List[dict]:
    with _sessions_lock:
        rows = []
        for mac, state in _devices.items():
            if state.current_session_id is not None: # Currently active
                top_port = None
                if state.ports:
                    top_port = max(state.ports.items(), key=lambda kv: kv[1])[0]
                rows.append({
                    "mac": mac,
                    "ip": state.ip,
                    "name": state.name,
                    "bytes": state.bytes_used_run,
                    "top_port": top_port,
                    "connections_24h": db.get_connections_last_24h(mac),
                    "location": geolocation.get_location(state.ip)
                })
        return rows

def _handle_packet(pkt):
    if IP not in pkt:
        return
        
    src_ip = pkt[IP].src
    pkt_len = len(pkt)
    
    mac = _ip_to_mac.get(src_ip)
    if not mac:
        return
        
    with _sessions_lock:
        state = _devices.get(mac)
        if not state or state.current_session_id is None:
            return
            
        state.bytes_used_run += pkt_len
        
        # Track DNS queries for history
        if pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                db.log_domain(state.current_session_id, domain)
            except Exception:
                pass
                
        # Track ports
        proto = sport = dport = None
        if TCP in pkt:
            proto, dport = "tcp", pkt[TCP].dport
        elif UDP in pkt:
            proto, dport = "udp", pkt[UDP].dport
            
        if proto:
            port_key = (proto, dport)
            state.ports[port_key] = state.ports.get(port_key, 0) + pkt_len

        _check_limits(state)

def _check_limits(state: DeviceState):
    # Stage 1: Alert
    if state.bytes_used_run > config.DATA_LIMIT_ALERT_BYTES and not state.alerted_stage1:
        state.alerted_stage1 = True
        threading.Thread(target=_fire_stage1_alert, args=(state,), daemon=True).start()
        
    # Stage 2: Block
    if state.bytes_used_run > config.DATA_LIMIT_BLOCK_BYTES and not state.alerted_stage2:
        state.alerted_stage2 = True
        top_port = None
        if state.ports:
            top_port = max(state.ports.items(), key=lambda kv: kv[1])[0]
        threading.Thread(target=_fire_stage2_block, args=(state, top_port), daemon=True).start()

def _fire_stage1_alert(state: DeviceState):
    mb = state.bytes_used_run / (1024 * 1024)
    conn_count = db.get_connections_last_24h(state.mac)
    domains = db.get_session_domains(state.current_session_id)
    entry = f"{config.INTERFACE} / {config.NETWORK_SUBNET}"
    
    body = alerter.build_alert_body(
        mac=state.mac, ip=state.ip, name=state.name,
        reason="Data usage exceeded Limit 1 (Alert).",
        data_usage_mb=mb, entry_point=entry, 
        connection_count=conn_count, recent_domains=domains
    )
    alerter.send_alert("⚠️ Network Alert: High Data Usage", body)

def _fire_stage2_block(state: DeviceState, top_port):
    mb = state.bytes_used_run / (1024 * 1024)
    conn_count = db.get_connections_last_24h(state.mac)
    domains = db.get_session_domains(state.current_session_id)
    entry = f"{config.INTERFACE} / {config.NETWORK_SUBNET}"
    
    if top_port:
        proto, port = top_port
        blocker.block_port(state.ip, port, proto)
        action_msg = f"Blocked {proto.upper()} Port {port} for exceeding Limit 2 (Block)."
    else:
        blocker.block_device(state.ip)
        action_msg = "Blocked entire device for exceeding Limit 2 (Block)."
        
    body = alerter.build_alert_body(
        mac=state.mac, ip=state.ip, name=state.name,
        reason=action_msg,
        data_usage_mb=mb, entry_point=entry, 
        connection_count=conn_count, recent_domains=domains
    )
    alerter.send_alert("🚫 Network Block: Device Exceeded Limit", body)

def start_sniffing():
    _log.info(f"Starting packet sniffer on {config.INTERFACE}...")
    while True:
        try:
            sniff(iface=config.INTERFACE, prn=_handle_packet, store=False)
        except Exception as e:
            _log.error(f"Sniffer crashed: {e}. Restarting in 3 seconds...")
            import time
            time.sleep(3)
