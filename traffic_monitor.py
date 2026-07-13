import logging
import threading
from typing import Dict, Optional, Tuple

from scapy.all import sniff, IP, TCP, UDP, DNSQR
import config
import db
import alerter
import blocker
import geolocation

_log = logging.getLogger("network_monitor.traffic")

class Session:
    def __init__(self, mac: str, ip: str, session_id: int):
        self.mac = mac
        self.ip = ip
        self.session_id = session_id
        self.bytes_used = 0
        self.alerted_stage1 = False
        self.alerted_stage2 = False
        self.ports = {} # (proto, port) -> bytes

_sessions_lock = threading.Lock()
_active_sessions: Dict[str, Session] = {}
_ip_to_mac: Dict[str, str] = {}

def sync_active_devices(current_devices: Dict[str, str], entry_point: str) -> None:
    """Called periodically by main loop to update IP->MAC mapping and start/stop sessions."""
    global _ip_to_mac
    with _sessions_lock:
        _ip_to_mac = {ip: mac for mac, ip in current_devices.items()}
        
        # Check for disconnected devices
        disconnected = set(_active_sessions.keys()) - set(current_devices.keys())
        for mac in disconnected:
            sess = _active_sessions.pop(mac)
            db.end_session(sess.session_id, sess.bytes_used)
            _log.info(f"Device {mac} disconnected. Session {sess.session_id} ended with {sess.bytes_used} bytes.")
            
        # Check for newly connected devices
        for mac, ip in current_devices.items():
            if mac not in _active_sessions:
                db.record_connection(mac)
                sess_id = db.start_session(mac, entry_point)
                _active_sessions[mac] = Session(mac, ip, sess_id)
                _log.info(f"Device {mac} ({ip}) joined. Started session {sess_id}.")

def _handle_packet(pkt):
    if IP not in pkt:
        return
        
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    pkt_len = len(pkt)
    
    mac = _ip_to_mac.get(src_ip)
    if not mac:
        return
        
    with _sessions_lock:
        sess = _active_sessions.get(mac)
        if not sess:
            return
            
        sess.bytes_used += pkt_len
        
        # Track DNS queries for history
        if pkt.haslayer(DNSQR):
            try:
                domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                db.log_domain(sess.session_id, domain)
            except Exception:
                pass
                
        # Track ports
        proto = sport = dport = None
        if TCP in pkt:
            proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
            
        if proto:
            port_key = (proto, dport)
            sess.ports[port_key] = sess.ports.get(port_key, 0) + pkt_len

        # Check Limits!
        _check_limits(sess)

def _check_limits(sess: Session):
    # This is called inside the _sessions_lock, so it must be fast.
    # To avoid blocking the sniffer on SMTP (email), we should launch alerts in a thread.
    
    # Stage 1: Alert
    if sess.bytes_used > config.DATA_LIMIT_ALERT_BYTES and not sess.alerted_stage1:
        sess.alerted_stage1 = True
        threading.Thread(target=_fire_stage1_alert, args=(sess.mac, sess.ip, sess.session_id, sess.bytes_used), daemon=True).start()
        
    # Stage 2: Block
    if sess.bytes_used > config.DATA_LIMIT_BLOCK_BYTES and not sess.alerted_stage2:
        sess.alerted_stage2 = True
        # Find the most active port
        top_port = None
        if sess.ports:
            top_port = max(sess.ports.items(), key=lambda kv: kv[1])[0]
            
        threading.Thread(target=_fire_stage2_block, args=(sess.mac, sess.ip, sess.session_id, sess.bytes_used, top_port), daemon=True).start()

def _fire_stage1_alert(mac, ip, session_id, bytes_used):
    mb = bytes_used / (1024 * 1024)
    conn_count = db.get_connection_count(mac)
    domains = db.get_session_domains(session_id)
    
    geo = geolocation.get_location(ip) # if they were external, though usually this is local.
    entry = f"{config.INTERFACE} / {config.NETWORK_SUBNET}"
    
    body = alerter.build_alert_body(
        mac=mac, ip=ip, 
        reason="Data usage exceeded Stage 1 (Alert) limit.",
        data_usage_mb=mb, entry_point=entry, 
        connection_count=conn_count, recent_domains=domains
    )
    alerter.send_alert("⚠️ Network Alert: High Data Usage", body)

def _fire_stage2_block(mac, ip, session_id, bytes_used, top_port):
    mb = bytes_used / (1024 * 1024)
    conn_count = db.get_connection_count(mac)
    domains = db.get_session_domains(session_id)
    
    if top_port:
        proto, port = top_port
        blocker.block_port(ip, port, proto)
        action_msg = f"Blocked {proto.upper()} Port {port} for exceeding Stage 2."
    else:
        blocker.block_device(ip)
        action_msg = "Blocked entire device for exceeding Stage 2 (no specific port found)."
        
    entry = f"{config.INTERFACE} / {config.NETWORK_SUBNET}"
    body = alerter.build_alert_body(
        mac=mac, ip=ip, 
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
