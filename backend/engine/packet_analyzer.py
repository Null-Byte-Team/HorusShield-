"""HorusShield Packet Analyzer — Fixed"""
import time, threading, math
from collections import defaultdict, deque
from datetime import datetime
from utils.logger import get_logger
from utils.helpers import get_local_ipv4_addresses

logger = get_logger("packet_analyzer","engine")

SCAPY_AVAILABLE = None
IP = None
TCP = None
UDP = None
ICMP = None
DNS = None
ARP = None

def _ensure_scapy():
    global SCAPY_AVAILABLE, IP, TCP, UDP, ICMP, DNS, ARP
    if SCAPY_AVAILABLE is not None:
        return SCAPY_AVAILABLE
    try:
        from scapy.layers.inet import IP as _IP, TCP as _TCP, UDP as _UDP, ICMP as _ICMP
        from scapy.layers.dns import DNS as _DNS
        from scapy.layers.l2 import ARP as _ARP
        IP, TCP, UDP, ICMP, DNS, ARP = _IP, _TCP, _UDP, _ICMP, _DNS, _ARP
        SCAPY_AVAILABLE = True
        logger.info("Scapy loaded successfully")
    except Exception as e:
        SCAPY_AVAILABLE = False
        logger.warning(f"Scapy unavailable for packet analysis — falling back to system metrics ({e})")
    return SCAPY_AVAILABLE

class PacketAnalyzer:
    def __init__(self, buffer_size=1000):
        self.buffer_size = buffer_size
        self.packet_buffer = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self.counters = self._new_counters()
        self._last_snapshot = time.time()
        self.local_ips = get_local_ipv4_addresses()
        self.ip_packet_counts = defaultdict(int)
        self.ip_syn_counts    = defaultdict(int)
        self.ip_port_access   = defaultdict(set)
        self.ip_failed_auths  = defaultdict(int)
        self.ip_timestamps    = defaultdict(lambda: deque(maxlen=2000))

    def _new_counters(self):
        return {"packets_in":0,"packets_out":0,"bytes_in":0,"bytes_out":0,
                "tcp_count":0,"udp_count":0,"icmp_count":0,"other_count":0,
                "syn_count":0,"dns_count":0,"http_count":0,
                "unique_src_ips":set(),"unique_dst_ips":set(),"unique_ports":set(),
                "packet_sizes":[],"active_connections":0,"connection_keys":set()}

    def analyze_packet(self, packet):
        if not _ensure_scapy(): return
        try:
            info = self._extract_packet_info(packet)
            if info:
                with self._lock:
                    self.packet_buffer.append(info)
                    self._update_counters(info)
                    self._update_ip_tracking(info)
        except Exception as e:
            logger.debug(f"Packet error: {e}")

    def analyze_packet_batch(self, packets):
        """High-throughput batch analysis with single lock acquisition."""
        if not _ensure_scapy() or not packets:
            return
        parsed_infos = []
        for pkt in packets:
            try:
                info = self._extract_packet_info(pkt)
                if info:
                    parsed_infos.append(info)
            except Exception:
                pass
        if not parsed_infos:
            return
        with self._lock:
            for info in parsed_infos:
                self.packet_buffer.append(info)
                self._update_counters(info)
                self._update_ip_tracking(info)

    def _extract_packet_info(self, packet):
        if not _ensure_scapy(): return None
        try:
            info = {"timestamp":time.time(),"size":len(packet),"protocol":"other",
                    "src_ip":None,"dst_ip":None,"src_port":None,"dst_port":None,
                    "flags":"","is_syn":False,"is_dns":False,"is_http":False}
            if packet.haslayer(IP):
                info["src_ip"] = packet[IP].src
                info["dst_ip"] = packet[IP].dst
                if packet.haslayer(TCP):
                    info["protocol"]  = "tcp"
                    info["src_port"]  = packet[TCP].sport
                    info["dst_port"]  = packet[TCP].dport
                    info["flags"]     = str(packet[TCP].flags)
                    if packet[TCP].flags & 0x02 and not (packet[TCP].flags & 0x10):
                        info["is_syn"] = True
                    if packet[TCP].dport in (80,443,8080,8443): info["is_http"]=True
                elif packet.haslayer(UDP):
                    info["protocol"] = "udp"
                    info["src_port"] = packet[UDP].sport
                    info["dst_port"] = packet[UDP].dport
                    if packet.haslayer(DNS) or packet[UDP].dport==53: info["is_dns"]=True
                elif packet.haslayer(ICMP): info["protocol"]="icmp"
            elif packet.haslayer(ARP):
                info["protocol"]="arp"
                info["src_ip"]=packet[ARP].psrc
                info["dst_ip"]=packet[ARP].pdst
            info["direction"] = self._classify_direction(info)
            return info
        except Exception as e:
            logger.debug(f"Packet parse failed: {e}")
            return None

    def _classify_direction(self, packet_info):
        src = packet_info.get("src_ip")
        dst = packet_info.get("dst_ip")
        src_local = src in self.local_ips if src else False
        dst_local = dst in self.local_ips if dst else False

        if src_local and not dst_local:
            return "outbound"
        if dst_local and not src_local:
            return "inbound"
        if src_local and dst_local:
            return "local"
        return "inbound"

    def _update_counters(self, p):
        c = self.counters
        direction = p.get("direction")
        if direction == "outbound":
            c["packets_out"] += 1
            c["bytes_out"] += p["size"]
        elif direction == "local":
            c["packets_in"] += 1
            c["packets_out"] += 1
            c["bytes_in"] += p["size"]
            c["bytes_out"] += p["size"]
        else:
            c["packets_in"] += 1
            c["bytes_in"] += p["size"]

        c["packet_sizes"].append(p["size"])
        proto=p["protocol"]
        if proto=="tcp": c["tcp_count"]+=1
        elif proto=="udp": c["udp_count"]+=1
        elif proto=="icmp": c["icmp_count"]+=1
        else: c["other_count"]+=1
        if p["is_syn"]: c["syn_count"]+=1
        if p["is_dns"]: c["dns_count"]+=1
        if p["is_http"]: c["http_count"]+=1
        if p["src_ip"]: c["unique_src_ips"].add(p["src_ip"])
        if p["dst_ip"]: c["unique_dst_ips"].add(p["dst_ip"])
        if p["dst_port"]: c["unique_ports"].add(p["dst_port"])
        if p.get("src_ip") and p.get("dst_ip"):
            if p.get("src_port") is not None or p.get("dst_port") is not None:
                flow = tuple(sorted([
                    (p["src_ip"], p.get("src_port") or 0),
                    (p["dst_ip"], p.get("dst_port") or 0),
                ])) + (proto,)
            else:
                flow = (p["src_ip"], p["dst_ip"], proto)
            c["connection_keys"].add(flow)
            c["active_connections"] = len(c["connection_keys"])

    def _update_ip_tracking(self, p):
        src = p.get("src_ip")
        if not src: return
        now = time.time()
        self.ip_packet_counts[src]+=1
        self.ip_timestamps[src].append(now)
        if p["is_syn"]: self.ip_syn_counts[src]+=1
        if p.get("dst_port"): self.ip_port_access[src].add(p["dst_port"])
        ts = self.ip_timestamps[src]
        while ts and ts[0] < now-60: ts.popleft()

    def get_snapshot(self):
        with self._lock:
            now = time.time()
            elapsed = max(now-self._last_snapshot, 0.1)
            c = self.counters
            sizes = c["packet_sizes"]
            total_in = c["bytes_in"]
            total_out = c["bytes_out"]
            total_p = c["packets_in"] + c["packets_out"]
            total_b = total_in + total_out
            snap = {
                "packets_in":c["packets_in"],"packets_out":c["packets_out"],
                "bytes_in":c["bytes_in"],"bytes_out":c["bytes_out"],
                "tcp_count":c["tcp_count"],"udp_count":c["udp_count"],
                "icmp_count":c["icmp_count"],"other_count":c["other_count"],
                "syn_count":c["syn_count"],"dns_count":c["dns_count"],
                "http_count":c["http_count"],
                "unique_src_ips":len(c["unique_src_ips"]),"unique_dst_ips":len(c["unique_dst_ips"]),
                "unique_ports":len(c["unique_ports"]),
                "avg_packet_size":sum(sizes)/len(sizes) if sizes else 0,
                "bandwidth_mbps":(total_b*8)/(elapsed*1_000_000),
                "download_mbps":(total_in*8)/(elapsed*1_000_000),
                "upload_mbps":(total_out*8)/(elapsed*1_000_000),
                "active_connections":len(c["connection_keys"]),
                "packets_per_sec":total_p/elapsed,"bytes_per_sec":total_b/elapsed,
                "timestamp":datetime.utcnow().isoformat(),
            }
            self.counters = self._new_counters()
            self._last_snapshot = now
            return snap

    def get_ai_features(self):
        snap = self.get_snapshot()
        total = snap["tcp_count"]+snap["udp_count"]+snap["icmp_count"]+snap["other_count"] or 1
        return {
            "packets_per_sec":snap["packets_per_sec"],"bytes_per_sec":snap["bytes_per_sec"],
            "unique_src_ips":snap["unique_src_ips"],"unique_dst_ports":snap["unique_ports"],
            "syn_ratio":snap["syn_count"]/total,"udp_ratio":snap["udp_count"]/total,
            "icmp_ratio":snap["icmp_count"]/total,"avg_packet_size":snap["avg_packet_size"],
            "connection_count":snap["active_connections"],"entropy":self._entropy(),
        }

    def _entropy(self):
        total = sum(self.ip_packet_counts.values())
        if not total: return 0.0
        return -sum((c/total)*math.log2(c/total) for c in self.ip_packet_counts.values() if c>0)

    def record_failed_auth(self, ip):
        with self._lock: self.ip_failed_auths[ip]+=1

    def reset_ip_tracking(self):
        with self._lock:
            self.ip_packet_counts.clear(); self.ip_syn_counts.clear()
            self.ip_port_access.clear(); self.ip_failed_auths.clear()
            self.ip_timestamps.clear()

    def get_ip_stats(self, ip, window=60):
        now=time.time(); cutoff=now-window
        recent=[t for t in self.ip_timestamps.get(ip,[]) if t>cutoff]
        return {"ip":ip,"total_packets":self.ip_packet_counts.get(ip,0),
                "recent_packets":len(recent),"packets_per_sec":len(recent)/window if recent else 0,
                "syn_count":self.ip_syn_counts.get(ip,0),
                "unique_ports_accessed":len(self.ip_port_access.get(ip,set())),
                "failed_auths":self.ip_failed_auths.get(ip,0)}

    def record_flow(self, flow_info):
        """Record a socket/network flow event into the packet buffer."""
        if not flow_info or not isinstance(flow_info, dict):
            return
        entry = {
            "timestamp": flow_info.get("timestamp") or time.time(),
            "time_str": flow_info.get("time_str") or datetime.now().strftime("%H:%M:%S"),
            "size": flow_info.get("size", 64),
            "protocol": (flow_info.get("protocol") or "tcp").upper(),
            "src_ip": flow_info.get("src_ip", "127.0.0.1"),
            "dst_ip": flow_info.get("dst_ip", "127.0.0.1"),
            "src_port": flow_info.get("src_port"),
            "dst_port": flow_info.get("dst_port"),
            "src": flow_info.get("src") or (f"{flow_info.get('src_ip')}:{flow_info.get('src_port')}" if flow_info.get('src_port') else str(flow_info.get('src_ip', ''))),
            "dst": flow_info.get("dst") or (f"{flow_info.get('dst_ip')}:{flow_info.get('dst_port')}" if flow_info.get('dst_port') else str(flow_info.get('dst_ip', ''))),
            "direction": flow_info.get("direction", "inbound"),
            "status": flow_info.get("status", "ESTABLISHED"),
            "flags": flow_info.get("flags", ""),
        }
        with self._lock:
            self.packet_buffer.append(entry)

    def get_recent_packets(self, limit=50):
        """Get recent packets/flows formatted for live display."""
        with self._lock:
            items = list(self.packet_buffer)

        result = []
        for p in reversed(items[-limit:]):
            ts = p.get("timestamp")
            if isinstance(ts, (int, float)):
                t_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            elif isinstance(ts, str) and "T" in ts:
                t_str = ts.split("T")[1][:8]
            else:
                t_str = p.get("time_str") or datetime.now().strftime("%H:%M:%S")

            src_ip = p.get("src_ip") or "127.0.0.1"
            dst_ip = p.get("dst_ip") or "127.0.0.1"
            src_p = p.get("src_port")
            dst_p = p.get("dst_port")
            src_str = p.get("src") or (f"{src_ip}:{src_p}" if src_p else src_ip)
            dst_str = p.get("dst") or (f"{dst_ip}:{dst_p}" if dst_p else dst_ip)

            result.append({
                "timestamp": t_str,
                "protocol": (p.get("protocol") or "TCP").upper(),
                "src": src_str,
                "dst": dst_str,
                "size": p.get("size", 64),
                "direction": p.get("direction", "inbound"),
                "status": p.get("status", "OK"),
                "flags": p.get("flags", ""),
            })
        return result

