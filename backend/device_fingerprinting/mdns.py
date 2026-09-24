"""
HorusShield 2.0 — mDNS / Bonjour Service Discovery Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Zero-dependency UDP 5353 multicast mDNS probe & passive cache.
Discovers local service advertisements (_ipp._tcp, _airplay._tcp, _smb._tcp, etc.)
to corroborate device type classification.
"""

import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Set

from utils.logger import get_logger

logger = get_logger("fingerprint_mdns", "device")

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

# Standard discovery services to query
TARGET_SERVICES = [
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_smb._tcp.local",
    "_workstation._tcp.local",
    "_ssh._tcp.local",
    "_http._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
]


class MDNSDiscoverer:
    """Non-blocking mDNS query generator and service cache."""

    _instance: Optional["MDNSDiscoverer"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "MDNSDiscoverer":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    # IP -> Set of service names
                    cls._instance._services_by_ip: Dict[str, Set[str]] = {}
                    # IP -> Observed device name / host
                    cls._instance._names_by_ip: Dict[str, str] = {}
                    cls._instance._cache_lock = threading.Lock()
                    cls._instance._last_sweep = 0.0
        return cls._instance

    def get_services_for_ip(self, ip: str) -> List[str]:
        """Return cached mDNS services for an IP address."""
        with self._cache_lock:
            return sorted(list(self._services_by_ip.get(ip, set())))

    def get_name_for_ip(self, ip: str) -> Optional[str]:
        """Return cached mDNS announced name for an IP address."""
        with self._cache_lock:
            return self._names_by_ip.get(ip)

    def trigger_sweep(self, timeout_sec: float = 0.6) -> None:
        """
        Send a lightweight mDNS multicast probe for common device services.
        Collects responses asynchronously with a strict timeout.
        """
        now = time.time()
        # Rate-limit global sweeps to once every 30 seconds
        if now - self._last_sweep < 30.0:
            return
        self._last_sweep = now

        threading.Thread(
            target=self._run_probe,
            args=(timeout_sec,),
            daemon=True,
            name="mDNS-Sweep"
        ).start()

    def _run_probe(self, timeout_sec: float) -> None:
        """Execute UDP multicast queries and collect replies."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(timeout_sec)
            # Allow multiple sockets to use the same PORT number
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Build and send PTR queries for our target services
            for service in TARGET_SERVICES:
                packet = self._build_dns_query(service)
                try:
                    sock.sendto(packet, (MDNS_GROUP, MDNS_PORT))
                except Exception:
                    pass

            start_time = time.time()
            while time.time() - start_time < timeout_sec:
                try:
                    data, (src_ip, _) = sock.recvfrom(4096)
                    self._parse_mdns_response(data, src_ip)
                except socket.timeout:
                    break
                except Exception:
                    break

            sock.close()
        except Exception as e:
            logger.debug(f"mDNS sweep notice: {e}")

    def _build_dns_query(self, service_name: str) -> bytes:
        """Build standard DNS PTR query packet for a service."""
        header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
        qname = b""
        for part in service_name.split("."):
            encoded = part.encode("utf-8")
            qname += struct.pack("B", len(encoded)) + encoded
        qname += b"\x00"
        # Type PTR (12), Class IN (1) | QU unicast response requested
        qtype_qclass = struct.pack(">HH", 12, 1)
        return header + qname + qtype_qclass

    def _parse_mdns_response(self, data: bytes, src_ip: str) -> None:
        """Lightweight extraction of service names and text records from response."""
        try:
            raw_text = data.decode("latin-1", errors="ignore")
            for svc in TARGET_SERVICES:
                svc_clean = svc.replace(".local", "")
                if svc_clean in raw_text or svc in raw_text:
                    with self._cache_lock:
                        self._services_by_ip.setdefault(src_ip, set()).add(svc_clean)

            # Check for common friendly names in text records
            # e.g. "model=AppleTV", "model=MacBookPro", "am=AppleTV"
            for marker in ["model=", "am=", "md="]:
                if marker in raw_text:
                    start = raw_text.find(marker) + len(marker)
                    end = raw_text.find("\x00", start)
                    if end == -1 or end - start > 40:
                        end = raw_text.find(" ", start)
                    if 0 < end - start <= 40:
                        extracted = raw_text[start:end].strip()
                        if extracted and len(extracted) > 2:
                            with self._cache_lock:
                                self._names_by_ip[src_ip] = extracted
        except Exception:
            pass


mdns_discoverer = MDNSDiscoverer()
