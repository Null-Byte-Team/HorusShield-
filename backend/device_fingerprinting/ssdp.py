"""
HorusShield 2.0 — SSDP / UPnP Discovery Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Discovers and parses UPnP / SSDP device announcements across the subnet.
Extracts friendlyName, manufacturer, modelName, modelNumber, and deviceType.
Strictly local and non-blocking with defusedxml protection.
"""

import re
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from urllib.parse import urlparse

import urllib.request
import defusedxml.ElementTree as ET

from utils.logger import get_logger

logger = get_logger("fingerprint_ssdp", "device")

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2

M_SEARCH_PAYLOAD = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    f"MX: {SSDP_MX}\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("utf-8")


class SSDPDiscoverer:
    """Thread-safe SSDP/UPnP active scanner and cache."""

    _instance: Optional["SSDPDiscoverer"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "SSDPDiscoverer":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    # IP -> Dictionary of UPnP attributes
                    cls._instance._devices_by_ip: Dict[str, Dict[str, Any]] = {}
                    cls._instance._cache_lock = threading.Lock()
                    cls._instance._last_sweep = 0.0
        return cls._instance

    def get_ssdp_for_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Return cached UPnP/SSDP details for an IP address."""
        with self._cache_lock:
            data = self._devices_by_ip.get(ip)
            return dict(data) if data else None

    def trigger_sweep(self, timeout_sec: float = 0.8) -> None:
        """Trigger an asynchronous SSDP discovery broadcast."""
        now = time.time()
        # Rate-limit global sweeps to once every 30 seconds
        if now - self._last_sweep < 30.0:
            return
        self._last_sweep = now

        threading.Thread(
            target=self._run_sweep,
            args=(timeout_sec,),
            daemon=True,
            name="SSDP-Sweep"
        ).start()

    def _run_sweep(self, timeout_sec: float) -> None:
        """Broadcast SSDP M-SEARCH and process incoming responses."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(timeout_sec)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(M_SEARCH_PAYLOAD, (SSDP_ADDR, SSDP_PORT))

            start_time = time.time()
            discovered_locations: List[Tuple[str, str]] = []

            while time.time() - start_time < timeout_sec:
                try:
                    data, (src_ip, _) = sock.recvfrom(4096)
                    location = self._extract_header(data, "LOCATION")
                    server = self._extract_header(data, "SERVER")
                    st = self._extract_header(data, "ST")

                    with self._cache_lock:
                        entry = self._devices_by_ip.setdefault(src_ip, {})
                        if server:
                            entry["server"] = server
                        if st:
                            entry["st"] = st
                        if location and "location" not in entry:
                            entry["location"] = location
                            discovered_locations.append((src_ip, location))
                except socket.timeout:
                    break
                except Exception:
                    break

            sock.close()

            # Safely fetch XML descriptions for discovered devices in background
            for ip, loc in discovered_locations[:10]:
                self._fetch_xml_description(ip, loc)

        except Exception as e:
            logger.debug(f"SSDP sweep notice: {e}")

    def _extract_header(self, data: bytes, header_name: str) -> Optional[str]:
        """Extract a single header value from raw HTTP-like text."""
        try:
            text = data.decode("utf-8", errors="ignore")
            pattern = rf"(?i)^{re.escape(header_name)}\s*:\s*(.+)$"
            match = re.search(pattern, text, re.MULTILINE)
            return match.group(1).strip() if match else None
        except Exception:
            return None

    def _fetch_xml_description(self, ip: str, location_url: str) -> None:
        """Fetch and parse UPnP XML device description safely."""
        try:
            parsed = urlparse(location_url)
            # Only allow HTTP/HTTPS to private IP addresses (no DNS rebinding, no cloud)
            host = parsed.hostname
            if not host:
                return

            # Quick verification that target is a private IPv4 address
            is_private = (
                host.startswith("192.168.")
                or host.startswith("10.")
                or host.startswith("172.16.")
                or host.startswith("172.17.")
                or host.startswith("172.18.")
                or host.startswith("172.19.")
                or host.startswith("172.2")
                or host.startswith("172.3")
                or host == "127.0.0.1"
            )
            if not is_private:
                return

            req = urllib.request.Request(
                location_url,
                headers={"User-Agent": "HorusShield/2.0 UPnP-Client"}
            )
            with urllib.request.urlopen(req, timeout=0.8) as resp:
                xml_data = resp.read(65536)  # Cap read to 64KB for safety

            root = ET.fromstring(xml_data)

            # Extract standard UPnP device fields ignoring namespaces
            def find_text(tag_name: str) -> Optional[str]:
                for elem in root.iter():
                    if elem.tag.endswith(tag_name) and elem.text and elem.text.strip():
                        return elem.text.strip()
                return None

            friendly_name = find_text("friendlyName")
            manufacturer = find_text("manufacturer")
            model_name = find_text("modelName")
            model_number = find_text("modelNumber")
            device_type = find_text("deviceType")

            with self._cache_lock:
                entry = self._devices_by_ip.setdefault(ip, {})
                if friendly_name:
                    entry["friendly_name"] = friendly_name
                if manufacturer:
                    entry["manufacturer"] = manufacturer
                if model_name:
                    entry["model_name"] = model_name
                if model_number:
                    entry["model_number"] = model_number
                if device_type:
                    entry["device_type"] = device_type

        except Exception as e:
            logger.debug(f"UPnP XML fetch skipped for {ip}: {e}")


ssdp_discoverer = SSDPDiscoverer()
