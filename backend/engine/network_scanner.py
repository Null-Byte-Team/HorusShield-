"""
HorusShield Network Scanner — Improved
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Only returns devices that genuinely respond.  Falls back gracefully when
Scapy / WinPcap is unavailable.  Improved over v4-3:
  • _socket_scan uses a thread-pool (concurrent.futures) for faster scanning
  • Multi-port probe per host — avoids false positives from filtered hosts
  • ARP + neighbor-table + socket results are merged correctly
  • All public methods type-annotated
  • _merge_devices deduplicates by MAC, then by IP
"""

import ipaddress
import platform
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from utils.logger import get_logger
from utils.helpers import (
    classify_device_type,
    get_gateway_ip,
    get_hostname,
    get_local_ip,
    get_network_range,
    mac_to_vendor,
    synthetic_mac_from_ip,
)

logger = get_logger("network_scanner", "network")

# Ports tried when checking whether a host is truly alive
_PROBE_PORTS = (80, 443, 22, 445, 8080, 7, 139, 135, 3389)
_SOCKET_TIMEOUT = 0.4          # seconds per port probe
_MAX_SCANNER_WORKERS = 64      # concurrent socket-scan threads


class NetworkScanner:
    def __init__(self) -> None:
        self.local_ip = get_local_ip()
        self.network_range = get_network_range(self.local_ip)
        self.gateway_ip = get_gateway_ip()
        self._scanning = False

    # ── public entry point ──

    def arp_scan(self, network_range: Optional[str] = None) -> List[Dict]:
        """Run a full network scan; return a deduplicated list of live devices."""
        target = network_range or self.network_range
        arp_devices = self._arp_scan(target)
        cached_devices = self._read_neighbor_table(target)

        # Only fall back to the slower socket scan when ARP found nothing useful
        socket_devices: List[Dict] = []
        if len(arp_devices) < 2:
            socket_devices = self._socket_scan(target)

        return self._merge_devices(
            self._synthetic_local_devices(),
            cached_devices,
            arp_devices,
            socket_devices,
        )

    # ── scan strategies ──

    def _arp_scan(self, target: str) -> List[Dict]:
        """Try a Scapy ARP sweep; return empty list if unavailable."""
        try:
            from scapy.all import ARP, Ether, srp, conf  # type: ignore
            conf.verb = 0
            logger.info(f"ARP scan on {target}")
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answered, _ = srp(pkt, timeout=3, verbose=False)
            devices = []
            for _, received in answered:
                ip = received.psrc
                mac = received.hwsrc.upper()
                devices.append(self._build_device_dict(ip, mac))
            logger.info(f"ARP scan complete: {len(devices)} devices found")
            return devices
        except ImportError:
            logger.warning("Scapy not available — skipping ARP scan")
        except Exception as exc:
            msg = str(exc).lower()
            if "pcap" in msg or "winpcap" in msg:
                logger.warning("WinPcap/Npcap not installed — skipping ARP scan")
            else:
                logger.error(f"ARP scan error: {exc}")
        return []

    def _socket_scan(self, network_range: str) -> List[Dict]:
        """
        Concurrent multi-port TCP probe scan.

        A host is considered *alive* if it responds to **any** of the probe
        ports (SYN-ACK, RST, or even an explicit connection-refused all count
        as evidence that the host exists).
        """
        host_ips = self._host_candidates(network_range, limit=512)
        logger.info(f"Socket scan on {network_range} ({len(host_ips)} candidates)")
        devices: List[Dict] = []
        lock = threading.Lock()

        def probe(ip: str) -> Optional[str]:
            """Return ip if the host is alive, else None."""
            for port in _PROBE_PORTS:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(_SOCKET_TIMEOUT)
                        result = sock.connect_ex((ip, port))
                        # 0 = connected, 111/10061 = refused — both mean a live host
                        if result in (0, 111, 10061):
                            return ip
                except OSError:
                    pass
            return None

        with ThreadPoolExecutor(max_workers=_MAX_SCANNER_WORKERS) as pool:
            futures = {pool.submit(probe, ip): ip for ip in host_ips}
            for future in as_completed(futures):
                ip = future.result()
                if ip:
                    mac = synthetic_mac_from_ip(ip)
                    with lock:
                        devices.append(self._build_device_dict(ip, mac))

        logger.info(f"Socket scan complete: {len(devices)} live hosts found")
        return devices

    def _read_neighbor_table(self, network_range: str) -> List[Dict]:
        """Parse the OS ARP/neighbour cache for known MAC→IP pairs."""
        devices: List[Dict] = []
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            if platform.system().lower() == "windows":
                output = subprocess.check_output("arp -a", shell=True, timeout=5).decode(errors="ignore")
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        mac_raw = parts[1].strip()
                        try:
                            if ipaddress.ip_address(ip) in network:
                                mac = mac_raw.upper().replace("-", ":")
                                if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                                    devices.append(self._build_device_dict(ip, mac))
                        except ValueError:
                            pass
            else:
                for cmd in (["ip", "neigh"], ["arp", "-n"]):
                    try:
                        output = subprocess.check_output(cmd, timeout=5).decode(errors="ignore")
                        for line in output.splitlines():
                            parts = line.split()
                            ip = parts[0] if parts else ""
                            mac = ""
                            for part in parts:
                                if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", part):
                                    mac = part.upper()
                                    break
                            try:
                                if ip and mac and ipaddress.ip_address(ip) in network:
                                    devices.append(self._build_device_dict(ip, mac))
                            except ValueError:
                                pass
                        break
                    except (FileNotFoundError, subprocess.CalledProcessError):
                        continue
        except Exception as exc:
            logger.warning(f"Neighbor table read failed: {exc}")
        return devices

    def _synthetic_local_devices(self) -> List[Dict]:
        """Always include the scanning host itself."""
        return [self._build_device_dict(self.local_ip, synthetic_mac_from_ip(self.local_ip))]

    # ── helpers ──

    def _build_device_dict(self, ip: str, mac: str) -> Dict:
        """Construct a normalised device dict from an IP + MAC pair."""
        hostname = get_hostname(ip)
        vendor = mac_to_vendor(mac)
        return {
            "ip_address": ip,
            "mac_address": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": classify_device_type(hostname, vendor),
            "is_gateway": ip == self.gateway_ip,
        }

    @staticmethod
    def _host_candidates(network_range: str, limit: int = 512) -> List[str]:
        """Return up to *limit* host IPs from the given CIDR range."""
        try:
            net = ipaddress.ip_network(network_range, strict=False)
            hosts = list(net.hosts())
            return [str(h) for h in hosts[:limit]]
        except ValueError:
            return []

    @staticmethod
    def _merge_devices(*device_lists: List[Dict]) -> List[Dict]:
        """
        Merge multiple device lists, deduplicating first by MAC, then by IP.
        Later lists take priority for metadata fields when a MAC matches.
        """
        seen_macs: Dict[str, Dict] = {}
        seen_ips: Dict[str, Dict] = {}

        for device_list in device_lists:
            for device in device_list:
                mac = device.get("mac_address", "")
                ip = device.get("ip_address", "")

                if mac and mac in seen_macs:
                    # Update with more recent data (later lists win)
                    seen_macs[mac].update({k: v for k, v in device.items() if v})
                elif mac:
                    seen_macs[mac] = dict(device)
                    if ip:
                        seen_ips[ip] = seen_macs[mac]
                elif ip and ip not in seen_ips:
                    # No MAC — deduplicate by IP
                    seen_ips[ip] = dict(device)

        # Combine: MAC-keyed entries are canonical; add any IP-only stragglers
        result = list(seen_macs.values())
        for ip, dev in seen_ips.items():
            if not any(d.get("ip_address") == ip for d in result):
                result.append(dev)

        return result
