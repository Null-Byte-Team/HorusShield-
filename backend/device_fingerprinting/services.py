"""
HorusShield 2.0 — Network Service Fingerprinting Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Safely observes network services and banners across standard diagnostic ports.
Analyzes port combinations rather than single-port assumptions.
Non-intrusive, strictly local, and bounded by tight timeouts.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import Any, Dict, List, Optional, Set

from utils.logger import get_logger

logger = get_logger("fingerprint_services", "device")

DIAGNOSTIC_PORTS = [80, 443, 22, 445, 139, 631, 9100, 53, 554, 3389, 8080, 5000, 8008]
PROBE_TIMEOUT = 0.35  # seconds per port connect


class ServiceFingerprinter:
    """Safe, bounded scanner for network service clues."""

    def probe_services(self, ip: str, given_ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Probe diagnostic ports on the target host and extract lightweight banners.
        Returns:
            {
                "open_ports": List[int],
                "banners": Dict[int, str],
                "http_server": Optional[str],
                "ssh_banner": Optional[str],
                "has_printer_ports": bool,
                "has_camera_ports": bool,
                "has_smb": bool,
                "has_rdp": bool,
                "has_dns": bool,
                "has_gateway_services": bool,
            }
        """
        if not ip or ip == "127.0.0.1" or ip == "0.0.0.0":
            return self._empty_result()

        open_ports: Set[int] = set()

        # If caller already provided open ports from a previous scan, reuse them
        if given_ports:
            open_ports.update(given_ports)

        # Probe ports that weren't checked yet
        ports_to_check = [p for p in DIAGNOSTIC_PORTS if p not in open_ports]

        def check_port(port: int) -> Optional[int]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(PROBE_TIMEOUT)
                    if s.connect_ex((ip, port)) == 0:
                        return port
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=14) as executor:
            futures = [executor.submit(check_port, p) for p in ports_to_check]
            for fut in as_completed(futures):
                res = fut.result()
                if res is not None:
                    open_ports.add(res)

        banners: Dict[int, str] = {}
        http_server: Optional[str] = None
        ssh_banner: Optional[str] = None

        # Safe HTTP banner inspection (ports 80 / 8080)
        for web_port in [80, 8080]:
            if web_port in open_ports and not http_server:
                banner = self._grab_http_banner(ip, web_port)
                if banner:
                    banners[web_port] = banner
                    http_server = banner

        # Safe SSH banner inspection (port 22)
        if 22 in open_ports:
            ssh_banner = self._grab_ssh_banner(ip, 22)
            if ssh_banner:
                banners[22] = ssh_banner

        # Safe RTSP inspection (port 554)
        if 554 in open_ports:
            rtsp_banner = self._grab_rtsp_banner(ip, 554)
            if rtsp_banner:
                banners[554] = rtsp_banner

        sorted_ports = sorted(list(open_ports))

        return {
            "open_ports": sorted_ports,
            "banners": banners,
            "http_server": http_server,
            "ssh_banner": ssh_banner,
            "has_printer_ports": 631 in open_ports or 9100 in open_ports,
            "has_camera_ports": 554 in open_ports or (banners.get(554) is not None),
            "has_smb": 445 in open_ports or 139 in open_ports,
            "has_rdp": 3389 in open_ports,
            "has_dns": 53 in open_ports,
            "has_gateway_services": (53 in open_ports or 67 in open_ports) and (80 in open_ports or 443 in open_ports or 8080 in open_ports),
        }

    def _grab_http_banner(self, ip: str, port: int) -> Optional[str]:
        """Send HEAD / and read Server header."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                s.connect((ip, port))
                req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HorusShield\r\n\r\n"
                s.sendall(req.encode("ascii"))
                data = s.recv(1024).decode("latin-1", errors="ignore")
                for line in data.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return None

    def _grab_ssh_banner(self, ip: str, port: int) -> Optional[str]:
        """Read initial SSH identification string."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                s.connect((ip, port))
                data = s.recv(256).decode("ascii", errors="ignore").strip()
                if data.startswith("SSH-"):
                    return data
        except Exception:
            pass
        return None

    def _grab_rtsp_banner(self, ip: str, port: int) -> Optional[str]:
        """Send safe RTSP OPTIONS and read response."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                s.connect((ip, port))
                req = f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: HorusShield\r\n\r\n"
                s.sendall(req.encode("ascii"))
                data = s.recv(512).decode("latin-1", errors="ignore")
                if "RTSP/1.0" in data:
                    for line in data.splitlines():
                        if line.lower().startswith("server:"):
                            return line.split(":", 1)[1].strip()
                    return "RTSP Server"
        except Exception:
            pass
        return None

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "open_ports": [],
            "banners": {},
            "http_server": None,
            "ssh_banner": None,
            "has_printer_ports": False,
            "has_camera_ports": False,
            "has_smb": False,
            "has_rdp": False,
            "has_dns": False,
            "has_gateway_services": False,
        }


service_fingerprinter = ServiceFingerprinter()
