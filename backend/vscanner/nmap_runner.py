"""
HorusShield V-8 Scanner — Nmap Runner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Thin subprocess wrapper around the system `nmap` binary.

HorusShield never constructs Nmap NSE exploit scripts or crafts custom
packets — it shells out to the real, already-installed `nmap` tool with
a conservative, non-intrusive script set (`default` + `safe` categories
only) and parses Nmap's own XML output. This mirrors what any analyst
would do from a terminal; the "logic" here is process-management and
XML parsing, not attack logic.
"""
import shlex
import shutil
import subprocess
import defusedxml.ElementTree as ET
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from config import active_config as config
from utils.logger import get_logger

logger = get_logger("nmap_runner", "vscanner")


class NmapRunner:
    """Runs a safe Nmap service/version scan against a single host."""

    def __init__(self, nmap_path: Optional[str] = None, timeout: Optional[int] = None):
        self.nmap_path = nmap_path or config.NMAP_PATH
        self.timeout = timeout or config.NMAP_TIMEOUT

    def is_available(self) -> bool:
        return shutil.which(self.nmap_path) is not None

    @staticmethod
    def _host_from_url(target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        return parsed.hostname or target_url

    def scan(self, target_url: str) -> Dict[str, Any]:
        """Run a service/version detection scan with only default+safe NSE scripts.

        Returns a dict: {"success": bool, "host": str, "ports": [...], "error": str}
        """
        host = self._host_from_url(target_url)
        if not self.is_available():
            return {"success": False, "host": host, "ports": [], "error": "nmap binary not found on PATH"}

        cmd = [
            self.nmap_path,
            "-sV",                       # version detection
            "--script", "default,safe",  # NO 'vuln'/'exploit' categories, no crafted payloads
            "-T3",                       # polite timing, avoid hammering the target
            "-oX", "-",                  # XML to stdout
            host,
        ]
        logger.info(f"Nmap scan starting: {' '.join(shlex.quote(c) for c in cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            return {"success": False, "host": host, "ports": [], "error": "Nmap scan timed out"}
        except Exception as e:
            logger.error(f"Nmap execution error: {e}")
            return {"success": False, "host": host, "ports": [], "error": str(e)}

        if proc.returncode not in (0, None) and not proc.stdout:
            return {"success": False, "host": host, "ports": [], "error": proc.stderr.strip()[:500]}

        try:
            ports = self._parse_xml(proc.stdout)
        except Exception as e:
            logger.error(f"Nmap XML parse error: {e}")
            return {"success": False, "host": host, "ports": [], "error": f"Parse error: {e}"}

        return {"success": True, "host": host, "ports": ports, "error": ""}

    @staticmethod
    def _parse_xml(xml_text: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not xml_text.strip():
            return results
        root = ET.fromstring(xml_text)
        for host_el in root.findall("host"):
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue
                service_el = port_el.find("service")
                scripts = []
                for script_el in port_el.findall("script"):
                    scripts.append({
                        "id": script_el.get("id", ""),
                        "output": (script_el.get("output", "") or "")[:2000],
                    })
                results.append({
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": state,
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                    "scripts": scripts,
                })
        return results
