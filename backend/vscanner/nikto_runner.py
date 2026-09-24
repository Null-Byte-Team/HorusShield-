"""
HorusShield V-8 Scanner — Nikto Runner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Thin subprocess wrapper around the system `nikto` binary.

Nikto already implements its own well-known web-server misconfiguration
and sensitive-file checks. HorusShield only invokes it with its native
JSON output format and parses the result — it does not add, modify, or
generate any of Nikto's test payloads.
"""
import json
import shlex
import subprocess
import tempfile
import os
from typing import Any, Dict, List, Optional

from config import active_config as config
from utils.logger import get_logger
from vscanner.tool_discovery import resolve_nikto, resolve_perl

logger = get_logger("nikto_runner", "vscanner")


class NiktoRunner:
    """Runs a standard Nikto web-server scan and parses its JSON report."""

    def __init__(self, nikto_path: Optional[str] = None, timeout: Optional[int] = None):
        self.nikto_path = nikto_path or config.NIKTO_PATH
        self.timeout = timeout or config.NIKTO_TIMEOUT

    def is_available(self) -> bool:
        return bool(resolve_nikto(self.nikto_path) and resolve_perl(config.PERL_PATH))

    def scan(self, target_url: str) -> Dict[str, Any]:
        """Run `nikto -h <url> -Format json -output <tmpfile>` and parse it.

        Returns {"success": bool, "findings": [...], "error": str}
        """
        script = resolve_nikto(self.nikto_path)
        perl = resolve_perl(config.PERL_PATH)
        if not script:
            return {"success": False, "findings": [], "error": "Nikto script not found"}
        if not perl:
            return {"success": False, "findings": [], "error": "Nikto was found, but Perl is unavailable"}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        cmd = [
            perl,
            script,
            "-h", target_url,
            "-Format", "json",
            "-output", out_path,
            "-nointeractive",
        ]
        logger.info(f"Nikto scan starting: {' '.join(shlex.quote(c) for c in cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                cwd=os.path.dirname(script), timeout=self.timeout, shell=False
            )
        except subprocess.TimeoutExpired:
            self._cleanup(out_path)
            return {"success": False, "findings": [], "error": "Nikto scan timed out"}
        except Exception as e:
            logger.error(f"Nikto execution error: {e}")
            self._cleanup(out_path)
            return {"success": False, "findings": [], "error": f"Nikto could not start: {e}"}

        findings: List[Dict[str, Any]] = []
        try:
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                findings = self._normalize(data)
            elif proc.returncode != 0:
                return {"success": False, "findings": [], "error": f"Nikto exited with code {proc.returncode}: {proc.stderr.strip()[:400]}"}
            else:
                return {"success": False, "findings": [], "error": "Nikto returned no output"}
        except Exception as e:
            logger.error(f"Nikto output parse error: {e}")
            return {"success": False, "findings": [], "error": f"Nikto returned invalid output: {e}"}
        finally:
            self._cleanup(out_path)

        return {"success": True, "findings": findings, "error": ""}

    @staticmethod
    def _cleanup(path: str) -> None:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    @staticmethod
    def _normalize(data: Any) -> List[Dict[str, Any]]:
        """Nikto's JSON report shape: {"host":..., "vulnerabilities": [...]}"""
        vulns = []
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", []) or []
        elif isinstance(data, list):
            vulns = data
        out = []
        for v in vulns:
            out.append({
                "id": v.get("id", ""),
                "method": v.get("method", "GET"),
                "url": v.get("url", ""),
                "message": v.get("msg", v.get("message", "")),
                "osvdb": v.get("OSVDB", v.get("references", "")),
            })
        return out
