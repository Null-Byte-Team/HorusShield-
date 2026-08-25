"""
HorusShield V-8 Scanner — OWASP ZAP Client
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A minimal REST client for a locally-running OWASP ZAP daemon
(`zap.sh -daemon ...` / `zap.bat -daemon ...`).

HorusShield does not send any raw attack traffic itself. It only calls
ZAP's own, well-documented API endpoints (spider, passive scan, optional
active scan, alerts) — ZAP is the tool that owns and executes all actual
test logic. This client is pure HTTP orchestration + JSON parsing.

Requires ZAP to already be running and reachable at config.ZAP_API_URL.
"""
import time
from typing import Any, Dict, List, Optional

import requests

from config import active_config as config
from utils.logger import get_logger

logger = get_logger("zap_client", "vscanner")


class ZAPClient:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or config.ZAP_API_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else config.ZAP_API_KEY
        self.timeout = config.ZAP_TIMEOUT
        self.poll_interval = config.ZAP_POLL_INTERVAL

    # ── low level ──

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        params = dict(params or {})
        if self.api_key:
            params["apikey"] = self.api_key
        try:
            r = requests.get(f"{self.base_url}{path}", params=params, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"ZAP API call failed ({path}): {e}")
            return None

    def is_available(self) -> bool:
        return self._get("/JSON/core/view/version/") is not None

    # ── workflow steps — each simply triggers ZAP's own built-in engine ──

    def new_session(self) -> bool:
        return self._get("/JSON/core/action/newSession/", {"name": "", "overwrite": "true"}) is not None

    def spider(self, target_url: str, max_wait: int = 180) -> Dict[str, Any]:
        """Crawl the target to discover pages/endpoints (ZAP's own spider)."""
        resp = self._get("/JSON/spider/action/scan/", {"url": target_url, "recurse": "true"})
        if not resp or "scan" not in resp:
            return {"success": False, "urls_found": 0, "error": "Failed to start ZAP spider"}
        scan_id = resp["scan"]
        waited = 0
        status = 0
        while waited < max_wait:
            st = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
            status = int(st.get("status", 0)) if st else 0
            if status >= 100:
                break
            time.sleep(self.poll_interval)
            waited += self.poll_interval
        results = self._get("/JSON/spider/view/results/", {"scanId": scan_id}) or {}
        urls = results.get("results", [])
        return {"success": True, "urls_found": len(urls), "urls": urls, "error": ""}

    def passive_scan_wait(self, max_wait: int = 120) -> Dict[str, Any]:
        """Wait for ZAP's passive scanner (non-intrusive) to finish analyzing traffic."""
        waited = 0
        remaining = 0
        while waited < max_wait:
            st = self._get("/JSON/pscan/view/recordsToScan/")
            remaining = int(st.get("recordsToScan", 0)) if st else 0
            if remaining <= 0:
                break
            time.sleep(self.poll_interval)
            waited += self.poll_interval
        return {"success": True, "records_remaining": remaining}

    def active_scan(self, target_url: str, max_wait: int = 900) -> Dict[str, Any]:
        """Run ZAP's active scanner. This DOES send live test requests to the
        target — this is ZAP's own, standard authorized-testing behavior, not
        custom payloads written by HorusShield. Only call this when the user
        has explicitly opted in and confirmed authorization for the target."""
        resp = self._get("/JSON/ascan/action/scan/", {"url": target_url, "recurse": "true"})
        if not resp or "scan" not in resp:
            return {"success": False, "error": "Failed to start ZAP active scan"}
        scan_id = resp["scan"]
        waited = 0
        progress = 0
        while waited < max_wait:
            st = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
            progress = int(st.get("status", 0)) if st else 0
            if progress >= 100:
                break
            time.sleep(self.poll_interval)
            waited += self.poll_interval
        return {"success": True, "progress": progress}

    def get_alerts(self, target_url: str) -> List[Dict[str, Any]]:
        """Retrieve all findings ZAP has recorded for this target (from spider,
        passive scan, and active scan if it ran)."""
        resp = self._get("/JSON/core/view/alerts/", {"baseurl": target_url})
        if not resp:
            return []
        return resp.get("alerts", [])
