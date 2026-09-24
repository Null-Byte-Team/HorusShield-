"""
HorusShield V-8 Scanner — Orchestrator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Coordinates a single scan job: runs the selected tools in sequence,
normalizes their native findings through the AI Cortex, persists
everything to the database, and streams progress over Socket.IO.

Workflow (only as intrusive as the user opts into):
  Target URL → Nmap recon → ZAP spider → ZAP passive scan →
  [optional, explicit opt-in] ZAP active scan → Nikto scan →
  AI Cortex (dedup/classify/score/prioritize) → stored findings + report
"""
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from database.db_manager import db
from utils.helpers import generate_session_id
from utils.logger import get_logger
from ai.vscanner_cortex import VScannerCortex
from vscanner.domain_reputation import domain_reputation
from vscanner.fast_web_scanner import fast_web_scanner
from vscanner.nmap_runner import NmapRunner
from vscanner.nikto_runner import NiktoRunner
from vscanner.zap_client import ZAPClient

logger = get_logger("vscanner_orchestrator", "vscanner")


class VScannerManager:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.nmap = NmapRunner()
        self.nikto = NiktoRunner()
        self.zap = ZAPClient()
        self.fast_scanner = fast_web_scanner
        self._stop_flags: Dict[str, bool] = {}
        self._lock = threading.Lock()

    # ── public API ──

    def start_scan(
        self,
        target_url: str,
        tools: Optional[List[str]] = None,
        active_scan: bool = False,
        requested_by: str = "",
        owner_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        requested_tools = tools or ["nmap"]
        if any(tool != "nmap" for tool in requested_tools):
            return {
                "success": False,
                "error": "Only Nmap is available in the web scanner",
            }
        tools = ["nmap"]
        scan_id = generate_session_id()
        db.add_vscan(
            scan_id,
            target_url,
            tools,
            active_scan=active_scan,
            requested_by=requested_by,
            owner_id=owner_id,
        )

        with self._lock:
            self._stop_flags[scan_id] = False

        t = threading.Thread(
            target=self._run,
            args=(scan_id, target_url, tools, active_scan),
            daemon=True,
        )
        t.start()
        return {"success": True, "scan_id": scan_id}

    def stop_scan(self, scan_id: str) -> Dict[str, Any]:
        if scan_id in self._stop_flags:
            self._stop_flags[scan_id] = True
            db.update_vscan(scan_id, status="stopped", stage="Stopped by user")
            self._emit("vscan_stopped", {"scan_id": scan_id})
            return {"success": True}
        return {"success": False, "error": "Scan not found or already finished"}

    # ── internals ──

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        if self.socketio:
            try:
                self.socketio.emit(event, payload)
            except Exception as e:
                logger.debug(f"socket emit failed: {e}")

    def _progress(self, scan_id: str, stage: str, progress: int) -> None:
        db.update_vscan(scan_id, stage=stage, progress=progress)
        self._emit("vscan_progress", {"scan_id": scan_id, "stage": stage, "progress": progress})
        logger.info(f"[{scan_id}] {stage} ({progress}%)")

    def _stopped(self, scan_id: str) -> bool:
        return self._stop_flags.get(scan_id, False)

    def _revalidate(self, scan_id: str, target_url: str, tool_name: str) -> bool:
        """Re-validate target URL immediately before invoking an external tool.
        Returns True if valid, or False (with scan marked failed and logged) if
        validation fails (e.g. DNS rebinding/TOCTOU IP change)."""
        from config import active_config as _config
        from security.ssrf import SSRFValidationError, validate_target

        try:
            validate_target(target_url, allow_private=_config.VSCAN_ALLOW_PRIVATE_TARGETS)
            return True
        except SSRFValidationError as e:
            logger.warning(f"[{scan_id}] SSRF re-validation failed before {tool_name}: {e}")
            db.update_vscan(
                scan_id,
                status="failed",
                error=f"SSRF protection ({tool_name}): {e}",
                finished_at=datetime.now().isoformat(),
            )
            self._emit("vscan_failed", {"scan_id": scan_id, "error": f"SSRF protection ({tool_name}): {e}"})
            db.add_audit_log(
                action="scan_finished",
                status="failure",
                details=f"scan_id={scan_id} target={target_url} error=SSRF re-validation failed before {tool_name}: {e}",
            )
            return False

    def _run(self, scan_id: str, target_url: str, tools: List[str], active_scan: bool) -> None:
        raw_findings: List[Dict[str, Any]] = []
        db.update_vscan(scan_id, status="running", started_at=datetime.now().isoformat())
        try:
            self._progress(scan_id, "Target analysis", 5)

            host = self.nmap._host_from_url(target_url)

            # ── Fast Cache Check (0-socket instant response) ──
            cached = domain_reputation.get_cached_result(target_url)
            if cached and not self._stopped(scan_id):
                self._progress(scan_id, "Instant response — retrieved from memory cache", 90)
                self._emit("vscan_log", {"scan_id": scan_id, "message": f"⚡ Fast Cache Hit: {cached['host']} (0ms socket latency)"})
                cached_findings = cached.get("findings", [])
                for f in cached_findings:
                    db.add_vscan_finding(
                        scan_id=scan_id,
                        source_tool=f.get("source_tool", "cache"),
                        finding_type=f.get("finding_type", "Info"),
                        severity=f.get("severity", "info"),
                        confidence=f.get("confidence", 1.0),
                        url=f.get("url", ""),
                        parameter=f.get("parameter", ""),
                        owasp_category=f.get("owasp_category", ""),
                        cwe_id=f.get("cwe_id", ""),
                        description=f.get("description", ""),
                        evidence=f.get("evidence", ""),
                        recommendation=f.get("recommendation", ""),
                        ai_explanation=f.get("ai_explanation", ""),
                        dedup_hash=f.get("dedup_hash", ""),
                        is_duplicate=f.get("is_duplicate", False),
                        correlation_group=f.get("correlation_group") or "",
                        correlated_with_tools=f.get("correlated_with_tools", []),
                        raw_data=f.get("raw_data", {}),
                    )
                cached_summary = cached.get("summary", {"total_findings": len(cached_findings), "duplicates_removed": 0, "average_confidence": 1.0, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": len(cached_findings)}})
                db.update_vscan(
                    scan_id,
                    status="completed",
                    stage="Completed (Cached)",
                    progress=100,
                    findings_count=cached_summary["total_findings"],
                    finished_at=datetime.now().isoformat(),
                )
                self._emit("vscan_complete", {"scan_id": scan_id, "summary": cached_summary})
                db.add_audit_log(
                    action="scan_finished", status="success",
                    details=f"scan_id={scan_id} target={target_url} findings={cached_summary['total_findings']} (cached)",
                )
                return

            # ── Domain Reputation & Whitelist Check ──
            rep = domain_reputation.check_reputation(target_url)
            if rep["status"] == "whitelisted" and not self._stopped(scan_id):
                self._progress(scan_id, f"Domain reputation: {rep['service_name']} (Verified Safe)", 30)
                self._emit("vscan_log", {"scan_id": scan_id, "message": f"🛡️ Whitelist Match: {rep['service_name']}"})
                self._emit("vscan_log", {"scan_id": scan_id, "message": f"ℹ️ {rep['description']}"})
                self._progress(scan_id, "AI certification — generating verified safe report", 75)
                safe_finding = {
                    "source_tool": "reputation",
                    "finding_type": "Verified Safe Domain (Approved Infrastructure)",
                    "severity": "info",
                    "confidence": 1.0,
                    "url": target_url,
                    "parameter": "",
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "cwe_id": "CWE-1008",
                    "description": f"Target '{rep['hostname']}' is recognized as high-reputation trusted infrastructure: {rep['service_name']}.",
                    "evidence": rep["description"],
                    "recommendation": "Verified legitimate host. Fast-track approval granted without socket exhaustion.",
                    "ai_explanation": f"The target domain is verified as enterprise-grade platform infrastructure ({rep['service_name']}). Intensive port sweeps were safely bypassed.",
                    "dedup_hash": f"rep-safe-{rep['hostname']}",
                    "is_duplicate": False,
                    "correlation_group": f"rep-{rep['hostname']}",
                    "correlated_with_tools": ["reputation"],
                    "raw_data": rep,
                }
                raw_findings.append(safe_finding)
            elif rep["status"] == "blacklisted" and not self._stopped(scan_id):
                self._progress(scan_id, f"Threat Intel Alert: {rep['service_name']}", 30)
                self._emit("vscan_log", {"scan_id": scan_id, "message": f"🚨 Blacklisted Target: {rep['service_name']}"})
                bad_finding = {
                    "source_tool": "threat_intel",
                    "finding_type": "Known Malicious Domain (Blacklisted)",
                    "severity": "critical",
                    "confidence": 1.0,
                    "url": target_url,
                    "parameter": "",
                    "owasp_category": "A01:2021-Broken Access Control",
                    "cwe_id": "CWE-937",
                    "description": f"Domain '{rep['hostname']}' matches known threat intelligence signature: {rep['service_name']}.",
                    "evidence": rep["description"],
                    "recommendation": "Block communication with this domain immediately using HorusShield Lockdown or Firewall.",
                    "ai_explanation": f"Threat intelligence identified domain '{rep['hostname']}' as an active attack target or malicious infrastructure.",
                    "dedup_hash": f"rep-bad-{rep['hostname']}",
                    "is_duplicate": False,
                    "correlation_group": f"rep-{rep['hostname']}",
                    "correlated_with_tools": ["threat_intel"],
                    "raw_data": rep,
                }
                raw_findings.append(bad_finding)
            else:
                # ── Reconnaissance: Nmap ──
                if "nmap" in tools and not self._stopped(scan_id):
                    if not self._revalidate(scan_id, target_url, "Nmap"):
                        return
                    self._progress(scan_id, "Reconnaissance — Fast service/port scan", 20)
                    result = self.nmap.scan(target_url)
                    if result.get("success"):
                        for port_info in result.get("ports", []):
                            raw_findings.append(VScannerCortex.from_nmap(host, port_info))
                    else:
                        logger.warning(f"[{scan_id}] Nmap unavailable/failed: {result.get('error')}")
                        self._emit("vscan_log", {"scan_id": scan_id, "message": f"ℹ️ Nmap: {result.get('error')}"})

                # ── Fast Native Web Security Audit (Headers, TLS, Ports) ──
                if getattr(self, "fast_scanner", None) and not self._stopped(scan_id):
                    self._progress(scan_id, "Security Audit — HTTP headers & TLS verification", 55)
                    try:
                        web_res = self.fast_scanner.scan(target_url)
                        if web_res and web_res.get("success"):
                            for f in web_res.get("findings", []):
                                raw_findings.append(f)
                    except Exception as e:
                        logger.debug(f"[{scan_id}] Fast web scanner error: {e}")

            # ── Crawling + passive analysis: ZAP ──
            zap_ok = False
            if "zap" in tools and not self._stopped(scan_id):
                if not self._revalidate(scan_id, target_url, "ZAP"):
                    return
                zap_status = self.zap.ensure_ready()
                if isinstance(zap_status, dict):
                    zap_ok = bool(zap_status.get("success"))
                    zap_error = zap_status.get("error", "ZAP is unavailable")
                else:  # compatibility with lightweight test doubles/custom clients
                    zap_ok = self.zap.is_available()
                    zap_error = "ZAP daemon not reachable"
                if zap_ok:
                    self._progress(scan_id, "Website crawling — ZAP spider", 30)
                    self.zap.new_session()
                    spider_res = self.zap.spider(target_url)
                    self._emit("vscan_log", {"scan_id": scan_id,
                                              "message": f"🕷️ ZAP spider found {spider_res.get('urls_found', 0)} URLs"})

                    self._progress(scan_id, "Endpoint & parameter discovery — ZAP passive scan", 45)
                    self.zap.passive_scan_wait()

                    if active_scan and not self._stopped(scan_id):
                        self._progress(scan_id, "AI scan planning — preparing active checks", 55)
                        self._emit("vscan_log", {"scan_id": scan_id,
                                                  "message": "🔍 Active scan opted-in — ZAP will send live test requests"})
                        self._progress(scan_id, "Security checks — ZAP active scan", 65)
                        self.zap.active_scan(target_url)
                    else:
                        self._progress(scan_id, "Security checks — passive analysis only (active scan not enabled)", 65)

                    alerts = self.zap.get_alerts(target_url)
                    for alert in alerts:
                        raw_findings.append(VScannerCortex.from_zap(alert))
                else:
                    logger.warning(f"[{scan_id}] ZAP unavailable: {zap_error}")
                    self._emit("vscan_log", {"scan_id": scan_id,
                                              "message": f"⚠️ OWASP ZAP: {zap_error}"})

            # ── Nikto web-server scan ──
            if "nikto" in tools and not self._stopped(scan_id):
                if not self._revalidate(scan_id, target_url, "Nikto"):
                    return
                self._progress(scan_id, "Security checks — Nikto web server scan", 78)
                nikto_res = self.nikto.scan(target_url)
                if nikto_res.get("success"):
                    for item in nikto_res.get("findings", []):
                        raw_findings.append(VScannerCortex.from_nikto(item))
                else:
                    logger.warning(f"[{scan_id}] Nikto unavailable/failed: {nikto_res.get('error')}")
                    self._emit("vscan_log", {"scan_id": scan_id, "message": f"⚠️ Nikto: {nikto_res.get('error')}"})

            if self._stopped(scan_id):
                return

            # ── AI Cortex: validation / dedup / confidence / prioritization ──
            self._progress(scan_id, "AI validation — deduplicating & scoring findings", 90)
            processed = VScannerCortex.process(raw_findings)

            for f in processed:
                db.add_vscan_finding(
                    scan_id=scan_id,
                    source_tool=f["source_tool"],
                    finding_type=f["finding_type"],
                    severity=f["severity"],
                    confidence=f["confidence"],
                    url=f.get("url", ""),
                    parameter=f.get("parameter", ""),
                    owasp_category=f.get("owasp_category", ""),
                    cwe_id=f.get("cwe_id", ""),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", ""),
                    recommendation=f.get("recommendation", ""),
                    ai_explanation=f.get("ai_explanation", ""),
                    dedup_hash=f.get("dedup_hash", ""),
                    is_duplicate=f.get("is_duplicate", False),
                    correlation_group=f.get("correlation_group") or "",
                    correlated_with_tools=f.get("correlated_with_tools", []),
                    raw_data=f.get("raw_data", {}),
                )

            summary = VScannerCortex.summarize(processed)
            domain_reputation.set_cached_result(target_url, summary, processed)
            db.update_vscan(
                scan_id,
                status="completed",
                stage="Completed",
                progress=100,
                findings_count=summary["total_findings"],
                finished_at=datetime.now().isoformat(),
            )
            self._emit("vscan_complete", {"scan_id": scan_id, "summary": summary})
            logger.info(f"[{scan_id}] Scan completed: {summary}")
            db.add_audit_log(
                action="scan_finished", status="success",
                details=f"scan_id={scan_id} target={target_url} findings={summary['total_findings']}",
            )

        except Exception as e:
            logger.error(f"[{scan_id}] Scan failed: {e}")
            db.update_vscan(scan_id, status="failed", error=str(e)[:500], finished_at=datetime.now().isoformat())
            self._emit("vscan_failed", {"scan_id": scan_id, "error": str(e)[:500]})
            db.add_audit_log(
                action="scan_finished", status="failure",
                details=f"scan_id={scan_id} target={target_url} error={str(e)[:300]}",
            )
        finally:
            close_zap = getattr(self.zap, "close", None)
            if close_zap:
                close_zap()
            with self._lock:
                self._stop_flags.pop(scan_id, None)
