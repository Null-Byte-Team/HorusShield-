"""V-8 Scanner orchestrator tests — comprehensive mock-based coverage.

Covers all 21 required scenarios without needing real Nmap, Nikto, or ZAP
installations. Uses unittest.mock to replace the tool runners, the
database layer, and the SSRF validation so every test is deterministic,
fast, and independent.

We call VScannerManager._run() directly (synchronously) rather than
start_scan() (which spawns a background thread) — this makes assertions
reliable without sleep/event coordination, and exercises 100% of the
scan-execution logic that _run() contains.
"""
import threading
from unittest.mock import MagicMock, patch, ANY

import pytest

from vscanner.orchestrator import VScannerManager
from ai.vscanner_cortex import VScannerCortex
from security.ssrf import SSRFValidationError


# ─────────────────────────────────────────────────────────────────────
# Helpers / sample data
# ─────────────────────────────────────────────────────────────────────

SAMPLE_TARGET = "http://example.com"
SCAN_ID = "test-scan-001"

NMAP_OK = {
    "success": True, "host": "example.com", "ports": [
        {"port": 80, "protocol": "tcp", "state": "open",
         "service": "http", "product": "nginx", "version": "1.18", "scripts": []},
        {"port": 443, "protocol": "tcp", "state": "open",
         "service": "https", "product": "nginx", "version": "1.18", "scripts": []},
    ], "error": "",
}

NMAP_FAIL = {"success": False, "host": "example.com", "ports": [], "error": "nmap binary not found on PATH"}
NMAP_TIMEOUT = {"success": False, "host": "example.com", "ports": [], "error": "Nmap scan timed out"}
NMAP_EMPTY = {"success": True, "host": "example.com", "ports": [], "error": ""}

ZAP_ALERTS = [
    {"name": "Cross Site Scripting", "risk": "3", "confidence": "2",
     "url": "http://example.com/search", "param": "q",
     "description": "XSS found", "evidence": "<script>", "solution": "Encode output"},
]

NIKTO_OK = {
    "success": True, "findings": [
        {"id": "1", "method": "GET", "url": "http://example.com/robots.txt",
         "message": "robots.txt contains interesting entries"},
    ], "error": "",
}
NIKTO_FAIL = {"success": False, "findings": [], "error": "nikto binary not found on PATH"}
NIKTO_TIMEOUT = {"success": False, "findings": [], "error": "Nikto scan timed out"}


@pytest.fixture(autouse=True)
def clean_cache():
    from vscanner.domain_reputation import domain_reputation
    domain_reputation.clear_cache()
    yield
    domain_reputation.clear_cache()


@pytest.fixture
def mgr():
    m = VScannerManager(socketio=MagicMock())
    m.fast_scanner = MagicMock()
    m.fast_scanner.scan.return_value = {"success": True, "findings": []}
    return m


@pytest.fixture
def mock_db():
    with patch("vscanner.orchestrator.db") as db_mock:
        db_mock.add_vscan = MagicMock()
        db_mock.update_vscan = MagicMock()
        db_mock.add_vscan_finding = MagicMock()
        db_mock.add_audit_log = MagicMock()
        yield db_mock


def _setup_scan_state(mgr, scan_id=SCAN_ID):
    mgr._active_scan_id = scan_id
    mgr._stop_flags[scan_id] = False


# ─────────────────────────────────────────────────────────────────────
# 1. Nmap success with port findings
# ─────────────────────────────────────────────────────────────────────

def test_nmap_success(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_OK
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap"], False)

    mgr.nmap.scan.assert_called_once_with(SAMPLE_TARGET)
    assert mock_db.add_vscan_finding.call_count == 2
    mock_db.update_vscan.assert_any_call(
        SCAN_ID, status="completed", stage="Completed", progress=100,
        findings_count=2, finished_at=ANY
    )


# ─────────────────────────────────────────────────────────────────────
# 2. Nmap returns error/failure
# ─────────────────────────────────────────────────────────────────────

def test_nmap_failure(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_FAIL
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap"], False)

    mock_db.update_vscan.assert_any_call(
        SCAN_ID, status="completed", stage="Completed", progress=100,
        findings_count=0, finished_at=ANY
    )


# ─────────────────────────────────────────────────────────────────────
# 3. Nmap times out
# ─────────────────────────────────────────────────────────────────────

def test_nmap_timeout(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_TIMEOUT
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap"], False)

    assert any(c.kwargs.get("status") == "completed" for c in mock_db.update_vscan.call_args_list)


# ─────────────────────────────────────────────────────────────────────
# 4. Nmap produces malformed/empty output
# ─────────────────────────────────────────────────────────────────────

def test_nmap_empty_output(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_EMPTY
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap"], False)

    assert mock_db.add_vscan_finding.call_count == 0


# ─────────────────────────────────────────────────────────────────────
# 5. ZAP success with spider + passive + alerts
# ─────────────────────────────────────────────────────────────────────

def test_zap_success(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.zap.is_available.return_value = True
    mgr.zap.new_session.return_value = True
    mgr.zap.spider.return_value = {"success": True, "urls_found": 5, "urls": [], "error": ""}
    mgr.zap.passive_scan_wait.return_value = {"success": True, "records_remaining": 0}
    mgr.zap.get_alerts.return_value = ZAP_ALERTS
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["zap"], False)

    mgr.zap.spider.assert_called_once_with(SAMPLE_TARGET)
    mgr.zap.passive_scan_wait.assert_called_once()
    mgr.zap.get_alerts.assert_called_once_with(SAMPLE_TARGET)
    assert mock_db.add_vscan_finding.call_count >= 1


# ─────────────────────────────────────────────────────────────────────
# 6. ZAP is not available
# ─────────────────────────────────────────────────────────────────────

def test_zap_not_available(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.zap.is_available.return_value = False
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["zap"], False)

    mgr.zap.spider.assert_not_called()
    mgr.zap.get_alerts.assert_not_called()


# ─────────────────────────────────────────────────────────────────────
# 7. ZAP active scan (active_scan=True)
# ─────────────────────────────────────────────────────────────────────

def test_zap_active_scan(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.zap.is_available.return_value = True
    mgr.zap.new_session.return_value = True
    mgr.zap.spider.return_value = {"success": True, "urls_found": 3, "urls": [], "error": ""}
    mgr.zap.passive_scan_wait.return_value = {"success": True, "records_remaining": 0}
    mgr.zap.active_scan.return_value = {"success": True, "progress": 100}
    mgr.zap.get_alerts.return_value = ZAP_ALERTS
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["zap"], True)

    mgr.zap.active_scan.assert_called_once_with(SAMPLE_TARGET)


# ─────────────────────────────────────────────────────────────────────
# 8. Nikto success with findings
# ─────────────────────────────────────────────────────────────────────

def test_nikto_success(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()
    mgr.nikto.scan.return_value = NIKTO_OK

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nikto"], False)

    mgr.nikto.scan.assert_called_once_with(SAMPLE_TARGET)
    assert mock_db.add_vscan_finding.call_count >= 1


# ─────────────────────────────────────────────────────────────────────
# 9. Nikto returns error/failure
# ─────────────────────────────────────────────────────────────────────

def test_nikto_failure(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()
    mgr.nikto.scan.return_value = NIKTO_FAIL

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nikto"], False)

    assert any(c.kwargs.get("status") == "completed" for c in mock_db.update_vscan.call_args_list)


# ─────────────────────────────────────────────────────────────────────
# 10. Nikto times out
# ─────────────────────────────────────────────────────────────────────

def test_nikto_timeout(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()
    mgr.nikto.scan.return_value = NIKTO_TIMEOUT

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nikto"], False)

    assert any(c.kwargs.get("status") == "completed" for c in mock_db.update_vscan.call_args_list)


# ─────────────────────────────────────────────────────────────────────
# 11. All three tools succeed together
# ─────────────────────────────────────────────────────────────────────

def test_all_tools_succeed(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_OK
    mgr.zap = MagicMock()
    mgr.zap.is_available.return_value = True
    mgr.zap.new_session.return_value = True
    mgr.zap.spider.return_value = {"success": True, "urls_found": 5, "urls": [], "error": ""}
    mgr.zap.passive_scan_wait.return_value = {"success": True, "records_remaining": 0}
    mgr.zap.get_alerts.return_value = ZAP_ALERTS
    mgr.nikto = MagicMock()
    mgr.nikto.scan.return_value = NIKTO_OK

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap", "zap", "nikto"], False)

    mgr.nmap.scan.assert_called_once()
    mgr.zap.spider.assert_called_once()
    mgr.nikto.scan.assert_called_once()
    assert mock_db.add_vscan_finding.call_count >= 3


# ─────────────────────────────────────────────────────────────────────
# 12. Partial failure: Nmap fails, ZAP+Nikto succeed
# ─────────────────────────────────────────────────────────────────────

def test_partial_failure_nmap_fails(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_FAIL
    mgr.zap = MagicMock()
    mgr.zap.is_available.return_value = True
    mgr.zap.new_session.return_value = True
    mgr.zap.spider.return_value = {"success": True, "urls_found": 2, "urls": [], "error": ""}
    mgr.zap.passive_scan_wait.return_value = {"success": True, "records_remaining": 0}
    mgr.zap.get_alerts.return_value = ZAP_ALERTS
    mgr.nikto = MagicMock()
    mgr.nikto.scan.return_value = NIKTO_OK

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap", "zap", "nikto"], False)

    assert any(c.kwargs.get("status") == "completed" for c in mock_db.update_vscan.call_args_list)
    assert mock_db.add_vscan_finding.call_count >= 1


# ─────────────────────────────────────────────────────────────────────
# 13. Scan cancellation via stop_scan
# ─────────────────────────────────────────────────────────────────────

def test_scan_cancellation(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr._stop_flags[SCAN_ID] = True
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap", "zap", "nikto"], False)

    mgr.nmap.scan.assert_not_called()
    mgr.zap.spider.assert_not_called()
    mgr.nikto.scan.assert_not_called()


# ─────────────────────────────────────────────────────────────────────
# 14. Concurrent scans use independent stop flags
# ─────────────────────────────────────────────────────────────────────

def test_concurrent_scans_are_independent(mgr, mock_db):
    with patch("vscanner.orchestrator.threading.Thread") as thread:
        thread.return_value.start.return_value = None
        first = mgr.start_scan(SAMPLE_TARGET, tools=["nmap"])
        second = mgr.start_scan(SAMPLE_TARGET, tools=["nmap"])

    assert first["success"] is True
    assert second["success"] is True
    assert first["scan_id"] != second["scan_id"]
    assert mgr._stop_flags[first["scan_id"]] is False
    assert mgr._stop_flags[second["scan_id"]] is False


# ─────────────────────────────────────────────────────────────────────
# 15. SSRF re-validation failure before Nmap
# ─────────────────────────────────────────────────────────────────────

def test_ssrf_revalidation_failure_before_nmap(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=False):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap", "zap", "nikto"], False)

    mgr.nmap.scan.assert_not_called()
    mgr.zap.spider.assert_not_called()
    mgr.nikto.scan.assert_not_called()


# ─────────────────────────────────────────────────────────────────────
# 16. SSRF re-validation failure before ZAP
# ─────────────────────────────────────────────────────────────────────

def test_ssrf_revalidation_failure_before_zap(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_OK
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", side_effect=[True, False]):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap", "zap", "nikto"], False)

    mgr.nmap.scan.assert_called_once()
    mgr.zap.spider.assert_not_called()
    mgr.nikto.scan.assert_not_called()


# ─────────────────────────────────────────────────────────────────────
# 17. SSRF re-validation failure before Nikto
# ─────────────────────────────────────────────────────────────────────

def test_ssrf_revalidation_failure_before_nikto(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_OK
    mgr.zap = MagicMock()
    mgr.zap.is_available.return_value = True
    mgr.zap.new_session.return_value = True
    mgr.zap.spider.return_value = {"success": True, "urls_found": 1, "urls": [], "error": ""}
    mgr.zap.passive_scan_wait.return_value = {"success": True, "records_remaining": 0}
    mgr.zap.get_alerts.return_value = []
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", side_effect=[True, True, False]):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap", "zap", "nikto"], False)

    mgr.nmap.scan.assert_called_once()
    mgr.zap.spider.assert_called_once()
    mgr.nikto.scan.assert_not_called()


# ─────────────────────────────────────────────────────────────────────
# 18. Cortex processes and deduplicates findings correctly
# ─────────────────────────────────────────────────────────────────────

def test_cortex_deduplication():
    f1 = VScannerCortex.from_nmap("example.com", {
        "port": 80, "protocol": "tcp", "state": "open",
        "service": "http", "product": "nginx", "version": "1.18", "scripts": [],
    })
    f2 = VScannerCortex.from_nmap("example.com", {
        "port": 80, "protocol": "tcp", "state": "open",
        "service": "http", "product": "nginx", "version": "1.18", "scripts": [],
    })
    processed = VScannerCortex.process([f1, f2])
    active = [f for f in processed if not f.get("is_duplicate")]
    duplicates = [f for f in processed if f.get("is_duplicate")]
    assert len(active) == 1
    assert len(duplicates) == 1


# ─────────────────────────────────────────────────────────────────────
# 19. Findings get persisted to database
# ─────────────────────────────────────────────────────────────────────

def test_findings_persisted_to_db(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_OK
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap"], False)

    assert mock_db.add_vscan_finding.call_count == 2
    for c in mock_db.add_vscan_finding.call_args_list:
        assert c.kwargs["scan_id"] == SCAN_ID
        assert c.kwargs["source_tool"] == "nmap"
        assert "severity" in c.kwargs
        assert "confidence" in c.kwargs


# ─────────────────────────────────────────────────────────────────────
# 20. Scan cleanup removes the scan's stop flag
# ─────────────────────────────────────────────────────────────────────

def test_scan_cleanup(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.return_value = "example.com"
    mgr.nmap.scan.return_value = NMAP_OK
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap"], False)

    assert SCAN_ID not in mgr._stop_flags


# ─────────────────────────────────────────────────────────────────────
# 21. Exception during scan execution marks scan as failed
# ─────────────────────────────────────────────────────────────────────

def test_exception_marks_scan_failed(mgr, mock_db):
    _setup_scan_state(mgr)
    mgr.nmap = MagicMock()
    mgr.nmap._host_from_url.side_effect = RuntimeError("Unexpected crash")
    mgr.zap = MagicMock()
    mgr.nikto = MagicMock()

    with patch.object(mgr, "_revalidate", return_value=True):
        mgr._run(SCAN_ID, SAMPLE_TARGET, ["nmap"], False)

    failed_calls = [c for c in mock_db.update_vscan.call_args_list
                    if c.kwargs.get("status") == "failed"]
    assert len(failed_calls) >= 1
    assert "Unexpected crash" in failed_calls[0].kwargs.get("error", "")
    assert SCAN_ID not in mgr._stop_flags


# ─────────────────────────────────────────────────────────────────────
# Additional edge-case & direct _revalidate unit tests
# ─────────────────────────────────────────────────────────────────────

def test_revalidate_real_method_success(mgr, mock_db):
    """Direct test of _revalidate helper when target passes."""
    with patch("security.ssrf.validate_target", return_value={"url": "http://example.com"}):
        ok = mgr._revalidate(SCAN_ID, "http://example.com", "Nmap")
        assert ok is True


def test_revalidate_real_method_failure(mgr, mock_db):
    """Direct test of _revalidate helper when target triggers SSRFValidationError."""
    with patch("security.ssrf.validate_target", side_effect=SSRFValidationError("SSRF blocked")):
        ok = mgr._revalidate(SCAN_ID, "http://127.0.0.1", "Nmap")
        assert ok is False
        mock_db.update_vscan.assert_called_with(
            SCAN_ID,
            status="failed",
            error="SSRF protection (Nmap): SSRF blocked",
            finished_at=ANY,
        )
        mock_db.add_audit_log.assert_called_with(
            action="scan_finished",
            status="failure",
            details="scan_id=test-scan-001 target=http://127.0.0.1 error=SSRF re-validation failed before Nmap: SSRF blocked",
        )


def test_stop_scan_unknown_id(mgr):
    result = mgr.stop_scan("nonexistent-id")
    assert result["success"] is False


def test_stop_scan_sets_flag(mgr, mock_db):
    mgr._stop_flags["scan-X"] = False
    result = mgr.stop_scan("scan-X")
    assert result["success"] is True
    assert mgr._stop_flags["scan-X"] is True


def test_cortex_severity_and_confidence():
    alert = {"name": "SQL Injection", "risk": "3", "confidence": "3",
             "url": "http://example.com/login", "param": "user",
             "description": "SQL injection detected", "evidence": "' OR 1=1",
             "solution": "Use parameterized queries"}
    finding = VScannerCortex.from_zap(alert)
    assert finding["severity"] == "critical"
    assert finding["confidence"] == 0.9
    assert finding["source_tool"] == "zap"

    processed = VScannerCortex.process([finding])
    assert processed[0]["owasp_category"] == "A03:2021 - Injection"
    assert processed[0]["cwe_id"] == "CWE-89"


def test_cortex_correlation():
    f1 = VScannerCortex.from_nmap("example.com", {
        "port": 80, "protocol": "tcp", "state": "open",
        "service": "http", "product": "nginx", "version": "1.18", "scripts": [],
    })
    f2 = VScannerCortex.from_zap({
        "name": "Missing Header", "risk": "1", "confidence": "2",
        "url": "http://example.com/", "param": "",
        "description": "Missing X-Frame-Options", "evidence": "", "solution": "Add header",
    })
    processed = VScannerCortex.process([f1, f2])
    active = [f for f in processed if not f.get("is_duplicate")]
    groups = [f.get("correlation_group") for f in active if f.get("correlation_group")]
    assert len(groups) >= 1


def test_cortex_summarize():
    findings = [
        {"severity": "critical", "confidence": 0.9, "is_duplicate": False},
        {"severity": "high", "confidence": 0.8, "is_duplicate": False},
        {"severity": "high", "confidence": 0.7, "is_duplicate": True},
        {"severity": "low", "confidence": 0.5, "is_duplicate": False},
    ]
    summary = VScannerCortex.summarize(findings)
    assert summary["total_findings"] == 3
    assert summary["duplicates_removed"] == 1
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["low"] == 1
