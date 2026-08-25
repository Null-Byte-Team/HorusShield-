"""Tests for backend/database — schema init, CRUD, audit log, shutdown."""

import time


def test_database_file_created():
    import os

    from database.models import DB_PATH

    assert os.path.exists(DB_PATH)


def test_add_and_get_device(db):
    db.add_device(
        mac_address="AA:BB:CC:DD:EE:01",
        ip_address="192.168.1.50",
        hostname="test-device",
        vendor="TestVendor",
    )
    devices = db.get_all_devices()
    assert any(d["mac_address"] == "AA:BB:CC:DD:EE:01" for d in devices)


def test_audit_log_round_trip(db):
    before = len(db.get_audit_log(limit=500))
    db.add_audit_log(
        action="login",
        username="tester@example.com",
        status="success",
        ip_address="127.0.0.1",
        details="pytest",
    )
    after = db.get_audit_log(limit=500)
    assert len(after) == before + 1
    assert after[0]["action"] == "login"
    assert after[0]["username"] == "tester@example.com"


def test_audit_log_filters_by_action(db):
    db.add_audit_log(action="scan_started", details="pytest scan A")
    db.add_audit_log(action="scan_finished", details="pytest scan A done")
    only_started = db.get_audit_log(limit=500, action="scan_started")
    assert all(r["action"] == "scan_started" for r in only_started)
    assert len(only_started) >= 1


def test_vscan_crud_and_cascade_delete(db):
    scan_id = f"pytest-{int(time.time() * 1000)}"
    db.add_vscan(scan_id, "http://example.com", ["nmap"], active_scan=False, requested_by="pytest")
    db.update_vscan(scan_id, status="completed", progress=100, findings_count=1)

    scan = db.get_vscan(scan_id)
    assert scan is not None
    assert scan["status"] == "completed"
    assert scan["tools_used"] == ["nmap"]

    db.add_vscan_finding(
        scan_id=scan_id,
        source_tool="nmap",
        finding_type="Open Port",
        severity="low",
        confidence=0.8,
        url="example.com:22",
    )
    findings = db.get_vscan_findings(scan_id)
    assert len(findings) == 1
    assert findings[0]["source_tool"] == "nmap"

    deleted = db.delete_vscan(scan_id)
    assert deleted is True
    assert db.get_vscan(scan_id) is None
    assert db.get_vscan_findings(scan_id) == []


def test_close_all_connections_does_not_raise(db):
    # Should be safe to call even mid-test-session; a later query must
    # transparently open a fresh connection on the same thread.
    db.close_all_connections()
    db.add_audit_log(action="login", details="post-close smoke test")
    assert len(db.get_audit_log(limit=1)) == 1


def test_vscan_finding_correlation_fields_round_trip(db):
    scan_id = f"pytest-corr-{int(time.time() * 1000)}"
    db.add_vscan(scan_id, "http://example.com", ["nmap", "zap"], active_scan=False)
    db.add_vscan_finding(
        scan_id=scan_id,
        source_tool="nmap",
        finding_type="Open Port",
        severity="low",
        confidence=0.8,
        url="example.com:80",
        correlation_group="example.com",
        correlated_with_tools=["zap", "nikto"],
    )
    findings = db.get_vscan_findings(scan_id)
    assert findings[0]["correlation_group"] == "example.com"
    assert findings[0]["correlated_with_tools"] == ["zap", "nikto"]
    db.delete_vscan(scan_id)
