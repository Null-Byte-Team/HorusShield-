"""Tests for report generation — the main daily report and V-8 Scanner reports."""

import os
import time
import pytest


def test_report_generator_produces_a_pdf(tmp_path, monkeypatch):
    from services.report_generator import ReportGenerator

    gen = ReportGenerator()
    # Redirect output into pytest's tmp dir so we never touch the real
    # backend/reports folder.
    monkeypatch.setattr(gen, "output_dir", str(tmp_path), raising=False)
    path = gen.generate_daily_report(facility_name="Pytest Facility", language="en")
    assert path is not None
    assert os.path.exists(path)
    assert path.endswith(".pdf")
    assert os.path.getsize(path) > 0


def test_vscan_report_generator_all_formats(db):
    from services.vscan_report_generator import VScanReportGenerator

    scan_id = f"pytest-report-{int(time.time() * 1000)}"
    db.add_vscan(scan_id, "http://example.com", ["nmap"], active_scan=False, owner_id=1)
    db.update_vscan(scan_id, status="completed", progress=100, findings_count=2)

    # Finding 1 with basic info
    db.add_vscan_finding(
        scan_id=scan_id,
        source_tool="nmap",
        finding_type="Open Port",
        severity="low",
        confidence=0.7,
        url="example.com:80",
        owasp_category="A05:2021 - Security Misconfiguration",
        cwe_id="CWE-1327",
    )

    # Finding 2 with both ai_explanation and recommendation (tests multi_cell cursor fix)
    db.add_vscan_finding(
        scan_id=scan_id,
        source_tool="zap",
        finding_type="Reflected Cross-Site Scripting",
        severity="critical",
        confidence=0.95,
        url="http://example.com/search?q=test",
        parameter="q",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        description="User input is reflected without sanitization.",
        evidence="<script>alert(1)</script>",
        ai_explanation="An attacker could execute arbitrary scripts in the victim context.",
        recommendation="Implement HTML output encoding and CSP headers.",
    )

    gen = VScanReportGenerator()
    for fmt in ("pdf", "html", "json"):
        path = gen.generate(scan_id, fmt)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0
        if fmt == "pdf":
            with open(path, "rb") as fp:
                assert fp.read(4).startswith(b"%PDF")

    reports = db.get_vscan_reports(scan_id)
    assert len(reports) == 3

    db.delete_vscan(scan_id)


def test_vscan_report_generator_zero_findings(db):
    """Ensure report generator succeeds when a scan reports 0 findings."""
    from services.vscan_report_generator import VScanReportGenerator

    scan_id = f"pytest-zero-{int(time.time() * 1000)}"
    db.add_vscan(scan_id, "https://secure-site.local", ["nmap"], active_scan=False, owner_id=1)
    db.update_vscan(scan_id, status="completed", progress=100, findings_count=0)

    gen = VScanReportGenerator()
    pdf_path = gen.generate(scan_id, "pdf")
    assert os.path.exists(pdf_path)
    with open(pdf_path, "rb") as fp:
        assert fp.read(4).startswith(b"%PDF")

    db.delete_vscan(scan_id)


def test_api_vscanner_pdf_report_endpoint(client, auth_headers, db):
    """Test GET /api/vscanner/scan/<scan_id>/report/pdf returns 200 and application/pdf."""
    scan_id = f"pytest-api-report-{int(time.time() * 1000)}"
    db.add_vscan(scan_id, "http://api-target.org", ["nmap"], active_scan=False, owner_id=1)
    db.update_vscan(scan_id, status="completed", progress=100, findings_count=1)
    db.add_vscan_finding(
        scan_id=scan_id,
        source_tool="nmap",
        finding_type="Open Port 443",
        severity="info",
        confidence=1.0,
        url="https://api-target.org:443",
        description="HTTPS port open",
        ai_explanation="HTTPS service is active.",
        recommendation="Maintain valid TLS certificates.",
    )

    resp = client.get(f"/api/vscanner/scan/{scan_id}/report/pdf", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.content_type == "application/pdf"
    assert resp.data.startswith(b"%PDF")

    # Test query param format ?token=<token>
    # Get token from auth_headers
    token = auth_headers.get("Authorization", "").replace("Bearer ", "").strip()
    resp_token = client.get(f"/api/vscanner/scan/{scan_id}/report/pdf?token={token}")
    assert resp_token.status_code == 200
    assert resp_token.content_type == "application/pdf"
    assert resp_token.data.startswith(b"%PDF")

    # Test invalid format
    resp_invalid_fmt = client.get(f"/api/vscanner/scan/{scan_id}/report/docx", headers=auth_headers)
    assert resp_invalid_fmt.status_code == 400

    # Test non-existent scan
    resp_404 = client.get("/api/vscanner/scan/nonexistent-scan-id/report/pdf", headers=auth_headers)
    assert resp_404.status_code == 404

    # Test unauthenticated request
    resp_unauth = client.get(f"/api/vscanner/scan/{scan_id}/report/pdf")
    assert resp_unauth.status_code == 401

    db.delete_vscan(scan_id)
