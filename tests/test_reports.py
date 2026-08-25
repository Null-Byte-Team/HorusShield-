"""Tests for report generation — the main daily report and V-8 Scanner reports."""

import os


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
    import time

    from services.vscan_report_generator import VScanReportGenerator

    scan_id = f"pytest-report-{int(time.time() * 1000)}"
    db.add_vscan(scan_id, "http://example.com", ["nmap"], active_scan=False)
    db.update_vscan(scan_id, status="completed", progress=100, findings_count=1)
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

    gen = VScanReportGenerator()
    for fmt in ("pdf", "html", "json"):
        path = gen.generate(scan_id, fmt)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    reports = db.get_vscan_reports(scan_id)
    assert len(reports) == 3

    db.delete_vscan(scan_id)  # also cleans up the report file rows
