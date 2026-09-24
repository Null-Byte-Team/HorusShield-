import queue
import time
from unittest.mock import MagicMock, patch, ANY
import pytest

from vscanner.domain_reputation import DomainReputationManager, domain_reputation
from vscanner.nmap_runner import NmapRunner
from vscanner.orchestrator import VScannerManager
from engine.network_monitor import NetworkMonitor
from engine.packet_analyzer import PacketAnalyzer


# ── Domain Reputation & Whitelist Tests ──────────────────────────────────────

def test_domain_reputation_whitelist_youtube():
    rep = domain_reputation.check_reputation("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
    assert rep["status"] == "whitelisted"
    assert rep["is_safe"] is True
    assert "YouTube" in rep["service_name"]


def test_domain_reputation_whitelist_google_and_github():
    rep_google = domain_reputation.check_reputation("google.com")
    assert rep_google["status"] == "whitelisted"
    assert rep_google["is_safe"] is True

    rep_github = domain_reputation.check_reputation("https://raw.githubusercontent.com/user/repo")
    assert rep_github["status"] == "whitelisted"
    assert rep_github["is_safe"] is True


def test_domain_reputation_unknown_domain():
    rep = domain_reputation.check_reputation("http://my-custom-internal-site.local")
    assert rep["status"] == "unknown"
    assert rep["is_safe"] is False


def test_domain_reputation_blacklist():
    rep = domain_reputation.check_reputation("http://malware-traffic-analysis.net/sample")
    assert rep["status"] == "blacklisted"
    assert rep["is_safe"] is False


def test_domain_reputation_caching():
    mgr = DomainReputationManager(cache_ttl_seconds=2)
    mgr.clear_cache()
    
    assert mgr.get_cached_result("https://testdomain.com") is None
    
    summary = {"total_findings": 3, "by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0}}
    findings = [{"finding_type": "Open Port", "severity": "low"}]
    
    mgr.set_cached_result("https://testdomain.com", summary, findings)
    
    cached = mgr.get_cached_result("https://testdomain.com")
    assert cached is not None
    assert cached["summary"]["total_findings"] == 3
    assert len(cached["findings"]) == 1
    
    # Wait for expiration
    time.sleep(2.1)
    assert mgr.get_cached_result("https://testdomain.com") is None


# ── Fast Native Web Scanner Tests ─────────────────────────────────────────────

def test_fast_web_scanner_execution():
    from vscanner.fast_web_scanner import FastWebScanner
    scanner = FastWebScanner(timeout=1.0)
    with patch.object(scanner, "_probe_ports", return_value=[{"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "", "version": "", "scripts": []}]), \
         patch.object(scanner, "_audit_http_headers", return_value=([], {"Server": "cloudflare"})), \
         patch.object(scanner, "_audit_tls", return_value=([], {"protocol": "TLSv1.3", "cipher": "AES-256"})):
        
        result = scanner.scan("https://example.com")
        assert result["success"] is True
        assert len(result["open_ports"]) == 1
        assert result["open_ports"][0]["port"] == 443
        assert any("Open Port 443" in f["finding_type"] for f in result["findings"])


# ── Nmap Runner Command Optimization Tests ────────────────────────────────────

def test_nmap_runner_uses_fast_flags():
    runner = NmapRunner(nmap_path="nmap")
    with patch("vscanner.nmap_runner.resolve_nmap", return_value="C:\\Program Files\\Nmap\\nmap.exe"), \
         patch("vscanner.nmap_runner.subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "<nmaprun></nmaprun>"
        mock_run.return_value = mock_proc
        
        result = runner.scan("example.com")
        assert result["success"] is True
        
        cmd_args = mock_run.call_args[0][0]
        assert "-sT" in cmd_args
        assert "-Pn" in cmd_args
        assert "-n" in cmd_args
        assert "--open" in cmd_args
        assert "-T4" in cmd_args
        assert "--top-ports" in cmd_args
        assert "50" in cmd_args
        assert "--max-retries" in cmd_args
        assert "0" in cmd_args
        assert any("--host-timeout" in arg for arg in cmd_args)


# ── Live Traffic Non-Blocking Queue Tests ─────────────────────────────────────

def test_network_monitor_non_blocking_queue():
    monitor = NetworkMonitor()
    assert isinstance(monitor._packet_queue, queue.Queue)
    assert monitor._packet_queue.maxsize >= 10000
    
    # Test batch ingestion
    analyzer = PacketAnalyzer()
    analyzer.analyze_packet_batch([])  # should handle empty cleanly


# ── Orchestrator Whitelist & Fast Path Tests ──────────────────────────────────

def test_orchestrator_youtube_whitelist_instant_approval():
    mgr = VScannerManager(socketio=MagicMock())
    mgr.fast_scanner = MagicMock()
    mgr.fast_scanner.scan.return_value = {"success": True, "findings": []}
    mgr._stop_flags["scan-yt"] = False
    
    with patch("vscanner.orchestrator.db") as mock_db, \
         patch.object(mgr, "_revalidate", return_value=True):
        
        mgr._run("scan-yt", "https://www.youtube.com", ["nmap"], False)
        
        # Verify finding recorded as Verified Safe Domain
        assert mock_db.add_vscan_finding.called
        finding_kwargs = mock_db.add_vscan_finding.call_args.kwargs
        assert finding_kwargs["source_tool"] == "reputation"
        assert "Verified Safe Domain" in finding_kwargs["finding_type"]
        assert finding_kwargs["severity"] == "info"
        
        mock_db.update_vscan.assert_any_call(
            "scan-yt", status="completed", stage="Completed", progress=100,
            findings_count=1, finished_at=ANY
        )
