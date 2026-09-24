"""Deterministic tests for external scanner discovery and Windows invocation."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from vscanner.nikto_runner import NiktoRunner
from vscanner.nmap_runner import NmapRunner
from vscanner.tool_discovery import resolve_nikto, resolve_nmap, resolve_perl, resolve_zap
from vscanner.zap_client import ZAPClient


def test_tools_are_found_through_path():
    with patch("vscanner.tool_discovery.shutil.which", side_effect=lambda name: {
        "nmap": r"C:\Nmap\nmap.exe",
        "perl": r"C:\Strawberry\perl.exe",
        "nikto.pl": r"C:\Nikto\nikto.pl",
        "zap.bat": r"C:\ZAP\zap.bat",
    }.get(name)):
        assert resolve_nmap("") == r"C:\Nmap\nmap.exe"
        assert resolve_perl("") == r"C:\Strawberry\perl.exe"
        assert resolve_nikto("") == r"C:\Nikto\nikto.pl"
        assert resolve_zap("") == r"C:\ZAP\zap.bat"


def test_explicit_paths_and_missing_tools(tmp_path):
    nmap = tmp_path / "nmap.exe"
    nikto = tmp_path / "nikto.pl"
    perl = tmp_path / "perl.exe"
    zap = tmp_path / "zap.bat"
    for path in (nmap, nikto, perl, zap):
        path.write_text("tool")
    assert resolve_nmap(str(nmap)) == str(nmap)
    assert resolve_nikto(str(nikto)) == str(nikto)
    assert resolve_perl(str(perl)) == str(perl)
    assert resolve_zap(str(zap)) == str(zap)
    assert resolve_nmap(str(tmp_path / "missing.exe")) is None


def test_windows_default_program_files_locations_are_resolved(monkeypatch):
    installed = {
        r"C:\Program Files\Nikto\program\nikto.pl": True,
        r"C:\Program Files\Strawberry\perl\bin\perl.exe": True,
        r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat": True,
    }
    monkeypatch.setattr("vscanner.tool_discovery.os.path.isfile", lambda p: installed.get(p, False))
    monkeypatch.setattr("vscanner.tool_discovery.shutil.which", lambda name: None)

    assert resolve_nikto("") == r"C:\Program Files\Nikto\program\nikto.pl"
    assert resolve_perl("") == r"C:\Program Files\Strawberry\perl\bin\perl.exe"
    assert resolve_zap("") == r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"


def test_nikto_uses_perl_absolute_script_and_script_directory(tmp_path):
    script = tmp_path / "nikto.pl"
    perl = tmp_path / "perl.exe"
    script.write_text("#!perl")
    perl.write_text("runtime")
    output = tmp_path / "report.json"
    fake_process = MagicMock(returncode=0, stderr="", stdout="")
    with patch("vscanner.nikto_runner.resolve_nikto", return_value=str(script)), \
         patch("vscanner.nikto_runner.resolve_perl", return_value=str(perl)), \
         patch("vscanner.nikto_runner.tempfile.NamedTemporaryFile") as temp_file, \
         patch("vscanner.nikto_runner.subprocess.run", return_value=fake_process) as run:
        temp_file.return_value.__enter__.return_value.name = str(output)
        output.write_text(json.dumps({"vulnerabilities": []}))
        result = NiktoRunner(nikto_path=str(script)).scan("http://example.com")
    assert result["success"] is True
    command = run.call_args.args[0]
    assert command[:2] == [str(perl), str(script)]
    assert run.call_args.kwargs["cwd"] == str(tmp_path)
    assert run.call_args.kwargs["shell"] is False


def test_nmap_reports_missing_executable():
    runner = NmapRunner(nmap_path=r"C:\missing\nmap.exe")
    with patch("vscanner.nmap_runner.resolve_nmap", return_value=None):
        result = runner.scan("http://example.com")
    assert result["success"] is False
    assert "not found" in result["error"]


def test_zap_spider_timeout_is_not_success():
    client = ZAPClient()
    client.poll_interval = 0
    client._get = MagicMock(side_effect=[{"scan": "1"}, {"status": "0"}])
    result = client.spider("http://example.com", max_wait=0)
    assert result["success"] is False
    assert result["state"] == "timeout"


def test_zap_passive_timeout_is_not_success():
    client = ZAPClient()
    client.poll_interval = 0
    client._get = MagicMock(return_value={"recordsToScan": "2"})
    result = client.passive_scan_wait(max_wait=0)
    assert result["success"] is False
    assert "timed out" in result["error"]
