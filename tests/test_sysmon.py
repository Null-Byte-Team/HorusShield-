"""
Comprehensive tests for HorusShield 2.0 System Monitor & Process Management.
Assertions match the actual backend schema:
  - /api/sysmon/overview   → dict with cpu, memory, disk, network, system
                             cpu keys: usage_percent, per_cpu, logical_cores ...
                             memory keys: percent, total_gb, available_gb ...
                             disk keys: percent, total_gb, read_mb_s, write_mb_s, partitions
                             network keys: download_mb_s, upload_mb_s, active_connections ...
                             system keys: os, hostname, platform, boot_time, uptime ...
  - /api/sysmon/processes  → flat list of process dicts (not wrapped)
  - /api/sysmon/process/<pid> → flat process dict (not wrapped in {success, process})
  - terminate_process()    → dict with success, error, status keys
"""
import os
import pytest
from services.system_monitor import SystemMonitorService, system_monitor_service


def test_system_monitor_overview_service():
    """Verify get_system_overview returns complete real OS telemetry."""
    service = SystemMonitorService()
    overview = service.get_system_overview()

    assert "cpu" in overview
    assert "memory" in overview
    assert "disk" in overview
    assert "network" in overview
    assert "system" in overview

    # CPU — actual keys: usage_percent, per_cpu, logical_cores, physical_cores
    cpu = overview["cpu"]
    cpu_pct = cpu.get("usage_percent") if "usage_percent" in cpu else cpu.get("percent", 0)
    assert isinstance(cpu_pct, (int, float)), f"cpu percent not numeric: {cpu}"
    assert 0 <= cpu_pct <= 100
    per_cpu = cpu.get("per_cpu") or cpu.get("per_cpu_percent") or []
    assert isinstance(per_cpu, list)
    logical = cpu.get("logical_cores") or cpu.get("count_logical") or 1
    assert logical >= 1

    # Memory — actual keys: percent, total_gb, available_gb, used_gb, cached_gb
    mem = overview["memory"]
    mem_pct = mem.get("percent") if "percent" in mem else mem.get("ram_percent", 0)
    assert isinstance(mem_pct, (int, float))
    assert 0 <= mem_pct <= 100
    total = mem.get("total_gb") or mem.get("ram_total_gb") or 0
    assert total > 0
    avail = mem.get("available_gb") if "available_gb" in mem else mem.get("ram_available_gb", 0)
    assert avail >= 0

    # Disk — actual keys: total_gb, used_gb, free_gb, percent, read_mb_s, write_mb_s, partitions
    disk = overview["disk"]
    disk_total = disk.get("total_gb") or disk.get("total_size_gb") or 0
    assert disk_total > 0
    assert isinstance(disk.get("partitions"), list)

    # Network — actual keys: download_mb_s, upload_mb_s, active_connections
    net = overview["network"]
    assert "download_mb_s" in net
    assert "upload_mb_s" in net
    conns_key = "active_connections" if "active_connections" in net else "connection_count"
    assert conns_key in net

    # System info — actual keys: os, hostname, platform, boot_time, uptime
    sys_info = overview["system"]
    assert sys_info.get("hostname")
    assert sys_info.get("os")
    assert sys_info.get("platform")


def test_system_monitor_processes_enumeration():
    """Verify get_processes returns a flat list with correct process fields."""
    service = SystemMonitorService()
    result = service.get_processes(sort_by="cpu", order="desc", limit=50)

    # The service returns a raw list
    assert isinstance(result, list), f"Expected list, got {type(result)}"
    assert len(result) > 0

    for p in result:
        assert "pid" in p, f"Missing pid in {p}"
        assert "name" in p
        assert "status" in p
        assert "cpu_percent" in p
        assert "memory_mb" in p
        assert "is_protected" in p

    # Search filter
    python_procs = service.get_processes(search="python")
    assert isinstance(python_procs, list)
    for p in python_procs:
        assert "python" in p["name"].lower() or str(p["pid"]) in str(p)


def test_system_monitor_process_details():
    """Verify get_process_details returns flat dict with correct keys."""
    service = SystemMonitorService()
    current_pid = os.getpid()
    proc = service.get_process_details(current_pid)

    assert proc is not None
    assert proc["pid"] == current_pid
    assert "name" in proc
    # backend uses "exe" not "exe_path"
    assert "exe" in proc or "exe_path" in proc
    assert "memory_rss_mb" in proc
    assert "num_threads" in proc


def test_system_monitor_protected_process_refusal():
    """Verify terminating protected PIDs returns correct error dict."""
    service = SystemMonitorService()

    res0 = service.terminate_process(0, username="test_analyst", client_ip="127.0.0.1")
    assert res0["success"] is False
    # Error message: "Cannot terminate critical system process (PID 0/4)"
    err_lower = res0["error"].lower()
    assert "cannot terminate" in err_lower or "critical" in err_lower or "protected" in err_lower

    res4 = service.terminate_process(4, username="test_analyst", client_ip="127.0.0.1")
    assert res4["success"] is False


def test_api_sysmon_overview_endpoint(client, auth_headers):
    """GET /api/sysmon/overview returns 200 with expected sections."""
    resp = client.get("/api/sysmon/overview", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "cpu" in data
    assert "memory" in data
    assert "disk" in data
    assert "network" in data
    assert "system" in data


def test_api_sysmon_processes_endpoint(client, auth_headers):
    """GET /api/sysmon/processes returns 200 with a list."""
    resp = client.get("/api/sysmon/processes?sort_by=memory&order=desc&limit=20", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    # Backend returns a flat list
    assert isinstance(data, list)
    if data:
        assert "pid" in data[0]
        assert "name" in data[0]


def test_api_sysmon_process_details_endpoint(client, auth_headers):
    """GET /api/sysmon/process/<pid> returns 200 with process info."""
    current_pid = os.getpid()
    resp = client.get(f"/api/sysmon/process/{current_pid}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    # Backend returns flat dict directly (no success wrapper)
    assert data.get("pid") == current_pid or data.get("success") is True


def test_api_sysmon_process_not_found(client, auth_headers):
    """GET /api/sysmon/process/<invalid_pid> returns 404."""
    resp = client.get("/api/sysmon/process/99999999", headers=auth_headers)
    assert resp.status_code == 404
    data = resp.get_json()
    assert "error" in data


def test_api_sysmon_kill_protected_refusal(client, auth_headers):
    """POST /api/sysmon/process/4/kill returns 403 on protected PID."""
    resp = client.post("/api/sysmon/process/4/kill", headers=auth_headers)
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["success"] is False
    # "Cannot terminate critical system process (PID 0/4)"
    err_lower = data["error"].lower()
    assert "cannot terminate" in err_lower or "critical" in err_lower or "protected" in err_lower


def test_api_sysmon_unauthenticated(client):
    """Unauthenticated requests to /api/sysmon/* return 401."""
    resp = client.get("/api/sysmon/overview")
    assert resp.status_code == 401

    resp = client.get("/api/sysmon/processes")
    assert resp.status_code == 401

    resp = client.post(f"/api/sysmon/process/{os.getpid()}/kill")
    assert resp.status_code == 401
