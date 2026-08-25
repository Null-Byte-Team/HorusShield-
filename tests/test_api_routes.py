"""Tests for REST API endpoints via Flask's test client — no live server needed."""


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "online"


def test_index_serves_the_ui_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"HorusShield" in resp.data or b"horus" in resp.data.lower()


# ── Authentication / Authorization enforcement ──
# These specifically verify the auth fix: every one of these endpoints used
# to be reachable with no token at all.


def test_vscan_history_requires_auth(client):
    resp = client.get("/api/vscanner/history")
    assert resp.status_code == 401


def test_devices_list_requires_auth(client):
    resp = client.get("/api/devices/")
    assert resp.status_code == 401


def test_terminal_run_requires_auth(client):
    resp = client.post("/api/terminal/run", json={"operation": "whoami"})
    assert resp.status_code == 401


def test_settings_toggle_requires_auth(client):
    resp = client.post("/api/settings/toggle", json={"key": "x", "value": True})
    assert resp.status_code == 401


def test_audit_log_requires_auth(client):
    resp = client.get("/api/audit/?limit=5")
    assert resp.status_code == 401


def test_ai_train_requires_auth(client):
    resp = client.post("/api/ai/train")
    assert resp.status_code == 401


# ── Same endpoints, now with a real authenticated session ──


def test_vscan_history_endpoint_returns_a_list(client, auth_headers):
    resp = client.get("/api/vscanner/history", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


def test_vscan_start_rejects_missing_target_url(client, auth_headers):
    resp = client.post("/api/vscanner/scan/start", json={}, headers=auth_headers)
    assert resp.status_code == 400
    assert "target_url" in resp.get_json()["error"]


def test_vscan_start_rejects_malformed_url(client, auth_headers):
    resp = client.post(
        "/api/vscanner/scan/start", json={"target_url": "not a url!!"}, headers=auth_headers
    )
    assert resp.status_code in (400, 409)


def test_vscan_start_rejects_active_scan_without_authorization(client, auth_headers):
    resp = client.post(
        "/api/vscanner/scan/start",
        json={
            "target_url": "http://example.com",
            "active_scan": True,
            "authorized_confirmation": False,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "authorization" in resp.get_json()["error"].lower()


def test_vscan_report_rejects_unknown_format(client, auth_headers):
    resp = client.get("/api/vscanner/scan/does-not-exist/report/exe", headers=auth_headers)
    assert resp.status_code == 400


def test_audit_log_endpoint_returns_a_list(client, auth_headers):
    resp = client.get("/api/audit/?limit=5", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


def test_settings_toggle_requires_key(client, auth_headers):
    resp = client.post("/api/settings/toggle", json={"value": True}, headers=auth_headers)
    assert resp.status_code == 400


def test_dashboard_stats_endpoint_does_not_error(client, auth_headers):
    resp = client.get("/api/dashboard/stats", headers=auth_headers)
    # Not asserting exact shape (evolves independently) — just that the
    # route is wired up and doesn't 500.
    assert resp.status_code in (200, 404)


def test_unknown_route_returns_404_or_serves_static(client):
    resp = client.get("/api/this-route-does-not-exist")
    assert resp.status_code == 404


# ── Terminal allowlist ──


def test_terminal_operations_list_is_reachable(client, auth_headers):
    resp = client.get("/api/terminal/operations", headers=auth_headers)
    assert resp.status_code == 200
    names = [op["name"] for op in resp.get_json()["operations"]]
    assert "whoami" in names
    assert "format" not in names  # nothing destructive is ever in the allowlist


def test_terminal_rejects_non_allowlisted_operation(client, auth_headers):
    resp = client.post(
        "/api/terminal/run", json={"operation": "del /f /s /q C:\\"}, headers=auth_headers
    )
    assert resp.status_code == 400


def test_terminal_rejects_injection_shaped_target(client, auth_headers):
    resp = client.post(
        "/api/terminal/run",
        json={"operation": "ping", "target": "8.8.8.8; rm -rf /"},
        headers=auth_headers,
    )
    assert resp.status_code == 400


def test_terminal_allows_valid_operation(client, auth_headers):
    resp = client.post("/api/terminal/run", json={"operation": "whoami"}, headers=auth_headers)
    assert resp.status_code == 200
    assert "exit_code" in resp.get_json()


def test_terminal_shells_list(client, auth_headers):
    resp = client.get("/api/terminal/shells", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "shells" in data
    assert len(data["shells"]) > 0


def test_terminal_exec_runs_command(client, auth_headers):
    resp = client.post(
        "/api/terminal/exec",
        json={"command": "echo HorusShield_Real_Shell_Test", "shell": "cmd"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("exit_code") == 0
    assert "HorusShield_Real_Shell_Test" in data.get("stdout", "")


def test_terminal_exec_requires_command(client, auth_headers):
    resp = client.post("/api/terminal/exec", json={"command": ""}, headers=auth_headers)
    assert resp.status_code == 400


# ── Rate limiting ──


def test_login_rate_limit_returns_429_eventually(client, reset_rate_limits):
    codes = []
    for _ in range(8):
        resp = client.post(
            "/api/auth/login", json={"email": "nobody@example.com", "password": "wrong"}
        )
        codes.append(resp.status_code)
    assert 429 in codes
