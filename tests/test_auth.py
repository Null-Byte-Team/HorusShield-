"""Tests for auth/decorators.py and auth/auth_manager.py — role enforcement
specifically, which tests/test_api_routes.py's auth_headers fixture can't
cover on its own (that fixture's user is always role='admin' by DB default).
"""

from flask import Flask, jsonify


def _make_probe_app():
    """A minimal Flask app with three routes, one per decorator, so we can
    test auth/decorators.py in isolation from the rest of HorusShield's
    blueprints."""
    from auth.decorators import admin_required, analyst_required, login_required

    app = Flask(__name__)

    @app.route("/login-only")
    @login_required
    def _login_only():
        return jsonify({"ok": True, "user": request_user()})

    @app.route("/analyst-only")
    @analyst_required
    def _analyst_only():
        return jsonify({"ok": True})

    @app.route("/admin-only")
    @admin_required
    def _admin_only():
        return jsonify({"ok": True})

    def request_user():
        from flask import request

        return request.current_user.get("email", "")

    return app


def _create_user_with_role(db, email, password, role):
    """Insert a user directly with a specific role — auth_manager's public
    register() always creates 'admin', so role-enforcement tests need a
    lower-privileged user created directly."""
    from auth.auth_manager import _hash_password

    password_hash = _hash_password(password)  # "salt_hex:key_hex", see auth_manager.py
    with db.get_connection() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO users
               (email, password_hash, full_name, role, is_verified)
               VALUES (?, ?, ?, ?, 1)""",
            (email, password_hash, "Role Test User", role),
        )


def _login_and_get_token(client, email, password):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


def test_login_required_rejects_no_token():
    app = _make_probe_app()
    with app.test_client() as c:
        resp = c.get("/login-only")
        assert resp.status_code == 401


def test_login_required_rejects_garbage_token():
    app = _make_probe_app()
    with app.test_client() as c:
        resp = c.get("/login-only", headers={"Authorization": "Bearer not-a-real-token"})
        assert resp.status_code == 401


def test_analyst_role_can_reach_analyst_endpoint_but_not_admin(client, db):
    _create_user_with_role(db, "analyst@example.com", "AnalystPass123!", "analyst")
    token = _login_and_get_token(client, "analyst@example.com", "AnalystPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    # analyst-level endpoint: settings GET is login_required (any role) —
    # use a real analyst_required endpoint instead: device block/unblock.
    resp = client.post("/api/devices/999999/trust", headers=headers)
    # 404 (device doesn't exist) is fine — the point is it's NOT 401/403
    assert resp.status_code not in (401, 403)

    # admin-only endpoint: terminal must reject an analyst
    resp = client.post("/api/terminal/run", json={"operation": "whoami"}, headers=headers)
    assert resp.status_code == 403


def test_unknown_role_is_rejected_from_admin_endpoint(client, db):
    _create_user_with_role(db, "norole@example.com", "NoRolePass123!", "guest")
    token = _login_and_get_token(client, "norole@example.com", "NoRolePass123!")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post("/api/terminal/run", json={"operation": "whoami"}, headers=headers)
    assert resp.status_code == 403

    resp = client.post("/api/settings/toggle", json={"key": "x", "value": True}, headers=headers)
    assert resp.status_code == 403


def test_authorization_denial_is_audit_logged(client, db):
    _create_user_with_role(db, "denied@example.com", "DeniedPass123!", "guest")
    token = _login_and_get_token(client, "denied@example.com", "DeniedPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    before = len(
        db.get_audit_log(limit=500, action="authorization_denied", username="denied@example.com")
    )
    client.post("/api/terminal/run", json={"operation": "whoami"}, headers=headers)
    after = db.get_audit_log(
        limit=500, action="authorization_denied", username="denied@example.com"
    )
    assert len(after) == before + 1
    assert after[0]["username"] == "denied@example.com"


def test_password_hashing_uses_unique_salts(db):
    from auth.auth_manager import _hash_password, _verify_password

    hash1 = _hash_password("SamePassword123!")
    hash2 = _hash_password("SamePassword123!")
    assert hash1 != hash2  # same password, random salt each time -> different stored hash
    # both still verify correctly against the same plaintext
    assert _verify_password("SamePassword123!", hash1)
    assert _verify_password("SamePassword123!", hash2)
    assert not _verify_password("WrongPassword", hash1)


def test_login_rate_limit_resets_key_is_per_ip_not_global(client, reset_rate_limits):
    """Sanity check that the rate limiter is actually configured (doesn't
    verify true per-IP isolation, which needs multiple source IPs — just
    confirms the limiter engages predictably within a single test client)."""
    codes = [
        client.post("/api/auth/login", json={"email": "a@a.com", "password": "x"}).status_code
        for _ in range(6)
    ]
    assert any(c == 429 for c in codes)
