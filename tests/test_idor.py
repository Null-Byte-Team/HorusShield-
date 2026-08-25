"""Tests for the IDOR fix — V-8 Scanner scans now belong to an owner and
non-admin users can only access their own. Fixes a confirmed High finding
from the Red Team review: any authenticated user could previously read
and delete any other user's scan."""
import time

import pytest


@pytest.fixture(autouse=True)
def _reset_limits_for_every_test(reset_rate_limits):
    """Every test in this file registers/logs in 1-2 fresh users — without
    resetting rate limits between tests, the register (3/min) and login
    (5/min) limits get exhausted partway through the file, unrelated to
    what's actually being tested here (IDOR, not rate limiting)."""
    yield


def _make_analyst(client, db, email, password):
    """Register + verify + login a fresh user, forced to 'analyst' role
    (new registrations default to 'analyst' now anyway unless they happen
    to be the very first user ever — forcing it here keeps the test
    independent of registration order)."""
    reg = client.post("/api/auth/register", json={"email": email, "password": password, "name": "T"})
    dev_code = reg.get_json().get("dev_code")
    if dev_code:
        client.post("/api/auth/verify", json={"email": email, "code": dev_code})
    with db.get_connection() as conn:
        conn.execute("UPDATE users SET role='analyst', is_verified=1 WHERE email=?", (email,))
    login = client.post("/api/auth/login", json={"email": email, "password": password})
    token = login.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_owner_can_access_own_scan(client, db):
    headers_a = _make_analyst(client, db, f"idor-a-{int(time.time()*1000)}@example.com", "OwnerPass123!")
    r = client.post("/api/vscanner/scan/start", json={"target_url": "http://example.com", "tools": ["nmap"]}, headers=headers_a)
    scan_id = r.get_json()["scan_id"]
    r2 = client.get(f"/api/vscanner/scan/{scan_id}", headers=headers_a)
    assert r2.status_code == 200


def test_other_user_cannot_read_scan_they_dont_own(client, db):
    headers_a = _make_analyst(client, db, f"idor-b1-{int(time.time()*1000)}@example.com", "OwnerPass123!")
    headers_b = _make_analyst(client, db, f"idor-b2-{int(time.time()*1000)}@example.com", "OtherPass123!")

    r = client.post("/api/vscanner/scan/start", json={"target_url": "http://example.com", "tools": ["nmap"]}, headers=headers_a)
    scan_id = r.get_json()["scan_id"]

    r2 = client.get(f"/api/vscanner/scan/{scan_id}", headers=headers_b)
    assert r2.status_code == 403, "non-owner must be rejected with 403, not 200 or 404"


def test_other_user_cannot_delete_scan_they_dont_own(client, db):
    """The exact exploit confirmed live in the Red Team review: User B
    deleting User A's scan."""
    headers_a = _make_analyst(client, db, f"idor-c1-{int(time.time()*1000)}@example.com", "OwnerPass123!")
    headers_b = _make_analyst(client, db, f"idor-c2-{int(time.time()*1000)}@example.com", "OtherPass123!")

    r = client.post("/api/vscanner/scan/start", json={"target_url": "http://example.com", "tools": ["nmap"]}, headers=headers_a)
    scan_id = r.get_json()["scan_id"]

    r2 = client.delete(f"/api/vscanner/scan/{scan_id}", headers=headers_b)
    assert r2.status_code == 403

    r3 = client.get(f"/api/vscanner/scan/{scan_id}", headers=headers_a)
    assert r3.status_code == 200


def test_other_user_cannot_stop_scan_they_dont_own(client, db):
    headers_a = _make_analyst(client, db, f"idor-d1-{int(time.time()*1000)}@example.com", "OwnerPass123!")
    headers_b = _make_analyst(client, db, f"idor-d2-{int(time.time()*1000)}@example.com", "OtherPass123!")

    r = client.post("/api/vscanner/scan/start", json={"target_url": "http://example.com", "tools": ["nmap"]}, headers=headers_a)
    scan_id = r.get_json()["scan_id"]

    r2 = client.post(f"/api/vscanner/scan/{scan_id}/stop", headers=headers_b)
    assert r2.status_code == 403


def test_unauthorized_access_returns_403_not_404(client, db):
    headers_a = _make_analyst(client, db, f"idor-e1-{int(time.time()*1000)}@example.com", "OwnerPass123!")
    headers_b = _make_analyst(client, db, f"idor-e2-{int(time.time()*1000)}@example.com", "OtherPass123!")

    r = client.post("/api/vscanner/scan/start", json={"target_url": "http://example.com", "tools": ["nmap"]}, headers=headers_a)
    scan_id = r.get_json()["scan_id"]

    assert client.get(f"/api/vscanner/scan/{scan_id}", headers=headers_b).status_code == 403
    assert client.get(f"/api/vscanner/scan/{scan_id}/status", headers=headers_b).status_code == 403
    assert client.get("/api/vscanner/scan/does-not-exist-at-all", headers=headers_b).status_code == 404


def test_admin_can_access_any_scan(client, auth_headers, db):
    """auth_headers fixture is forced to admin — confirm admin really can
    see a scan created by someone else, per the explicit 'Admins may
    access everything' requirement."""
    headers_owner = _make_analyst(client, db, f"idor-f-{int(time.time()*1000)}@example.com", "OwnerPass123!")
    r = client.post("/api/vscanner/scan/start", json={"target_url": "http://example.com", "tools": ["nmap"]}, headers=headers_owner)
    scan_id = r.get_json()["scan_id"]

    r2 = client.get(f"/api/vscanner/scan/{scan_id}", headers=auth_headers)
    assert r2.status_code == 200


def test_scan_history_only_shows_own_scans_for_non_admin(client, db):
    headers_a = _make_analyst(client, db, f"idor-g1-{int(time.time()*1000)}@example.com", "OwnerPass123!")
    headers_b = _make_analyst(client, db, f"idor-g2-{int(time.time()*1000)}@example.com", "OtherPass123!")

    client.post("/api/vscanner/scan/start", json={"target_url": "http://example.com", "tools": ["nmap"]}, headers=headers_a)

    hist_a = client.get("/api/vscanner/history", headers=headers_a).get_json()
    hist_b = client.get("/api/vscanner/history", headers=headers_b).get_json()
    assert len(hist_a) >= 1
    assert isinstance(hist_b, list)
