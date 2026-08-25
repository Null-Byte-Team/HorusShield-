"""Tests for the /verify endpoint hardening — fixes a confirmed Medium
finding (no endpoint-specific rate limit on a brute-forceable 6-digit
code)."""
import time

import pytest


@pytest.fixture(autouse=True)
def _reset_limits(reset_rate_limits):
    yield


def test_verify_endpoint_has_its_own_rate_limit(client):
    """Confirms RATELIMIT_VERIFY actually engages, not just the weaker
    global default."""
    email = f"verifylimit-{int(time.time()*1000)}@example.com"
    codes = []
    for _ in range(8):
        r = client.post("/api/auth/verify", json={"email": email, "code": "000000"})
        codes.append(r.status_code)
    assert 429 in codes


def test_account_lockout_after_repeated_failures(client, db):
    """Per-account lockout: fail verification enough times for ONE
    account and further attempts for that account get rejected — this is
    a distinct control from the per-IP limit above (see
    routes_auth.py's verify_email() docstring)."""
    email = f"lockout-{int(time.time()*1000)}@example.com"
    client.post("/api/auth/register", json={"email": email, "password": "LockoutPass123!", "name": "T"})

    from config import active_config as config

    for _ in range(config.VERIFY_ACCOUNT_LOCKOUT_THRESHOLD):
        db.add_audit_log(action="email_verify_attempt", username=email, status="failure",
                          ip_address="1.2.3.4", details="seeded failure")

    r = client.post("/api/auth/verify", json={"email": email, "code": "999999"})
    assert r.status_code == 429
    assert "locked" in r.get_json()["error"].lower() or "too many" in r.get_json()["error"].lower()


def test_successful_verification_is_not_blocked_by_unrelated_accounts_lockout(client, db):
    """Lockout is per-account, not global — a different account's failures
    must not affect this one."""
    victim_email = f"other-account-{int(time.time()*1000)}@example.com"
    from config import active_config as config

    for _ in range(config.VERIFY_ACCOUNT_LOCKOUT_THRESHOLD + 2):
        db.add_audit_log(action="email_verify_attempt", username=victim_email, status="failure",
                          ip_address="1.2.3.4", details="seeded")

    my_email = f"unaffected-{int(time.time()*1000)}@example.com"
    reg = client.post("/api/auth/register", json={"email": my_email, "password": "MyPass123!", "name": "T"})
    code = reg.get_json().get("dev_code")
    if code:
        r = client.post("/api/auth/verify", json={"email": my_email, "code": code})
        assert r.status_code == 200


def test_every_verify_attempt_is_audit_logged(client, db):
    email = f"auditverify-{int(time.time()*1000)}@example.com"
    before = db.count_recent_audit_actions("email_verify_attempt", email, since_minutes=60)
    client.post("/api/auth/verify", json={"email": email, "code": "111111"})
    after = db.count_recent_audit_actions("email_verify_attempt", email, since_minutes=60)
    assert after == before + 1
