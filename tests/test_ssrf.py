"""Tests for security/ssrf.py — the fix for a confirmed Critical finding
from the Red Team review (V-8 Scanner accepted internal/loopback/cloud-
metadata targets)."""
import pytest


def test_rejects_loopback_ipv4():
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("http://127.0.0.1")
    with pytest.raises(SSRFValidationError):
        validate_target("http://127.0.0.1:8080")


def test_rejects_loopback_ipv6():
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("http://[::1]")


def test_rejects_cloud_metadata_endpoint():
    """The exact address exploited live in the Red Team review."""
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("http://169.254.169.254/latest/meta-data/")


def test_rejects_rfc1918_private_ranges():
    from security.ssrf import SSRFValidationError, validate_target

    for ip in ("http://10.0.0.1", "http://172.16.0.1", "http://192.168.1.1"):
        with pytest.raises(SSRFValidationError):
            validate_target(ip)


def test_rejects_link_local():
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("http://169.254.1.1")


def test_rejects_ipv6_unique_local_and_link_local():
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("http://[fc00::1]")
    with pytest.raises(SSRFValidationError):
        validate_target("http://[fe80::1]")


def test_rejects_multicast():
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("http://224.0.0.1")


def test_rejects_disallowed_schemes():
    from security.ssrf import SSRFValidationError, validate_target

    for scheme_url in ("file:///etc/passwd", "ftp://example.com", "gopher://example.com", "dict://example.com"):
        with pytest.raises(SSRFValidationError):
            validate_target(scheme_url)


def test_rejects_unresolvable_hostname():
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("http://this-definitely-does-not-resolve-anywhere-xyz123.invalid")


def test_accepts_legitimate_public_looking_ip():
    """8.8.8.8 is a real public IP (Google DNS) — must NOT be rejected as
    private/internal. Confirms the validator isn't just blocking
    everything."""
    from security.ssrf import validate_target

    result = validate_target("http://8.8.8.8")
    assert result["hostname"] == "8.8.8.8"
    assert "8.8.8.8" in result["resolved_ips"]


def test_allow_private_flag_bypasses_the_check_when_explicitly_set():
    """The opt-out exists for legitimate internal-network testing —
    verify it actually works when explicitly enabled, and confirm it's
    off by default (see test_rejects_* above, none of them pass
    allow_private)."""
    from security.ssrf import validate_target

    result = validate_target("http://127.0.0.1", allow_private=True)
    assert result["hostname"] == "127.0.0.1"


def test_missing_url_rejected():
    from security.ssrf import SSRFValidationError, validate_target

    with pytest.raises(SSRFValidationError):
        validate_target("")
    with pytest.raises(SSRFValidationError):
        validate_target(None)


def test_resolve_all_ips_returns_real_addresses():
    from security.ssrf import resolve_all_ips

    ips = resolve_all_ips("localhost")
    assert len(ips) > 0
    # localhost must resolve to something loopback-classified
    assert any(ip.is_loopback for ip in ips)


# ── Endpoint-level: the actual fix wired into routes_vscanner.py ──


def test_vscan_start_rejects_loopback_target(client, auth_headers):
    resp = client.post(
        "/api/vscanner/scan/start",
        json={"target_url": "http://127.0.0.1:9999", "tools": ["nmap"]},
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert "disallowed" in resp.get_json()["error"].lower() or "private" in resp.get_json()["error"].lower()


def test_vscan_start_rejects_cloud_metadata_target(client, auth_headers):
    """This exact payload was ACCEPTED (200) in the Red Team review before
    this fix — must now be rejected."""
    resp = client.post(
        "/api/vscanner/scan/start",
        json={"target_url": "http://169.254.169.254/latest/meta-data/", "tools": ["nmap"]},
        headers=auth_headers,
    )
    assert resp.status_code == 400


def test_vscan_start_rejects_rfc1918_targets(client, auth_headers):
    for target in ("http://10.0.0.1", "http://192.168.1.1"):
        resp = client.post(
            "/api/vscanner/scan/start",
            json={"target_url": target, "tools": ["nmap"]},
            headers=auth_headers,
        )
        assert resp.status_code == 400, f"{target} should have been rejected"


def test_vscan_start_still_accepts_legitimate_public_target(client, auth_headers):
    """Confirms the SSRF fix didn't collaterally break normal scanning —
    a real public hostname must still pass validation (the scan itself
    may still fail later for unrelated reasons, e.g. nmap not installed
    in this environment, but it must not be rejected at the SSRF stage)."""
    resp = client.post(
        "/api/vscanner/scan/start",
        json={"target_url": "http://example.com", "tools": ["nmap"]},
        headers=auth_headers,
    )
    assert resp.status_code != 400 or "disallowed" not in resp.get_json().get("error", "").lower()
