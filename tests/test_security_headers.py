"""Tests for the security headers added on every response (Phase 10)."""


def test_security_headers_present_on_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in resp.headers.get("Permissions-Policy", "")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_security_headers_present_on_error_responses_too(client):
    resp = client.get("/api/this-does-not-exist")
    assert resp.status_code == 404
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_csp_allows_the_one_real_external_script_the_app_loads(client):
    resp = client.get("/api/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "cdn.socket.io" in csp


def test_hsts_only_sent_over_https(client):
    """The test client simulates plain HTTP — HSTS must not be sent, since
    it would be meaningless (and slightly wrong) advice over an insecure
    connection."""
    resp = client.get("/api/health")
    assert "Strict-Transport-Security" not in resp.headers
