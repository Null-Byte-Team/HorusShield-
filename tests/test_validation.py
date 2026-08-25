"""Tests for utils/validation.py and the endpoints updated to use it."""

import os


def test_validate_email():
    from utils.validation import validate_email

    assert validate_email("user@example.com")[0] == "user@example.com"
    assert validate_email("USER@Example.COM")[0] == "user@example.com"
    assert validate_email("not-an-email")[1] is not None
    assert validate_email("")[1] is not None
    assert validate_email(None)[1] is not None


def test_validate_hostname():
    from utils.validation import validate_hostname

    assert validate_hostname("example.com")[0] == "example.com"
    assert validate_hostname("sub.example.co.uk")[0] == "sub.example.co.uk"
    assert validate_hostname("not a host!!")[1] is not None
    assert validate_hostname("a" * 300)[1] is not None


def test_validate_ip():
    from utils.validation import validate_ip, validate_ipv4, validate_ipv6

    assert validate_ipv4("192.168.1.1")[0] == "192.168.1.1"
    assert validate_ipv4("999.999.999.999")[1] is not None
    assert validate_ipv6("::1")[0] == "::1"
    assert validate_ip("10.0.0.1")[0] == "10.0.0.1"
    assert validate_ip("::1")[0] == "::1"
    assert validate_ip("not-an-ip")[1] is not None


def test_validate_port():
    from utils.validation import validate_port

    assert validate_port(80)[0] == 80
    assert validate_port("443")[0] == 443
    assert validate_port(0)[1] is not None
    assert validate_port(70000)[1] is not None
    assert validate_port("abc")[1] is not None


def test_validate_url():
    from utils.validation import validate_url

    assert validate_url("https://example.com")[0] == "https://example.com"
    assert validate_url("ftp://example.com")[1] is not None
    assert validate_url("http://not a valid host!!")[1] is not None
    assert validate_url("x" * 3000)[1] is not None


def test_validate_filename():
    from utils.validation import validate_filename

    assert validate_filename("report_2026.pdf")[0] == "report_2026.pdf"
    assert validate_filename("../../etc/passwd")[1] is not None
    assert validate_filename("report.pdf", allowed_extensions={"pdf"})[1] is None
    assert validate_filename("report.exe", allowed_extensions={"pdf"})[1] is not None
    assert validate_filename(".hidden")[1] is not None


def test_safe_join_and_verify_blocks_traversal(tmp_path):
    from utils.validation import safe_join_and_verify

    base = tmp_path / "reports"
    base.mkdir()
    (base / "real.pdf").write_text("x")

    path, err = safe_join_and_verify(str(base), "real.pdf")
    assert err is None
    assert path == str((base / "real.pdf").resolve())

    # os.path.basename() strips the traversal before it ever reaches the
    # join, so this resolves to base/etc-passwd-shaped-but-harmless name,
    # not an escape — verifying the containment check holds regardless.
    path2, err2 = safe_join_and_verify(str(base), "../../../etc/passwd")
    assert err2 is None  # basename() reduced it to a harmless "passwd" filename
    assert os.path.dirname(path2) == str(base.resolve())


def test_validate_positive_int():
    from utils.validation import validate_positive_int

    assert validate_positive_int("5")[0] == 5
    assert validate_positive_int(-1)[1] is not None
    assert validate_positive_int("abc")[1] is not None
    assert validate_positive_int(100, max_value=50)[1] is not None


def test_validate_bool():
    from utils.validation import validate_bool

    assert validate_bool(True)[0] is True
    assert validate_bool("true")[0] is True
    assert validate_bool("false")[0] is False
    assert validate_bool("maybe")[1] is not None


def test_validate_enum():
    from utils.validation import validate_enum

    assert validate_enum("a", ["a", "b"])[0] == "a"
    assert validate_enum("c", ["a", "b"])[1] is not None


def test_validate_string_length_cap():
    from utils.validation import validate_string

    assert validate_string("hello", max_length=10)[0] == "hello"
    assert validate_string("x" * 20, max_length=10)[1] is not None
    assert validate_string("", required=False)[0] == ""
    assert validate_string(None, required=True)[1] is not None


# ── Endpoint-level checks for the validation added this pass ──


def test_settings_toggle_rejects_malformed_key(client, auth_headers):
    resp = client.post(
        "/api/settings/toggle",
        json={"key": "not a valid key!!", "value": True},
        headers=auth_headers,
    )
    assert resp.status_code == 400


def test_settings_get_rejects_malformed_key(client, auth_headers):
    resp = client.get("/api/settings/not-valid-key!!", headers=auth_headers)
    assert resp.status_code == 400


def test_ai_train_rejects_invalid_type(client, auth_headers):
    resp = client.post("/api/ai/train", json={"type": "nonsense"}, headers=auth_headers)
    assert resp.status_code == 400


def test_horus_ask_rejects_empty_query(client, auth_headers):
    resp = client.post("/api/horus/ask", json={"query": ""}, headers=auth_headers)
    assert resp.status_code == 400


def test_horus_ask_rejects_oversized_query(client, auth_headers):
    resp = client.post("/api/horus/ask", json={"query": "x" * 5000}, headers=auth_headers)
    assert resp.status_code == 400


def test_horus_ask_rejects_invalid_language(client, auth_headers):
    resp = client.post(
        "/api/horus/ask", json={"query": "hello", "language": "fr"}, headers=auth_headers
    )
    assert resp.status_code == 400


def test_reports_download_rejects_path_traversal(client, auth_headers):
    resp = client.get("/api/reports/download/..%2f..%2f..%2fetc%2fpasswd", headers=auth_headers)
    assert resp.status_code in (400, 404)  # never 200, never leaks a file outside the reports dir
