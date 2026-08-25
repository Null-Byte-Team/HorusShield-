"""Tests for backend/utils/helpers.py — pure functions, no DB/network needed."""

import re


def test_generate_session_id_is_unique_and_nonempty():
    from utils.helpers import generate_session_id

    a = generate_session_id()
    b = generate_session_id()
    assert a and b
    assert a != b


def test_is_private_ip():
    from utils.helpers import is_private_ip

    assert is_private_ip("192.168.1.10") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("8.8.8.8") is False


def test_synthetic_mac_from_ip_is_deterministic():
    from utils.helpers import synthetic_mac_from_ip

    mac1 = synthetic_mac_from_ip("192.168.1.50")
    mac2 = synthetic_mac_from_ip("192.168.1.50")
    mac3 = synthetic_mac_from_ip("192.168.1.51")
    assert mac1 == mac2  # same input → same synthetic MAC
    assert mac1 != mac3
    assert re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac1)


def test_severity_number_round_trip():
    from utils.helpers import number_to_severity, severity_to_number

    for sev in ("low", "medium", "high", "critical"):
        n = severity_to_number(sev)
        assert number_to_severity(n) == sev


def test_format_bytes_human_readable():
    from utils.helpers import format_bytes

    assert "KB" in format_bytes(2048) or "kb" in format_bytes(2048).lower()
    assert format_bytes(0) is not None


def test_safe_json_loads_returns_default_on_bad_input():
    from utils.helpers import safe_json_loads

    assert safe_json_loads("{not valid json", default={"x": 1}) == {"x": 1}
    assert safe_json_loads('{"a": 1}', default=None) == {"a": 1}
