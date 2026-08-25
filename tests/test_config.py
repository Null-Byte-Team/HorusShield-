"""Tests for backend/config.py — env-var overrides and safe defaults."""

import importlib
import os


def test_active_config_loads():
    from config import active_config

    assert active_config.PORT == int(os.environ.get("HORUS_PORT", "5050"))
    assert active_config.HOST  # never empty


def test_secret_key_is_persisted_and_nonempty():
    from config import active_config

    assert active_config.SECRET_KEY
    assert len(active_config.SECRET_KEY) >= 32


def test_host_defaults_to_localhost_when_unset(monkeypatch):
    """Guards the security-relevant default — HORUS_HOST must default to
    127.0.0.1 (never expose the desktop app to the LAN) unless explicitly
    overridden."""
    monkeypatch.delenv("HORUS_HOST", raising=False)
    import config

    importlib.reload(config)
    assert config.Config.HOST == "127.0.0.1"
    # restore module state for subsequent tests
    importlib.reload(config)


def test_score_weights_sum_close_to_one():
    from config import active_config

    total = sum(active_config.SCORE_WEIGHTS.values())
    assert abs(total - 1.0) < 0.01


def test_vscan_active_scan_defaults_to_off():
    """Safety-relevant default: ZAP active scan must default to opt-in only."""
    from config import active_config

    assert active_config.VSCAN_ALLOW_ACTIVE_SCAN_DEFAULT is False
