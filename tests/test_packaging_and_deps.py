"""Packaging & dependency regression tests.

Verifies that every module HorusShield's PyInstaller spec declares as a
hidden import is actually importable in the current environment, and that
the requirements-lock.txt and HorusShield.spec files stay in sync with the
application's runtime needs.

These are pure import / file-content tests — no Flask app, database, or
network access required.
"""
import importlib
import os

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Critical hidden imports that caused the original ModuleNotFoundError ──
CRITICAL_IMPORTS = [
    "flask_limiter",
    "flask_limiter.util",
    "limits",
    "limits.storage",
    "limits.strategies",
    "limits.aio",
    "ordered_set",
    "defusedxml",
    "defusedxml.ElementTree",
]

# Redis is optional at runtime (graceful fallback to memory://) but must be
# importable for the spec's hiddenimports to be correct.
OPTIONAL_IMPORTS = [
    "redis",
]


@pytest.mark.parametrize("module_name", CRITICAL_IMPORTS)
def test_critical_import(module_name):
    """Every critical hidden import must be importable."""
    mod = importlib.import_module(module_name)
    assert mod is not None


@pytest.mark.parametrize("module_name", OPTIONAL_IMPORTS)
def test_optional_import(module_name):
    """Optional hidden imports should be importable when installed."""
    mod = importlib.import_module(module_name)
    assert mod is not None


def test_flask_limiter_instantiation():
    """flask_limiter.Limiter must be instantiable (the original crash was
    a missing import, not a broken class)."""
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["100 per minute"],
        storage_uri="memory://",
    )
    assert limiter is not None


def test_spec_contains_flask_limiter():
    """HorusShield.spec must list flask_limiter in hiddenimports."""
    spec_path = os.path.join(PROJECT_ROOT, "HorusShield.spec")
    assert os.path.exists(spec_path), f"Spec file not found: {spec_path}"
    content = open(spec_path, encoding="utf-8").read()
    assert "flask_limiter" in content, "flask_limiter missing from HorusShield.spec hiddenimports"


def test_spec_contains_limits():
    """HorusShield.spec must list limits in hiddenimports."""
    spec_path = os.path.join(PROJECT_ROOT, "HorusShield.spec")
    content = open(spec_path, encoding="utf-8").read()
    assert "'limits'" in content or '"limits"' in content, (
        "limits missing from HorusShield.spec hiddenimports"
    )


def test_requirements_lock_contains_flask_limiter():
    """backend/requirements-lock.txt must pin Flask-Limiter."""
    lock_path = os.path.join(PROJECT_ROOT, "backend", "requirements-lock.txt")
    assert os.path.exists(lock_path), f"Lock file not found: {lock_path}"
    content = open(lock_path, encoding="utf-8").read().lower()
    assert "flask-limiter" in content, "Flask-Limiter missing from requirements-lock.txt"


def test_requirements_lock_contains_limits():
    """backend/requirements-lock.txt must pin limits."""
    lock_path = os.path.join(PROJECT_ROOT, "backend", "requirements-lock.txt")
    content = open(lock_path, encoding="utf-8").read().lower()
    assert "limits==" in content, "limits missing from requirements-lock.txt"
