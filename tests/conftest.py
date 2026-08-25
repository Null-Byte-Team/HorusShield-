"""
Shared pytest fixtures for HorusShield's test suite.

Every test runs against a throw-away SQLite database in a temp directory —
never the real backend/database/horus.db — set via HORUS_DB_PATH *before*
any HorusShield module is imported, since config.py and database/models.py
both read that env var once, at import time.
"""

import os
import sys
import tempfile

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, BACKEND_DIR)

_TMP_DIR = tempfile.mkdtemp(prefix="horus_test_")
os.environ.setdefault("HORUS_DB_PATH", os.path.join(_TMP_DIR, "test_horus.db"))
os.environ.setdefault("HORUS_ENV", "development")
os.environ.setdefault("HORUS_HEADLESS", "true")
os.environ.setdefault("HORUS_START_ENGINES", "false")
os.environ.setdefault("HORUS_SECRET_KEY", "test-secret-key-not-for-production")


@pytest.fixture(scope="session", autouse=True)
def _init_test_database():
    """Initialize the schema once for the whole test session."""
    from database.models import init_database

    init_database()
    yield


@pytest.fixture
def db():
    from database.db_manager import db as _db

    return _db


@pytest.fixture(scope="session")
def flask_app():
    """A real Flask app with every blueprint registered, exactly as
    production builds it. NOTE: create_app() also starts HorusShield's real
    background engines (network monitor, honeypot listeners, etc.) as a
    side effect — that's existing application behavior we're not changing.
    This fixture is session-scoped specifically so that only happens once
    per test run, instead of once per test (which would otherwise throw
    'address already in use' on the honeypot's fixed ports for every test
    after the first, and leak a fresh set of daemon threads each time)."""
    from app import create_app

    app, ws = create_app()
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture
def reset_rate_limits(flask_app):
    """Tests that deliberately exhaust a rate limit (to verify 429 behavior)
    would otherwise poison every later test sharing the same session-scoped
    Flask app — flask-limiter's default in-memory storage is keyed by
    source IP, and Flask's test client always uses the same IP (127.0.0.1)
    for every test in the process. Reset before AND after so this test's
    limit-exhaustion doesn't leak into whichever test happens to run next."""
    from api.rate_limit import limiter

    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(scope="session")
def auth_headers(flask_app):
    """A real Authorization header for a verified, logged-in test user —
    obtained through the actual register -> verify -> login flow (not a
    manufactured token), so these tests exercise the same path a real
    client does. Session-scoped: one test user, reused by every test that
    needs auth, rather than registering a fresh account per test.

    Role: new users now default to 'analyst' — only the very first user
    ever registered in a database becomes 'admin' automatically (see
    auth/auth_manager.py's _next_role(), the fix for a confirmed Red Team
    finding that every signup used to get admin access). Since this
    fixture can't rely on being the first registration in a shared test
    session (other test files/fixtures may register users first), it
    explicitly promotes itself to admin via a direct DB write after
    verifying — same approach as tests/test_auth.py's
    _create_user_with_role() — so admin-gated endpoint tests stay
    reliable regardless of test ordering. Tests that specifically verify
    role *enforcement* (rejecting a lower-privileged role) create their
    own lower-role user directly via the db fixture instead of using
    this one.

    NOTE: imports db directly (not as a pytest fixture param) — the `db`
    fixture is function-scoped and this fixture is session-scoped;
    pytest doesn't allow a session fixture to depend on a function
    fixture. db.py's `db` object is a module-level singleton anyway, so
    importing it directly here is equivalent and avoids the scope clash.
    """
    from database.db_manager import db as _db

    client = flask_app.test_client()
    email = "pytest-auth@example.com"
    password = "PytestAuth123!"

    reg = client.post(
        "/api/auth/register", json={"email": email, "password": password, "name": "Pytest User"}
    )
    dev_code = reg.get_json().get("dev_code") if reg.status_code == 200 else None
    if dev_code:
        client.post("/api/auth/verify", json={"email": email, "code": dev_code})

    with _db.get_connection() as conn:
        conn.execute("UPDATE users SET role='admin', is_verified=1 WHERE email=?", (email,))

    login = client.post("/api/auth/login", json={"email": email, "password": password})
    token = login.get_json().get("token") if login.status_code == 200 else None
    assert (
        token
    ), f"auth_headers fixture could not obtain a token: {login.status_code} {login.get_json()}"
    return {"Authorization": f"Bearer {token}"}
