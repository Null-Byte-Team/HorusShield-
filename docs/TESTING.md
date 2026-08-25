# HorusShield 2.0 — Testing Guide

## Running the suite locally

```bash
pip install -r backend/requirements.txt
pip install pytest pytest-cov
pytest tests/ -v
```

Every test uses a throw-away SQLite database (see `tests/conftest.py`) — **the real `backend/database/horus.db` is never touched by the test suite.**

With coverage:

```bash
pytest tests/ --cov=backend --cov-report=term-missing
```

## What's covered

| File | Covers |
|---|---|
| `test_config.py` | Env-var overrides, and that security-relevant defaults (host binds to `127.0.0.1`, active-scan opt-in defaults off) don't silently change |
| `test_database.py` | Schema init, device/audit-log/vscan CRUD, cascade delete, `close_all_connections()` |
| `test_ai.py` | Security scorer output shape/bounds, V-8 Scanner AI Cortex (dedup, OWASP/CWE classification, prioritization, summarization) |
| `test_reports.py` | Both PDF report generators actually produce non-empty files — this is what caught the em-dash/cursor-position crashes described in `docs/CHANGELOG_DEVOPS.md` |
| `test_utils.py` | Pure helper functions (MAC synthesis, private-IP detection, byte formatting, etc.) |
| `test_api_routes.py` | REST endpoints via Flask's test client — health check, V-8 Scanner input validation, audit log, settings |

## Why `flask_app` is session-scoped

`create_app()` (in `backend/app.py`) starts HorusShield's real background engines — network monitor, honeypot listeners on fixed ports, mesh defense, AI trainer thread — as an existing side effect of building the app. That's application behavior this test suite intentionally does not change. The `flask_app` fixture in `tests/conftest.py` is scoped to the whole test session specifically so this only happens **once** per test run; scoping it per-test would throw "address already in use" on the honeypot's ports for every test after the first, and leak a new set of daemon threads each time.

## CI

The same suite runs in `.github/workflows/main.yml` on every push/PR, plus two extra checks pytest doesn't cover on its own:

- `scripts/verify_db_init.py` — schema initializes cleanly from nothing, every expected table exists
- `scripts/verify_flask_boot.py` — actually spawns `python app.py` as a subprocess (headless) and polls `/api/health`, exercising the real entry point end-to-end
- `scripts/check_imports.py` — imports every module under `backend/` individually; this is what caught the stale `ai.horus_assistant` import path in `examples_horus_ai.py` (it had moved to `services.horus_assistant`)

## Adding new tests

Follow the existing pattern: import the real module, exercise real behavior against the temp DB (`db` fixture) or a real Flask test client (`client` fixture) — avoid mocking HorusShield's own code. Mocking `requests`/subprocess calls to *external* tools (ZAP, Nikto, Nmap) is reasonable since those aren't installed in CI; `vscanner/*.py` doesn't currently have tests for that reason and would need a mocked ZAP daemon or Nikto/Nmap binaries in the CI environment to test meaningfully.
