# Project Structure

```
HorusShield_2.0/
│
├── HorusShield_UI.html          # Entire frontend: HTML+CSS+JS in one file, Flask-served
│
├── backend/
│   ├── app.py                    # Entry point. create_app() builds Flask+SocketIO+engines;
│   │                              #   __main__ picks desktop (pywebview) or headless (Docker)
│   ├── config.py                  # All configuration; env-var driven (see .env.example)
│   ├── requirements.txt            # Direct dependencies
│   ├── requirements-lock.txt        # Full resolved dependency tree (generated, see header)
│   │
│   ├── ai/                          # Security scorer, threat classifier, anomaly/attack
│   │                                #   predictors, V-8 Scanner AI Cortex, Horus conversation engine
│   ├── api/                          # One routes_*.py blueprint per feature area — see
│   │                                #   docs/API_REFERENCE.md for the full endpoint list
│   ├── auth/                          # Login/register/session/SMTP/Google sign-in
│   ├── database/                       # models.py (schema) + db_manager.py (all DB access)
│   ├── engine/                          # Network monitor, packet analyzer, attack detector,
│   │                                    #   device blocker, lockdown manager, port-scan/portscan logic
│   ├── honeypot/                         # SSH/HTTP/FTP/Telnet honeypot listeners
│   ├── mesh/                              # Mesh Defense graph engine
│   ├── services/                           # Report generators (PDF/HTML/JSON), Horus AI
│   │                                       #   assistant, threat-map geolocation
│   ├── vscanner/                            # V-8 Scanner: orchestrates OWASP ZAP / Nikto / Nmap
│   └── utils/                                # Shared helpers, logging, Arabic text support
│
├── docker/Dockerfile               # Multi-stage build, headless/server mode
├── docker-compose.yml
├── .dockerignore
├── .env.example                    # Every real HORUS_* / ANTHROPIC_API_KEY env var, documented
│
├── tests/                          # pytest suite — see docs/TESTING.md
├── scripts/                         # CI verification scripts (import check, DB init, Flask boot)
│                                    #   + benchmark/ subfolder, see docs/SCANNER_PIPELINE.md
│
├── docs/                            # You are here
├── .github/workflows/main.yml       # CI pipeline
│
├── installer/                        # NSIS Windows installer script
├── HorusShield.spec                   # PyInstaller build spec
├── build_exe.bat, run.bat             # Windows convenience scripts
│
├── README.md, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, LICENSE
├── .gitignore, .flake8, pyproject.toml
```

## Module dependency direction

`api/` depends on everything below it (`ai/`, `database/`, `engine/`, `services/`, `vscanner/`) — never the reverse. `database/db_manager.py` is the single point of SQL access; no other module talks to SQLite directly. `config.py` has no dependencies on any other HorusShield module, so it can be imported anywhere without circular-import risk.

`app.py` is the only place that imports and wires together every engine (`NetworkMonitor`, `DeviceBlocker`, `LockdownManager`, `HoneypotManager`, `MeshDefense`, `VScannerManager`, AI trainer). Two different injection patterns are used to hand those instances to blueprints, and neither is used consistently everywhere:

- `current_app.extensions['device_blocker']` (Flask's own recommended pattern) — used by `routes_devices.py` for block/unblock, with a fallback to writing the DB directly if the extension isn't registered.
- A module-level `set_manager()` function called once from `app.py` — used by `routes_vscanner.py`.

Several other blueprints (`routes_attacks.py`, `routes_honeypot.py`, `routes_mesh.py`) don't reach an engine instance through either pattern — they only read pre-computed data back out of the database, so they don't need one. This is a reasonable design, but the two DI mechanisms coexisting without a documented rule for which to use where is worth standardizing on one pattern going forward (see the final audit report's maintainability notes).
