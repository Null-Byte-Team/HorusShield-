# HorusShield 2.0
## Egyptian AI Cybersecurity Platform
### Team NullByte · WE School · Alexandria 🇪🇬

---

## OVERVIEW

HorusShield is a network security monitoring and assessment platform combining four things in one dashboard: real-time network/device monitoring with an attack detector, an AI layer (threat classification, anomaly detection, attack prediction, a Claude-backed security assistant), a honeypot + Mesh Defense subsystem, and **V-8 Scanner** — a web-application security assessment tool that orchestrates OWASP ZAP, Nikto, and Nmap (it does not implement its own exploit logic — see `docs/SCANNER_PIPELINE.md`).

It runs three ways from one codebase: a native Windows desktop app (EXE), from Python source, or in Docker — see [Architecture](docs/ARCHITECTURE.md) for how.

## SCREENSHOTS

_Add screenshots here before a competition/public release —_ `docs/screenshots/dashboard.png`, `docs/screenshots/v8-scanner.png`, `docs/screenshots/threat-map.png` _(placeholders — not yet captured)._

## EXAMPLE REPORTS

_Add a sample generated PDF here before a competition/public release —_ `docs/examples/sample-daily-report.pdf`, `docs/examples/sample-v8-scan-report.pdf` _(placeholders — not yet generated). To create real ones: `POST /api/reports/generate` for the daily report, or run a V-8 scan and `GET /api/vscanner/scan/<id>/report/pdf`._

---

## HOW TO RUN

### Option A — Python (Development)
```
cd backend
pip install -r requirements.txt
python app.py
```

### Option B — Double-click
Double-click `run.bat` in the project root.

### Option C — EXE
Double-click `dist/HorusShield.exe`

### Option D — Docker
```
cp .env.example .env    # set HORUS_SECRET_KEY at minimum
docker compose up --build
```
Then open `http://localhost:5050`. Full details, including how network monitoring and the V-8 Scanner's ZAP integration work in a container: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## BUILD EXE
```
pip install pyinstaller
pyinstaller HorusShield.spec --clean --noconfirm
```
Or run `build_exe.bat`

---

## TESTING

```
pip install pytest pytest-cov
pytest tests/ -v
```

Tests run against a throw-away database — the real `backend/database/horus.db` is never touched. See [`docs/TESTING.md`](docs/TESTING.md) for what's covered and how to add more.

---

## CONTINUOUS INTEGRATION

Every push/PR runs `.github/workflows/main.yml`, which:

1. Compiles every `.py` file and checks for broken imports
2. Lints/formats `tests/` and `scripts/` (black, isort, flake8 — blocking); reports the same for `backend/` without failing the build, since the existing app code is intentionally not being mass-reformatted (see [`docs/CHANGELOG_DEVOPS.md`](docs/CHANGELOG_DEVOPS.md) for why)
3. Runs the pytest suite
4. Verifies the database schema initializes cleanly from nothing
5. Actually boots `python app.py` headless and polls `/api/health`
6. Builds the Docker image and confirms its healthcheck passes
7. Best-effort builds the Windows EXE (advisory — doesn't block the pipeline)

Any of steps 1–6 failing fails the workflow.

---

## ARCHITECTURE & FOLDER STRUCTURE

```
HorusShield_2.0/
├── HorusShield_UI.html      # The entire frontend — one file, served by Flask
├── backend/
│   ├── app.py                # Entry point — desktop (pywebview) or headless (Docker)
│   ├── config.py              # All configuration, env-var driven
│   ├── ai/                    # Security scorer, threat classifier, V-8 Scanner AI Cortex
│   ├── api/                   # Flask blueprints — one routes_*.py per feature area
│   ├── auth/                  # Login, sessions, SMTP/Google sign-in
│   ├── database/               # SQLite schema (models.py) + access layer (db_manager.py)
│   ├── engine/                 # Network monitor, device blocker, lockdown, attack detector
│   ├── honeypot/                # SSH/HTTP/FTP/Telnet honeypot listeners
│   ├── mesh/                    # Mesh Defense graph engine
│   ├── services/                 # Report generators, Horus AI assistant, threat map
│   ├── vscanner/                  # V-8 Scanner — orchestrates OWASP ZAP / Nikto / Nmap
│   └── utils/                     # Shared helpers, logging
├── docker/Dockerfile           # Multi-stage build — headless/server mode only
├── docker-compose.yml
├── tests/                       # pytest suite (see docs/TESTING.md)
├── scripts/                      # CI verification scripts + benchmark/ harness
├── docs/                          # Full technical docs (see index below)
└── .github/workflows/main.yml     # CI pipeline
```

Full breakdown: [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md). System diagram: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## DOCUMENTATION INDEX

| Doc | Covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System diagram, request flow, why SQLite |
| [`docs/SECURITY_ARCHITECTURE.md`](docs/SECURITY_ARCHITECTURE.md) | Auth/authorization flow, rate limiting, terminal security, threat model, validation rules |
| [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | Every REST endpoint with its real auth requirement, grep-verified against the actual route code |
| [`docs/AI_PIPELINE.md`](docs/AI_PIPELINE.md) | Every ML model used, the security-score formula, Horus AI's two-tier design |
| [`docs/SCANNER_PIPELINE.md`](docs/SCANNER_PIPELINE.md) | V-8 Scanner's exact ZAP/Nikto/Nmap workflow and safety controls |
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Source / EXE / Docker install steps |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Production deployment, volumes, network capture in Docker |
| [`docs/TESTING.md`](docs/TESTING.md) | What's tested and why, including 3 real bugs the test suite caught |
| [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | Full folder layout and module dependency direction |
| [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md) | V-8 Scanner vs. raw ZAP/Nikto/Nmap comparison harness (empty until you run it) |
| [`docs/CHANGELOG_DEVOPS.md`](docs/CHANGELOG_DEVOPS.md) | Every DevOps-pass change and why, including bugs found |
| [`SECURITY.md`](SECURITY.md) | Responsible disclosure policy |

V-8 Scanner is an orchestration layer over OWASP ZAP, Nikto, and Nmap — it never generates its own exploit payloads; see `backend/vscanner/__init__.py` for the exact scope.

---

## ROADMAP

Not commitments, just honestly-labeled ideas for where this could go next:

- [ ] Enforce authentication on API endpoints beyond `/api/auth/me` (currently the biggest gap — see the audit report)
- [ ] Automated tests for `vscanner/` against real ZAP/Nikto/Nmap (needs those tools in CI)
- [ ] Replace the terminal endpoint's command blocklist with an allowlist, or remove the feature if it's not essential
- [ ] Standardize on one dependency-injection pattern for engine access from blueprints (currently two coexist — see `docs/PROJECT_STRUCTURE.md`)
- [ ] Real screenshots and example reports in this README
- [ ] Populate `docs/BENCHMARK_RESULTS.md` with actual run data

---

## LICENSE

MIT — see [`LICENSE`](LICENSE). Note that V-8 Scanner's orchestrated tools (OWASP ZAP, Nikto, Nmap) are separately licensed under their own projects' terms.

## CONTRIBUTING

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## FIX: Port busy (WinError 10048)
```powershell
Get-Process python | Stop-Process -Force
```
Then restart.

---

## ERROR: Invalid async_mode specified
**Fixed in this version.** Root cause was `ws.sio.async_mode = 'threading'`
being set AFTER SocketIO initialization — now removed.


