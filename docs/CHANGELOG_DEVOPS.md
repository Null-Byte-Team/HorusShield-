# DevOps Layer — Changelog

This documents what was added in the DevOps pass: Docker support, CI, automated tests, and the code-quality tooling. Per the task's own rules, nothing about the UI, AI architecture, V-8 Scanner architecture, or database schema was redesigned — the few application-code changes below were required to make the new capabilities (Docker, CI) actually work, or were real bugs the new test suite caught while being written.

## New capabilities (purely additive)

- **Docker**: `docker/Dockerfile` (multi-stage), `docker-compose.yml`, `.dockerignore`
- **CI**: `.github/workflows/main.yml` — lint, unit tests, DB-init check, Flask-boot check, Docker build+healthcheck, optional Windows EXE build
- **Tests**: `tests/` — 36 pytest tests against a throw-away database
- **Code quality**: `pyproject.toml` (black/isort config), `.flake8`
- **Env config**: `.env.example` documenting every real `HORUS_*` variable the code reads
- **Docs**: this folder, plus `docs/DEPLOYMENT.md` and `docs/TESTING.md`

## Application-code changes and why

These were necessary for Docker/headless mode to exist at all, or are bugs the new tests caught — not style changes.

1. **`backend/app.py`** — added an opt-in `HORUS_HEADLESS=true` path that skips the native pywebview window and keeps the Flask/Socket.IO server in the foreground instead; made the `import webview` lazy (only imported when NOT headless) so the Docker image doesn't need GTK/Qt installed. Default behavior (desktop app) is unchanged.
2. **`backend/config.py`** — `HOST`, `PORT`, `DEBUG`, `LOG_LEVEL`, `LOG_FILE` are now overridable via `HORUS_*` env vars (same defaults as before if unset); added `.env` auto-loading via `python-dotenv` if present.
3. **`backend/database/models.py`** — `DB_DIR`/`DB_PATH` now respect `HORUS_DB_PATH` if set (previously hardcoded relative to the source tree, which doesn't work with a mounted Docker volume). Default behavior is unchanged if the variable isn't set.
4. **`backend/api/routes_vscanner.py`** — `_validate_target_url()` was accepting hostnames containing spaces/invalid characters (e.g. `"not a url!!"`) because `urllib.parse` doesn't validate hostname *content*, only splits the string. Caught by `test_vscan_start_rejects_malformed_url`; fixed with an explicit hostname-format check.
5. **`backend/examples_horus_ai.py`** — imported `ai.horus_assistant`, which doesn't exist (it lives in `services.horus_assistant`). Caught by `scripts/check_imports.py`. One-line fix.
6. **`backend/services/report_generator.py`** and **`backend/services/vscan_report_generator.py`** — three real, previously-undetected bugs, all caught by `test_reports.py`:
   - Both PDF generators used an em-dash (`—`) in static header/footer text. FPDF2's default core font only supports Latin-1, so **every PDF report — main daily report and V-8 Scanner report alike — crashed on generation** before this fix. Changed to ASCII hyphens in the specific static strings.
   - Added `utils.helpers.pdf_safe_text()` — report content includes network-derived, effectively attacker-controlled data (device hostnames, honeypot-captured usernames, scanned page content), so a single unexpected Unicode character anywhere in that data could crash a report the same way. `HorusPDF` in `report_generator.py` now sanitizes centrally via a `cell()`/`multi_cell()` override; `V8PDF` in `vscan_report_generator.py` sanitizes at its `kv_row()`/`finding_block()`/`header()` call sites.
   - `V8PDF.kv_row()` called `multi_cell()` without `new_x`/`new_y`, so fpdf2's default (`new_x=XPos.RIGHT`) left the cursor at the page's right edge instead of the left margin — the *second* `kv_row()` call in any report would fail with "Not enough horizontal space to render a single character". Fixed by passing `new_x=XPos.LMARGIN, new_y=YPos.NEXT` explicitly.
7. **`backend/ai/security_scorer.py`** — moved the risky-port list and score penalty constants into `config.py` (`SCORE_RISKY_PORTS`, `SCORE_PENALTY_PER_RISKY_PORT`, `SCORE_PENALTY_PER_ACTIVE_ATTACK`) so they're tunable without a code change, matching this task's "AI settings belong in config.py" requirement. Same values, same behavior.

## Known limitations, disclosed rather than hidden

- **Docker build was not actually run end-to-end** — this environment has no Docker daemon available. The Dockerfile/compose file were validated by: confirming every `COPY` source path exists, YAML-syntax-checking `docker-compose.yml`, and reasoning through the multi-stage build manually. It has not been proven to build and run on real Docker. Please run `docker compose up --build` yourself and report back if anything's off.
- **`black --check`/`flake8` against the existing `backend/` codebase report ~50 files that don't match black's style.** Rather than mass-reformat working code (which every task in this project has explicitly ruled out), CI runs those checks against `backend/` in **report-only** mode (visible in logs, doesn't fail the build) and enforces them strictly only on the new `tests/`/`scripts/` code. If a full reformat is ever wanted, it should be its own deliberate, reviewed change — not a side effect of adding CI.
- **V-8 Scanner's ZAP/Nikto/Nmap integration has no automated tests** — those are external tools/daemons not installed in CI. `vscanner/orchestrator.py`, `zap_client.py`, `nikto_runner.py`, `nmap_runner.py` are untested by this suite; testing them meaningfully would need a mocked ZAP daemon or the real binaries available in CI.
- **Windows EXE build in CI is best-effort** (`continue-on-error: true`) — pywebview's Windows GUI dependencies may or may not be fully present on the `windows-latest` GitHub-hosted runner; this wasn't verified against a real GitHub Actions run, only reasoned through.
