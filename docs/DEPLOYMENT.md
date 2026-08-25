# HorusShield 2.0 — Deployment Guide

Team NullByte · WE School · Alexandria 🇪🇬

HorusShield ships two genuinely different ways to run: the original **desktop app** (a native pywebview window — this is what the Windows EXE is), and a **headless server mode** added for Docker/Linux deployments. Both run the exact same Flask backend and the exact same `HorusShield_UI.html` — headless mode just serves it over HTTP to a normal browser instead of opening a native window.

---

## 1. Windows (Desktop App / EXE)

This is unchanged from before.

```bat
pip install -r backend\requirements.txt
pip install pyinstaller pillow
build_exe.bat
```

Produces `dist\HorusShield.exe`. Run it directly — it opens its own native window (no browser needed).

For development without building an EXE:

```bat
cd backend
python app.py
```

## 2. Linux (Headless / Source)

Linux has no pywebview GUI story here, so run headless and open the dashboard in a browser:

```bash
cd backend
pip install -r requirements.txt
export HORUS_HEADLESS=true
export HORUS_HOST=127.0.0.1   # or 0.0.0.0 to allow LAN access — see security note below
python app.py
```

Then open `http://127.0.0.1:5050` in a browser.

> **Security note:** `HORUS_HOST` defaults to `127.0.0.1` (local-only) deliberately. Only set it to `0.0.0.0` if you understand you're exposing the dashboard — and its device-blocking/lockdown controls — to your network.

## 3. Docker (recommended for servers/NAS/Raspberry Pi)

```bash
cp .env.example .env
# edit .env — at minimum set HORUS_SECRET_KEY to a real random value
docker compose up --build -d
```

Dashboard: `http://localhost:5050` (or whatever `HORUS_PORT` you set in `.env`).

**What's persisted:** the `horus_data` volume holds the SQLite database and logs; `horus_reports` holds generated PDF/HTML/JSON reports. Both survive `docker compose down` and image rebuilds.

**Network monitoring inside Docker:** HorusShield's packet capture (scapy) needs raw-socket access, which a container doesn't have by default. `docker-compose.yml` has this commented out on purpose so `docker compose up` works out of the box without elevated privileges:

```yaml
# cap_add:
#   - NET_ADMIN
#   - NET_RAW
# network_mode: host
```

Uncomment those three lines if you want HorusShield to actually see your host's network traffic. Without them, the app still runs fine — the network-monitoring panels just won't show live traffic, the same as a permission-denied case on the desktop app.

**V-8 Scanner's OWASP ZAP integration:** an optional `zap` service is included, off by default. Start it alongside HorusShield with:

```bash
docker compose --profile vscanner up -d
```

Then set `HORUS_ZAP_URL=http://zap:8090` in `.env` so HorusShield can reach it. Nikto and Nmap are *not* bundled in the image (see the architecture note below) — install them on the host and set `HORUS_NIKTO_PATH`/`HORUS_NMAP_PATH` to reach them, or run V-8 Scanner from a non-Docker deployment where those tools are directly on PATH.

### Updating

```bash
docker compose down
docker compose up --build -d
```

The database volume is untouched by this — your data survives.

### Logs

```bash
docker compose logs -f horusshield
```

Or from the host, since logs are also written into the `horus_data` volume:

```bash
docker compose exec horusshield tail -f /data/logs/horus.log
```

---

## 4. Configuration Reference

Every environment variable HorusShield actually reads is documented in [`.env.example`](../.env.example) at the project root, with a comment on what it does and which module reads it. Copy it to `.env` and fill in real values — never commit `.env` itself.

---

## 5. Rolling Back

Both the desktop EXE and the Docker image are just builds of the same source tree — if a deployment misbehaves, rebuild from a previous git commit/tag rather than hand-editing a running deployment. The database schema is additive-only across the versions in this repo's history (new tables, no destructive migrations), so an older EXE/image can generally still read a newer database, though the reverse (opening a newer database with a much older build) isn't tested.
