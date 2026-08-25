# Installation

Three ways to get HorusShield running: from source, as a Windows EXE, or via Docker. Full deployment detail (including Docker networking/volumes) is in [`DEPLOYMENT.md`](DEPLOYMENT.md) — this page is just "get it running."

## From Source (any OS)

```bash
git clone <repo-url>
cd HorusShield_2.0
pip install -r backend/requirements.txt
cp .env.example .env    # optional but recommended — see below
cd backend
python app.py
```

- **Windows**: this opens a native desktop window automatically.
- **Linux/Mac**: pywebview needs a GUI toolkit not covered here for a from-source run; set `HORUS_HEADLESS=true` and open `http://127.0.0.1:5050` in a browser instead:
  ```bash
  export HORUS_HEADLESS=true
  python app.py
  ```

### Minimum config

Nothing is strictly required to start — every setting has a working default. For anything beyond local testing, at minimum set:

```bash
# in .env
HORUS_SECRET_KEY=<a real random value>
```

Without it, a key is auto-generated and saved to `backend/.horus_secret` on first run — fine for local dev, not for anything you'll redeploy or share.

## Windows EXE

```bat
pip install -r backend\requirements.txt
pip install pyinstaller pillow
build_exe.bat
```

Produces `dist\HorusShield.exe` — double-click to run, no Python install needed on the target machine.

## Docker

```bash
cp .env.example .env
docker compose up --build
```

Dashboard at `http://localhost:5050`. See [`DEPLOYMENT.md`](DEPLOYMENT.md) for volumes, network-capture capabilities, and the optional ZAP service.

## V-8 Scanner's External Tools

V-8 Scanner orchestrates three separate tools it doesn't bundle — install what you want to use:

| Tool | Install | Config |
|---|---|---|
| Nmap | `apt install nmap` / `brew install nmap` / [nmap.org](https://nmap.org/download.html) | `HORUS_NMAP_PATH` (default: `nmap` on PATH) |
| Nikto | `apt install nikto` / [github.com/sullo/nikto](https://github.com/sullo/nikto) | `HORUS_NIKTO_PATH` (default: `nikto` on PATH) |
| OWASP ZAP | Run as a daemon: `zap.sh -daemon -port 8090 -config api.key=<key>` — or via `docker compose --profile vscanner up` | `HORUS_ZAP_URL`, `HORUS_ZAP_KEY` |

A scan still runs with whatever subset of these three is available — a missing tool logs a warning for that stage and the scan continues with the rest.

## Verifying It Worked

```bash
curl http://127.0.0.1:5050/api/health
# {"status": "online", ...}
```

Or just open the dashboard in a browser and confirm the panels populate.
