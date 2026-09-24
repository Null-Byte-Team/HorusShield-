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
| Nikto | Install Nikto and a Perl runtime (Strawberry Perl is supported on Windows) | `HORUS_NIKTO_PATH`, `HORUS_PERL_PATH` |
| OWASP ZAP | Install ZAP; HorusShield can start `zap.bat` in daemon mode on Windows | `HORUS_ZAP_URL`, `HORUS_ZAP_KEY`, `HORUS_ZAP_PATH` |

### Windows V-8 scanner setup

HorusShield resolves tools in this order: an explicit path environment variable,
the executable/script on `PATH`, then standard `Program Files` locations. Set
these variables when the app is started from an IDE or packaged EXE with a
different `PATH`:

```text
HORUS_NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
HORUS_PERL_PATH=C:\Strawberry\perl\bin\perl.exe
HORUS_NIKTO_PATH=C:\Nikto\program\nikto.pl
HORUS_ZAP_PATH=C:\Program Files\ZAP\Zed Attack Proxy\zap.bat
HORUS_ZAP_AUTOSTART=true
```

Nikto is launched as `perl.exe <absolute nikto.pl path>` with Nikto's directory
as its working directory. ZAP is launched with `zap.bat -daemon`; HorusShield
waits for `/JSON/core/view/version/` before scanning and cleans up only a ZAP
process it started. A separately running daemon is reused.

The authenticated `GET /api/vscanner/tools` endpoint returns boolean
availability in `tools` and diagnostic version/runtime/path information in
`details`. It does not expose the process environment or command-line secrets.

Manual checks from the same terminal used to start HorusShield:

```powershell
nmap --version
perl -v
perl C:\Nikto\program\nikto.pl -Version
C:\Program Files\ZAP\Zed Attack Proxy\zap.bat -version
```

Common errors are actionable: missing Java prevents ZAP startup, missing Perl
prevents Nikto, and a ZAP startup timeout means its API never became ready.
The current machine must have Java, Perl, and the relevant tool installed;
HorusShield cannot install these runtimes automatically.

A scan still runs with whatever subset of these three is available — a missing tool logs a warning for that stage and the scan continues with the rest.

## Verifying It Worked

```bash
curl http://127.0.0.1:5050/api/health
# {"status": "online", ...}
```

Or just open the dashboard in a browser and confirm the panels populate.
