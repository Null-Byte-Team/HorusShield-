# Architecture

## System Diagram

```mermaid
flowchart TB
    subgraph Client["Client"]
        UI["HorusShield_UI.html<br/>(single-file frontend)"]
    end

    subgraph Backend["Flask + Socket.IO Backend (backend/app.py)"]
        API["API Blueprints<br/>(api/routes_*.py)"]
        AUTH["Auth<br/>(auth/auth_manager.py)"]
        DB["Database Layer<br/>(database/db_manager.py)"]

        subgraph Engines["Background Engines"]
            NETMON["Network Monitor +<br/>Packet Analyzer"]
            ATKDET["Attack Detector"]
            BLOCKER["Device Blocker"]
            LOCKDOWN["Lockdown Manager"]
            HONEYPOT["Honeypot Listeners<br/>(SSH/HTTP/FTP/Telnet)"]
            MESH["Mesh Defense"]
        end

        subgraph AI["AI Layer"]
            SCORER["Security Scorer"]
            CLASSIFIER["Threat Classifier"]
            PREDICTOR["Attack Predictor"]
            HORUS["Horus AI Assistant<br/>(Claude API + rule-based fallback)"]
        end

        subgraph V8["V-8 Scanner"]
            ORCH["Orchestrator"]
            CORTEX["AI Cortex<br/>(dedup/classify/score/explain)"]
        end
    end

    subgraph External["External Tools (V-8 Scanner orchestrates, doesn't reimplement)"]
        ZAP["OWASP ZAP daemon"]
        NIKTO["Nikto"]
        NMAP["Nmap"]
    end

    SQLITE[("SQLite<br/>backend/database/horus.db")]

    UI <--HTTP + WebSocket--> API
    API --> AUTH
    API --> DB
    API -.injected via<br/>app.extensions /<br/>set_manager().-> Engines
    API --> AI
    API --> V8
    Engines --> DB
    AI --> DB
    ORCH --> ZAP
    ORCH --> NIKTO
    ORCH --> NMAP
    ORCH --> CORTEX
    CORTEX --> DB
    DB --> SQLITE
```

## Two Run Modes, One Codebase

| | Desktop / EXE | Docker / Headless |
|---|---|---|
| Entry point | `backend/app.py` → `webview.create_window()` | `backend/app.py` → `HORUS_HEADLESS=true` branch |
| UI delivery | Native pywebview window pointed at local Flask | Browser, pointed at exposed port |
| `HORUS_HOST` | `127.0.0.1` (fixed, local-only) | `0.0.0.0` (set by `docker-compose.yml`) |
| Network capture | Full (scapy has OS-level access) | Requires `--cap-add=NET_ADMIN --cap-add=NET_RAW` opt-in |

Both modes run the exact same `create_app()` and the exact same `HorusShield_UI.html` — there is no separate "server build."

## Request Flow (typical)

1. Browser/webview loads `HorusShield_UI.html` from `GET /`.
2. The page's JS polls REST endpoints (`/api/dashboard/stats`, etc.) and opens a Socket.IO connection for live events (`vscan_progress`, `mesh_update`, `honeypot_event`, ...).
3. API blueprints read/write through `database/db_manager.py` — no blueprint talks to SQLite directly.
4. Background engines (network monitor, attack detector, honeypot, mesh) run on daemon threads started once in `create_app()`, writing findings to the DB and emitting Socket.IO events as they go.
5. V-8 Scanner is different: it's *on-demand*, not a background loop. `POST /api/vscanner/scan/start` spins up one thread that runs Nmap → ZAP → Nikto in sequence, then hands raw findings to the AI Cortex before persisting.

## Data Flow: V-8 Scanner Specifically

```
Target URL
    │
    ▼
Nmap (service/version recon, default+safe scripts only)
    │
    ▼
OWASP ZAP (spider → passive scan → [optional, opt-in] active scan)
    │
    ▼
Nikto (web-server misconfiguration checks)
    │
    ▼
AI Cortex: normalize → deduplicate → classify (OWASP/CWE) →
           confidence-score → prioritize → explain
    │
    ▼
SQLite (vscans / vscan_findings / vscan_reports tables)
    │
    ▼
Report Generator → PDF / HTML / JSON
```

Full detail: [`SCANNER_PIPELINE.md`](SCANNER_PIPELINE.md).

## Why SQLite, not Postgres/MySQL

HorusShield is a single-instance desktop/small-deployment tool, not a multi-tenant SaaS — one HorusShield process per network/site, one database file. SQLite's WAL mode handles the concurrent read/write pattern here (multiple background engine threads + API requests) without needing a separate DB server to install/manage, which matters for a tool that's meant to be usable by a school or small business without a dedicated ops person. This is a reasonable choice for the current scope; it would need to change if HorusShield ever became a multi-site, centrally-managed product — see the Scalability notes in the final audit report.
