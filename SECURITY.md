# Security Policy

HorusShield 2.0 · Team NullByte · WE School, Alexandria 🇪🇬

## Reporting a Vulnerability

If you find a security vulnerability in HorusShield, please report it responsibly rather than opening a public GitHub issue.

**How to report:**
1. Open a private security advisory on this repository (GitHub → Security → Advisories → "Report a vulnerability"), if enabled, **or**
2. Contact a Team NullByte maintainer directly, in private, with details.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce it (proof-of-concept code is welcome)
- The affected version/commit
- Your suggested severity, if you have one

**What to expect:**
- We'll acknowledge your report and work on a fix as time allows — this is a student project maintained by a small team, not a company with an SLA, so please be patient.
- We'll credit you in the fix's changelog/commit unless you ask us not to.
- Please give us a reasonable window to ship a fix before disclosing publicly.

## Responsible Disclosure

We ask that you:
- **Do not** access, modify, or exfiltrate data belonging to other users while testing.
- **Do not** run V-8 Scanner, or any other HorusShield feature, against systems you don't own or have explicit authorization to test — the same rule the tool itself enforces (V-8 Scanner's active-scan mode requires explicit opt-in confirmation for exactly this reason).
- **Do not** publicly disclose a vulnerability before a fix is available, or before a reasonable disclosure window has passed (we suggest 90 days as a default, shorter for actively-exploited issues, longer if we're actively working with you on a fix).
- Test only against your own local/self-hosted instance, not a production deployment you don't control.

## Scope

**In scope:**
- The Flask backend (`backend/`) — auth, API endpoints, database layer, AI modules, V-8 Scanner orchestration
- The frontend (`HorusShield_UI.html`)
- The Docker image and `docker-compose.yml`
- The CI/CD pipeline (`.github/workflows/`)

**Out of scope:**
- Vulnerabilities in third-party tools HorusShield orchestrates but doesn't implement (OWASP ZAP, Nikto, Nmap) — report those upstream to their own projects.
- Vulnerabilities requiring physical access to a machine already running HorusShield.
- Social engineering.

## Red Team Review Fixes (this pass)

A structured Red Team review found and confirmed (live, not theoretically) several issues, all fixed and re-verified live in this pass:

- **SSRF (Critical)** — V-8 Scanner accepted `127.0.0.1`, RFC1918 ranges, and the cloud metadata endpoint (`169.254.169.254`) as scan targets. Fixed via `backend/security/ssrf.py`: resolves the hostname and rejects any target whose resolved IP is private/loopback/link-local/multicast/reserved, re-validated immediately before each tool runs (not only at submission time).
- **IDOR (High)** — any authenticated user could read and delete any other user's V-8 Scanner data. Fixed: scans now have a real `owner_id`, checked on every read/write; non-owners get 403, admins can access everything.
- **Default admin role (High)** — every new signup got full admin access. Fixed: only the first account ever registered in a database becomes admin automatically; every account after that defaults to `analyst`.
- **Audit log IP spoofing (Medium)** — every audit-log write trusted `X-Forwarded-For` unconditionally. Fixed via `backend/utils/network.py`: ignored by default (`request.remote_addr` used instead); only trusted if `HORUS_TRUST_PROXY=true` is explicitly set for a real reverse-proxy deployment.
- **Registration/resend-code enumeration (Medium)** — both endpoints revealed whether an email was already registered. Fixed: both now return the same generic response regardless.
- **Verification endpoint rate limiting (Medium)** — the 6-digit code endpoint had no endpoint-specific limit. Fixed: added both a per-IP limit and a per-account lockout after repeated failures.
- **CORS wildcard as a coded default (Low)** — fixed: environment-driven allowlist that fails closed on `*` even if explicitly requested via env var.
- **Rate-limit storage (Medium)** — was in-memory only. Fixed: optional Redis backing with automatic, verified graceful fallback to in-memory if Redis is unreachable.
- **Security headers** — added CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and conditional HSTS to every response.
- **Dependency vulnerabilities** — a `pip-audit` scan found 10 known CVEs across 6 packages (Flask, flask-cors ×3, requests, scapy, python-dotenv, dnspython); all fixed by upgrading to patched versions and re-verified with a clean `pip-audit` scan.



A few things that might look like issues on first read but are deliberate:

- **`HORUS_HOST` defaults to `127.0.0.1`** (local-only), never `0.0.0.0`, unless explicitly overridden — this is intentional so the dashboard (which includes device-blocking and network-lockdown controls) isn't accidentally exposed to a LAN.
- **V-8 Scanner's active scan mode is off by default** and requires an explicit `authorized_confirmation` flag — HorusShield does not implement its own exploit/payload logic; it orchestrates OWASP ZAP, Nikto, and Nmap, all of which have their own safety controls.
- **The Docker image does not request `NET_ADMIN`/`NET_RAW` capabilities by default** — real network packet capture requires explicitly opting in via `docker-compose.yml`, so the container has no elevated network privileges out of the box.

## Secret Handling

- No secrets are hardcoded in source. Every credential (Flask secret key, SMTP password, Google OAuth client ID, ZAP API key, Anthropic API key) is read from an environment variable — see `.env.example` for the complete list.
- `SECRET_KEY` is auto-generated and persisted to a local, gitignored file (`backend/.horus_secret`) on first run if `HORUS_SECRET_KEY` isn't set — this file must never be committed or shared. For any real deployment (Docker included), set `HORUS_SECRET_KEY` explicitly.
- Passwords are hashed with PBKDF2-HMAC-SHA256 (200,000 iterations) with a per-user salt — see `backend/auth/auth_manager.py`. Passwords are never stored or logged in plaintext.
