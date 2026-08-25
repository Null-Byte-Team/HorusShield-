# Security Architecture

This documents HorusShield's actual, current security posture — every claim below is checked against the real code (file/line references included) or verified live via `scripts/smoke_test_auth.py`, not aspirational. For the full list of what was found and fixed to get here, and what's still outstanding, see the audit reports in the project history; this doc describes the end state.

---

## Authentication Flow

**Mechanism**: Bearer tokens, never cookies. `auth/auth_manager.py` issues a token on successful login, stored client-side in `localStorage` (`hs_token`, see `HorusShield_UI.html`) and sent as `Authorization: Bearer <token>` on every subsequent request.

```
POST /api/auth/register  {email, password, name}
   -> creates user (role='admin' by DB default — see Authorization below),
      is_verified=0, generates a verification code
   -> if HORUS_SMTP_* isn't configured, the code is returned directly in
      the response as `dev_code` (dev-mode fallback) instead of emailed —
      this is real, current behavior, not a bug to hide
        |
        v
POST /api/auth/verify  {email, code}
   -> is_verified=1
        |
        v
POST /api/auth/login  {email, password}
   -> validates password (PBKDF2-HMAC-SHA256, 200,000 iterations, unique
      salt per user — auth/auth_manager.py's _hash_password/_verify_password)
   -> rejects with EMAIL_NOT_VERIFIED if is_verified=0
   -> on success: issues a session token (auth_sessions table), returns it
        |
        v
Every subsequent request: Authorization: Bearer <token>
   -> auth/decorators.py's login_required validates it via
      auth_manager.validate_token() (joins auth_sessions -> users,
      checks expiry)
```

Google Sign-In (`POST /api/auth/google`) follows the same shape, verifying a Google ID token server-side instead of a password.

**Why not sessions/cookies**: a single-process desktop-first app didn't need cookie-based sessions, and Bearer tokens sidestep classic CSRF entirely (see Threat Model below) since nothing is attached to a request automatically by the browser.

## Authorization Flow

Three decorators, one shared implementation (`auth/decorators.py`), used consistently across every blueprint — no blueprint reimplements its own auth check:

| Decorator | Requires | Used for |
|---|---|---|
| `login_required` | any valid token | Dashboard, device/attack lists, reports listing, honeypot/mesh status, AI predictions, Horus chat, V-8 Scanner read endpoints |
| `analyst_required` | token + `role` in `{admin, analyst}` | Device block/unblock/trust, V-8 Scanner start/stop/delete, report generation, attack mitigation |
| `admin_required` | token + `role == admin` | Terminal (all operations), settings changes, AI training trigger, SMTP/Google OAuth config, audit log |

**Role model**: `users.role` (schema, `database/models.py`) defaults to `'admin'` — every account created before this authorization model existed, and every account created since, defaults to full access unless explicitly given a lower role directly in the database. This was a deliberate choice to avoid locking out existing users when authorization was first enforced, not an oversight — see `auth/decorators.py`'s module docstring.

Authorization *denials* (valid token, wrong role) are distinct from authentication failures (no/invalid token) and are separately audit-logged as `authorization_denied` with the username, role, endpoint, and IP — see `database/db_manager.py`'s `add_audit_log`.

## Rate Limiting

`flask-limiter`, one shared instance (`api/rate_limit.py`), configurable limits in `config.py` — never hardcoded inline at the call site:

| Endpoint category | Limit | Config key |
|---|---|---|
| Login / register / Google sign-in | 5 (login) / 3 (register) per minute | `RATELIMIT_LOGIN`, `RATELIMIT_REGISTER` |
| V-8 Scanner start | 10/min | `RATELIMIT_SCANNER` |
| AI training trigger | 20/min | `RATELIMIT_AI` |
| Report generation | 10/min | `RATELIMIT_REPORTS` |
| Terminal | 15/min | `RATELIMIT_TERMINAL` |
| Settings changes | 30/min | `RATELIMIT_SETTINGS` |
| Everything else | 200/min | `RATELIMIT_DEFAULT` |

Storage is in-memory by default (`RATELIMIT_STORAGE_URI=memory://`) — fine for HorusShield's single-process deployment model, but means limits reset on restart and don't share state across multiple processes. For a multi-process deployment, set `HORUS_RATELIMIT_STORAGE` to a shared store (e.g. Redis) instead. Exceeding a limit returns `429` with a standardized JSON body (see API Security below).

## Terminal Security

`/api/terminal/run` was rewritten from a blocklist-filtered arbitrary-command-execution endpoint to a strict allowlist (`api/routes_terminal.py`):

- **Nine fixed operations** (`ipconfig`, `netstat`, `systeminfo`, `tasklist`, `whoami`, `hostname`, `arp`, `route`, `ping`), each mapped to a hardcoded argv list per OS (`_windows_args`/`_linux_args`) — nothing outside `OPERATIONS` is executable, by construction.
- **`shell=False`** on every `subprocess.run()` call — argv lists only, never a shell string, so there is no shell-metacharacter injection surface at all.
- **The one parameterized operation** (`ping`'s target) is validated against a strict hostname/IPv4-shaped regex before it ever reaches the argv list — `8.8.8.8; rm -rf /` is rejected with 400, not sanitized-and-run.
- **`admin_required`**, and every execution — allowed or rejected — writes to the audit log with timestamp, user, IP, operation, target, and result (`_audit()` in the same file).
- **Rate limited** (15/min) to blunt any residual DoS/brute-force-probing risk.

`GET /api/terminal/operations` lets the frontend build its command list from the actual allowlist rather than hardcoding a matching copy that could drift out of sync.

## Threat Model

**In scope / actively defended against:**
- Unauthenticated access to any state-changing or sensitive-read endpoint (Authentication/Authorization above)
- Command injection via the terminal (Terminal Security above)
- SQL injection — audited: every dynamic query in `database/db_manager.py` builds column *names* from a hardcoded allowlist and passes all *values* as parameterized `?` placeholders; there is no string-formatted SQL value anywhere in the codebase
- Path traversal in file downloads (`utils/validation.py`'s `safe_join_and_verify` — `os.path.basename()` first, then a resolved-path containment check as a second, independent layer)
- Oversized-payload DoS (`config.MAX_CONTENT_LENGTH`, 5 MB default, enforced by Flask)
- Brute-force login (rate limiting above)
- Cross-origin request forgery against the local API from a malicious webpage (see below)

**Deliberately out of scope / accepted risk:**
- Classic form/cookie CSRF — doesn't apply; there are no cookies to ride on (see below)
- Network-level attacks against the host OS itself — outside an application's threat model
- Compromise of the OWASP ZAP/Nikto/Nmap binaries themselves — HorusShield trusts these as legitimate external tools, per V-8 Scanner's explicit non-goal of reimplementing their logic
- Multi-tenant isolation — HorusShield is a single-instance-per-deployment tool; every authenticated user with a role can see that instance's whole picture

**Why classic CSRF protection (anti-CSRF tokens) is absent, and why that's correct here, not an oversight**: CSRF exploits the browser automatically attaching ambient credentials (cookies) to a forged cross-site request. HorusShield never uses cookies for auth — every request needs an explicit `Authorization: Bearer <token>` header that a malicious page cannot set without already having the token (which would require a separate compromise, e.g. XSS, not CSRF). The actual equivalent risk that existed here was `CORS_ORIGINS = ["*"]` as the *default* (inherited by `DevelopmentConfig`, which is what runs unless `HORUS_ENV=production` is explicitly set) combined with endpoints that had no auth check — together, those meant any webpage a user's browser visited could call `127.0.0.1:5050/api/terminal/run` directly. Both halves of that are now fixed: CORS defaults to `127.0.0.1`/`localhost` only (`config.py`), and every endpoint requires authentication.

## API Security

- **Standardized error responses** (`app.py`'s `errorhandler`s): every 400/401/403/404/413/429/500 returns the same JSON shape (`{"error": "...", "status": N}`); a catch-all `Exception` handler ensures no stack trace ever reaches a client — full detail still goes to the server log.
- **Input validation** (`utils/validation.py`): shared helpers for email, hostname, IPv4/IPv6, port, URL, filename, positive int, bool, enum, and string-length — used by the endpoints that previously had none (settings key format, AI training-type enum, Horus chat query length, device-block reason length, report-filename traversal defense). V-8 Scanner's and the terminal's own existing validation (`routes_vscanner.py`, `routes_terminal.py`) were left as-is per the standing "don't modify already-verified features" rule — see Validation Rules below for the full picture.
- **CORS**: restricted to `127.0.0.1`/`localhost` on the configured port by default (see Threat Model).

## Validation Rules

| Input | Validated by | Rule |
|---|---|---|
| Email | `auth_manager.register()` (existing) | Format check + uniqueness |
| Password | `auth_manager.register()` (existing) | Minimum 8 characters |
| V-8 Scanner target URL | `routes_vscanner.py`'s `_validate_target_url()` (existing) | `urllib.parse` + strict hostname regex — rejects malformed hosts like `"not a url!!"` |
| Terminal ping target | `routes_terminal.py`'s `_HOST_RE` (existing) | Strict hostname/IPv4 shape, no shell metacharacters |
| Settings key | `utils/validation.py` via `_SETTING_KEY_RE` in `routes_settings.py` | `^[a-z][a-z0-9_]{0,63}$` — pattern, not a hardcoded enum, since keys are set from several places in the codebase |
| AI training type | `routes_ai.py` | Strict enum: `history` or `synthetic` only |
| Horus chat query | `utils/validation.py`'s `validate_string` | Required, max 2000 chars |
| Horus chat language | `routes_horus.py` | Strict enum: `en` or `ar` |
| Device block reason | `utils/validation.py`'s `validate_string` | Max 300 chars |
| Report filename (download) | `utils/validation.py`'s `safe_join_and_verify` | Two-layer path-traversal defense |
| Request body size (all endpoints) | Flask's `MAX_CONTENT_LENGTH` | 5 MB default, configurable via `HORUS_MAX_CONTENT_LENGTH` |

Endpoints not listed here either take no user-supplied free-form input (e.g. `GET /api/dashboard/stats`) or use Flask's own URL converters (e.g. `<int:device_id>`, which 404s on anything non-integer before the view function even runs).
