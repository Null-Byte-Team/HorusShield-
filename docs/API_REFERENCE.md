# API Reference

Generated directly from the route decorators in `backend/api/routes_*.py` — every endpoint listed here actually exists in the code, including its real auth requirement (verified during the security/audit pass, not hand-typed from memory). Base URL: `http://<host>:<port>/api`.

**Authentication**: every endpoint below requires `Authorization: Bearer <token>` except the ones explicitly marked `public` (the pre-login parts of `/api/auth` and `/api/health`). See `docs/SECURITY_ARCHITECTURE.md` for the full authentication/authorization flow, role model, and rate limits. The `Auth` column below is the actual decorator applied in code:

- `public` — no token required
- `login_required` — any authenticated user
- `analyst_required` — `admin` or `analyst` role
- `admin_required` — `admin` role only

---

## `/api/dashboard`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/stats` | login_required | Overview counts (devices, attacks, alerts, score) |
| GET | `/traffic/history` | login_required | Historical network traffic series |
| GET | `/score/history` | login_required | Security score over time |
| GET | `/alerts` | login_required | Recent alerts |

## `/api/devices`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | login_required | List all known devices |
| POST | `/clear` | analyst_required | Clear the device list (fresh scan) |
| GET | `/<id>` | login_required | Single device detail |
| POST | `/<id>/trust` | analyst_required | Mark a device trusted |
| POST | `/<id>/block` | analyst_required | Block a device — `{reason}` (max 300 chars) |
| POST | `/<id>/unblock` | analyst_required | Unblock a device |

## `/api/attacks`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | login_required | List detected attacks |
| GET | `/active` | login_required | Currently active attacks |
| GET | `/stats` | login_required | Attack statistics |
| POST | `/<id>/mitigate` | analyst_required | Trigger mitigation for an attack |

## `/api/ai`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/predictions` | login_required | Current attack predictions |
| GET | `/anomalies` | login_required | Detected anomalies |
| GET | `/train/status` | login_required | Training status + live progress (`{stage, percent, model}`) |
| GET | `/train/metadata` | login_required | Real training metrics history — `?model=threat_classifier\|attack_predictor\|anomaly_detector&limit=N` |
| POST | `/train` | admin_required, rate-limited 20/min | Trigger model (re)training — `{type: "history"\|"synthetic"}`, strict enum. Logs `ai_analysis` audit entry |

See `docs/AI_PIPELINE.md` for what each model actually reports and why some metrics are intentionally null for some model types.

## `/api/reports`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/generate` | analyst_required, rate-limited 10/min | Generate the main daily PDF report |
| GET | `/download/<filename>` | login_required | Download a previously generated report — two-layer path-traversal defense |
| GET | `/list` | login_required | List generated reports |

## `/api/honeypot`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/status` | login_required | Honeypot listener status |
| GET | `/events` | login_required | Captured honeypot interaction events |

## `/api/mesh`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/topology` | login_required | Mesh Defense graph topology |
| GET | `/nodes/critical` | login_required | Critical nodes in the mesh |

## `/api/settings`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | login_required | All settings |
| GET | `/<key>` | login_required | Single setting value — key must match `^[a-z][a-z0-9_]{0,63}$` |
| POST | `/toggle` | admin_required, rate-limited 30/min | Change a setting — logs `settings_changed` audit entry |

## `/api/horus` — Horus AI Assistant
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/ask` | login_required | Ask Horus a question — `{query (max 2000 chars), language: "en"\|"ar"}`. Claude API if `ANTHROPIC_API_KEY` set, rule-based fallback otherwise |
| GET | `/history` | login_required | Conversation history |
| POST | `/clear` | login_required | Clear conversation history |

## `/api/terminal`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/operations` | admin_required | The actual allowlist of runnable operations — frontend builds its command list from this |
| POST | `/run` | admin_required, rate-limited 15/min | Run one allowlisted operation — `{operation, target}`. Strict allowlist, `shell=False`, every execution audit-logged. See `docs/SECURITY_ARCHITECTURE.md`'s Terminal Security section — this was a critical vulnerability in an earlier version and has been completely redesigned |
| GET | `/shells` | admin_required | Legacy compatibility endpoint — shell selection no longer exists, returns platform info only |

## `/api/auth`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/register` | public, rate-limited 3/min | Create an account — role defaults to `admin` |
| POST | `/verify` | public | Verify an emailed (or dev-mode-returned) code |
| POST | `/resend-code` | public, rate-limited 5/min | Resend verification code |
| POST | `/login` | public, rate-limited 5/min | Log in — logs a `login` audit entry |
| GET | `/google/client-id` | public | Get configured Google OAuth client ID (needed pre-login for the sign-in button) |
| POST | `/google` | public, rate-limited 5/min | Google sign-in |
| POST | `/logout` | login_required | Log out — logs a `logout` audit entry |
| GET | `/me` | login_required | Current user |
| GET / POST | `/smtp/config` | admin_required | View/update SMTP settings (password always masked on GET) |
| POST | `/smtp/test` | admin_required | Send a test email |
| POST | `/google/client-id` | admin_required | Set Google OAuth client ID |

## `/api/vscanner` — V-8 Scanner
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/scan/start` | analyst_required, rate-limited 10/min | Start a scan — `{target_url, tools, active_scan, authorized_confirmation}` |
| POST | `/scan/<id>/stop` | analyst_required | Stop a running scan |
| GET | `/scan/<id>/status` | login_required | Scan status/progress |
| GET | `/scan/<id>` | login_required | Full scan details + findings (now including `correlation_group`/`correlated_with_tools`) + reports |
| DELETE | `/scan/<id>` | analyst_required | Delete a scan and its findings/reports |
| GET | `/history` | login_required | Scan history |
| GET | `/scan/<id>/report/<fmt>` | login_required | Generate + download a report (`pdf`/`html`/`json`) |

See `docs/SCANNER_PIPELINE.md` for the full workflow this drives, `docs/SECURITY_ARCHITECTURE.md`'s Validation Rules for input validation, `docs/AI_PIPELINE.md` for the AI Cortex including the new cross-tool correlation step.

## `/api/audit`
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/?limit=&action=&username=` | admin_required | Query the audit log — includes `login`, `logout`, `settings_changed`, `device_blocked`/`unblocked`, `terminal_command`, `authorization_denied`, `ai_analysis`, `scan_started`/`finished`, `reports_generated` entries |

## Top-level
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | public | Liveness check — `{"status": "online", ...}` |
| GET | `/` | public | Serves `HorusShield_UI.html` |

## Error Responses

Every endpoint returns the same JSON shape on error: `{"error": "message", "status": N}`. Standard codes: `400` (validation failure), `401` (no/invalid token), `403` (valid token, insufficient role), `404`, `413` (request body over `MAX_CONTENT_LENGTH`, 5 MB default), `429` (rate limited), `500` (never includes a stack trace — full detail goes to the server log only).
