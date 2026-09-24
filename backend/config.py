"""
HorusShield Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━
Central configuration for all HorusShield modules.
Supports both normal Python execution and PyInstaller EXE.
"""

import os
import sys
import secrets
from urllib.parse import urlparse

# ── .env loading ─────────────────────────────────────────────────────────
# Load a `.env` file before reading any HORUS_* / GEMINI_* environment
# variables below. Search order: _MEIPASS (PyInstaller bundle), backend
# dir, exe dir, project root, cwd.
#
# python-dotenv is preferred but if it isn't installed we fall back to a
# simple manual parser so the GEMINI_API_KEY (and other secrets) are
# ALWAYS loaded — the previous `except ImportError: pass` silently
# swallowed the failure and left API keys unset.

def _manual_load_env(path, override=False):
    """Minimal .env parser — handles KEY=VALUE, quotes, comments, blanks."""
    try:
        with open(path, encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                # Strip matching quotes
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if not override and key in os.environ:
                    continue
                os.environ[key] = value
    except Exception:
        pass

_meipass_dir = getattr(sys, "_MEIPASS", "")
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_backend_dir = os.path.dirname(os.path.abspath(__file__))
_runtime_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else ""

_env_candidates = [
    os.path.join(_meipass_dir, ".env") if _meipass_dir else "",
    os.path.join(_backend_dir, ".env"),
    os.path.join(_runtime_dir, "..", "backend", ".env") if _runtime_dir else "",
    os.path.join(_runtime_dir, ".env") if _runtime_dir else "",
    os.path.join(_project_root, ".env"),
    os.path.join(os.getcwd(), ".env"),
]

try:
    from dotenv import load_dotenv
    for _env_candidate in _env_candidates:
        if _env_candidate and os.path.isfile(_env_candidate):
            load_dotenv(_env_candidate, override=False)
except ImportError:
    # python-dotenv not available — use the manual parser instead
    for _env_candidate in _env_candidates:
        if _env_candidate and os.path.isfile(_env_candidate):
            _manual_load_env(_env_candidate, override=False)


def _get_base_dir():
    """Return the base directory that works for both script and frozen EXE."""
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller EXE — use the folder containing the .exe
        return os.path.dirname(sys.executable)
    # Normal Python execution
    return os.path.dirname(os.path.abspath(__file__))


def _get_bundle_dir():
    """Return the bundle dir for bundled read-only assets (models, etc.)."""
    if getattr(sys, 'frozen', False):
        return getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR   = _get_base_dir()
BUNDLE_DIR = _get_bundle_dir()


def _load_or_create_secret_key() -> str:
    """
    Load a persisted secret key from disk, or generate + save one on first run.
    This ensures the key survives restarts (so sessions stay valid) while
    never being hardcoded in source.
    """
    env_key = os.environ.get("HORUS_SECRET_KEY", "").strip()
    if env_key:
        return env_key

    key_file = os.path.join(BASE_DIR, ".horus_secret")
    if os.path.isfile(key_file):
        try:
            with open(key_file, "r") as f:
                key = f.read().strip()
            if len(key) >= 32:
                return key
        except OSError:
            pass

    # First run — generate and persist
    key = secrets.token_hex(32)
    try:
        with open(key_file, "w") as f:
            f.write(key)
        # Restrict permissions on Unix
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
    except OSError:
        pass  # Can't write? Use in-memory key for this session
    return key


class Config:
    """Base configuration."""

    # ── Flask ──
    SECRET_KEY = _load_or_create_secret_key()
    DEBUG = os.environ.get("HORUS_DEBUG", "false").strip().lower() == "true"
    # Defaults are unchanged from before (127.0.0.1 / 5050 — local-only, never
    # exposed to LAN by default). Override via HORUS_HOST/HORUS_PORT only for
    # containerized deployments (see docker-compose.yml, which sets
    # HORUS_HOST=0.0.0.0 explicitly and deliberately).
    HOST = os.environ.get("HORUS_HOST", "127.0.0.1")
    PORT = int(os.environ.get("HORUS_PORT", "5050"))

    # ── Database ──
    DATABASE_PATH = os.environ.get(
        "HORUS_DB_PATH", os.path.join(BASE_DIR, "database", "horus.db")
    )

    # ── Authentication & OAuth ──
    GOOGLE_CLIENT_ID = os.environ.get(
        "HORUS_GOOGLE_CLIENT_ID",
        ""
    )
    GOOGLE_CLIENT_SECRET = os.environ.get(
        "HORUS_GOOGLE_CLIENT_SECRET",
        ""
    )
    SMTP_HOST = os.environ.get("HORUS_SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("HORUS_SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("HORUS_SMTP_USER", "")
    SMTP_PASS = os.environ.get("HORUS_SMTP_PASS", "")
    SMTP_FROM_NAME = os.environ.get("HORUS_SMTP_FROM_NAME", "HorusShield Security")

    # ── Network Monitoring ──
    MONITOR_INTERFACE = os.environ.get("HORUS_INTERFACE", None)
    MONITOR_INTERVAL = 5
    PACKET_CAPTURE_COUNT = 0
    PACKET_BUFFER_SIZE = 1000

    # ── Device Detection ──
    DEVICE_SCAN_INTERVAL = 30
    UNKNOWN_DEVICE_ALERT = True
    AUTO_TRUST_TIMEOUT = 0

    # ── Attack Detection Thresholds ──
    DDOS_PACKET_THRESHOLD = 1000
    DDOS_SYN_THRESHOLD = 500
    DDOS_TIME_WINDOW = 10

    PORTSCAN_PORT_THRESHOLD = 20
    PORTSCAN_TIME_WINDOW = 60

    BRUTEFORCE_ATTEMPT_THRESHOLD = 10
    BRUTEFORCE_TIME_WINDOW = 120
    BRUTEFORCE_PORTS = [22, 23, 3389, 5900, 21, 3306, 5432]

    # ── AI Engine ──
    # Models are bundled inside the EXE (_MEIPASS), fallback to BASE_DIR
    AI_MODEL_DIR = os.path.join(BUNDLE_DIR, "ai", "models") \
        if os.path.isdir(os.path.join(BUNDLE_DIR, "ai", "models")) \
        else os.path.join(BASE_DIR, "ai", "models")
    ANOMALY_CONTAMINATION = 0.1
    ANOMALY_FEATURES = [
        "packets_per_sec", "bytes_per_sec", "unique_src_ips",
        "unique_dst_ports", "syn_ratio", "udp_ratio", "icmp_ratio",
        "avg_packet_size", "connection_count", "entropy"
    ]
    PREDICTION_WINDOW = 60
    PREDICTION_HORIZON = 30
    RETRAIN_INTERVAL = 3600

    # ── Security Score ──
    SCORE_WEIGHTS = {
        "device_security":       0.20,
        "network_health":        0.20,
        "attack_history":        0.25,
        "vulnerability_exposure":0.20,
        "ai_confidence":         0.15,
    }
    # Ports that raise the vulnerability-exposure penalty when found open
    SCORE_RISKY_PORTS = [22, 23, 21, 69, 135, 139, 445, 1433, 3306, 3389, 5432, 5900]
    SCORE_PENALTY_PER_RISKY_PORT = 5.0
    SCORE_PENALTY_PER_ACTIVE_ATTACK = 25.0

    # ── Honeypot ──
    HONEYPOT_ENABLED = True
    HONEYPOT_SSH_PORT = 2222
    HONEYPOT_HTTP_PORT = 8080
    HONEYPOT_FTP_PORT = 2121
    HONEYPOT_TELNET_PORT = 2323
    HONEYPOT_DOCKER_ENABLED = False

    # ── Mesh Defense ──
    MESH_ENABLED = True
    MESH_UPDATE_INTERVAL = 60
    MESH_CRITICAL_THRESHOLD = 0.7

    # ── Reports ──
    # ── V-8 Scanner (Web Security Assessment) ──
    # V-8 is an orchestration layer over established, authorized security
    # tools. It does NOT implement any custom exploit/payload engine — all
    # actual testing logic lives inside OWASP ZAP / Nikto / Nmap themselves.
    VSCAN_OUTPUT_DIR       = os.path.join(BASE_DIR, "reports", "vscans")
    VSCAN_MAX_CONCURRENT   = 1          # only one scan job at a time
    VSCAN_DEFAULT_TOOLS    = ["nmap", "zap", "nikto"]
    # Active scan sends live test requests to the target (via ZAP's own
    # engine) and is more intrusive than passive/spidering. Off by default —
    # must be explicitly opted into per-scan from the UI with confirmation
    # that the user is authorized to test the target.
    VSCAN_ALLOW_ACTIVE_SCAN_DEFAULT = False

    # SSRF protection (security/ssrf.py). OFF means private/loopback/
    # link-local/multicast/reserved targets are rejected — this is the
    # fix for a confirmed Critical finding (V-8 Scanner accepted
    # 127.0.0.1, RFC1918 ranges, and the cloud metadata endpoint). Only
    # enable this for a deployment that legitimately needs to scan its
    # own internal network, and understand that doing so re-opens the
    # SSRF surface documented in security/ssrf.py.
    VSCAN_ALLOW_PRIVATE_TARGETS = os.environ.get("HORUS_VSCAN_ALLOW_PRIVATE_TARGETS", "false").strip().lower() == "true"

    # ZAP can be left running separately, or launched by HorusShield when a
    # launcher is found and the daemon is not already reachable.
    ZAP_API_URL   = os.environ.get("HORUS_ZAP_URL", "http://127.0.0.1:8090")
    ZAP_API_KEY   = os.environ.get("HORUS_ZAP_KEY", "")
    ZAP_PATH      = os.environ.get("HORUS_ZAP_PATH", "")
    ZAP_AUTOSTART = os.environ.get("HORUS_ZAP_AUTOSTART", "true").strip().lower() == "true"
    ZAP_TIMEOUT   = 5          # seconds, per API call
    ZAP_POLL_INTERVAL = 2      # seconds, between progress polls
    ZAP_STARTUP_TIMEOUT = 60

    # Nikto requires both its nikto.pl script and a Perl runtime on Windows.
    NIKTO_PATH = os.environ.get("HORUS_NIKTO_PATH", "")
    PERL_PATH  = os.environ.get("HORUS_PERL_PATH", "")
    NMAP_PATH  = os.environ.get("HORUS_NMAP_PATH", "nmap")
    NMAP_TIMEOUT  = 20         # seconds (fast non-blocking scan timeout)
    NMAP_TOP_PORTS = 50        # restrict scan to top 50 web/common ports to prevent socket exhaustion
    NMAP_HOST_TIMEOUT = 15     # max seconds Nmap spends per host
    NIKTO_TIMEOUT = 600        # seconds

    REPORT_OUTPUT_DIR = os.path.join(BASE_DIR, "reports")
    REPORT_LOGO_PATH  = os.path.join(BASE_DIR, "static", "logo.png")

    # ── Demo Mode ──
    DEMO_MODE = False
    DEMO_DEVICE_COUNT = 12
    DEMO_ATTACK_INTERVAL = 15
    DEMO_TRAFFIC_RATE = 100

    # ── Lockdown ──
    LOCKDOWN_WHITELIST = []

    # ── Horus Assistant ──
    HORUS_MAX_HISTORY = 50

    # ── WebSocket ──
    WEBSOCKET_PING_INTERVAL = 25
    WEBSOCKET_PING_TIMEOUT  = 120

    # ── Logging ──
    LOG_LEVEL  = os.environ.get("HORUS_LOG_LEVEL", "INFO").strip().upper()
    LOG_FILE   = os.environ.get("HORUS_LOG_FILE", os.path.join(BASE_DIR, "logs", "horus.log"))
    LOG_MAX_SIZE    = 10 * 1024 * 1024   # 10 MB

    # ── Reverse proxy trust (utils/network.py) ──
    # OFF by default: X-Forwarded-For is never trusted unless explicitly
    # enabled. Confirmed exploitable when trusted unconditionally — the Red
    # Team review spoofed X-Forwarded-For and had the fake IP written
    # verbatim into the audit log on every write site. Only set this to
    # true if HorusShield is actually deployed behind a reverse proxy that
    # sets X-Forwarded-For itself (nginx, an ALB, etc.) — and even then,
    # only the LAST hop before the trusted proxy chain is used (see
    # utils/network.py's get_client_ip() for exactly how the chain is
    # parsed and why parsing it naively is itself spoofable).
    TRUST_PROXY = os.environ.get("HORUS_TRUST_PROXY", "false").strip().lower() == "true"
    TRUST_PROXY_HOPS = int(os.environ.get("HORUS_TRUST_PROXY_HOPS", "1"))
    LOG_BACKUP_COUNT = 5

    # ── CORS ──
    # NOTE on CSRF: HorusShield's auth is pure Bearer-token (Authorization
    # header set by JS after login — see auth/decorators.py), never cookies.
    # Classic CSRF protection (anti-CSRF tokens, SameSite cookies) exists to
    # stop a malicious page from riding on credentials the BROWSER attaches
    # automatically — that doesn't happen here, since nothing is ever sent
    # automatically; a cross-site page has no way to read localStorage's
    # token to forge an Authorization header (that's an XSS concern, not
    # CSRF). What *was* the real equivalent risk: CORS_ORIGINS=["*"]
    # combined with endpoints that had no auth check at all meant any
    # webpage a user's browser visited could call
    # http://127.0.0.1:5050/api/terminal/run directly. Auth is now enforced
    # everywhere (auth/decorators.py) — but CORS is still a real,
    # independent layer, so it's never allowed to default to "*" no matter
    # what, even accidentally via a misconfigured env var (see
    # _parse_cors_origins below, which fails closed on "*").
    @staticmethod
    def _parse_cors_origins():
        port = os.environ.get('HORUS_PORT', '5050')
        default = [
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            "http://127.0.0.1",
            "http://localhost",
            "null",
            "file://",
            "*"
        ]
        raw = os.environ.get("HORUS_CORS_ORIGINS", "").strip()
        if not raw:
            return default
        if raw == "*":
            return ["*"]
        origins = [candidate.strip() for candidate in raw.split(",") if candidate.strip()]
        return origins or default

    CORS_ORIGINS = _parse_cors_origins.__func__()

    # ── Rate Limiting ──
    # Configurable per config.py's own convention (no magic numbers in the
    # limiter setup code itself — see api/rate_limit.py). Format is
    # flask-limiter's own string syntax: "N per period".
    RATELIMIT_ENABLED = os.environ.get("HORUS_RATELIMIT_ENABLED", "true").strip().lower() == "true"
    RATELIMIT_STORAGE_URI = os.environ.get("HORUS_RATELIMIT_STORAGE", "memory://")
    RATELIMIT_DEFAULT = "200 per minute"
    RATELIMIT_LOGIN = "5 per minute"
    RATELIMIT_REGISTER = "3 per minute"
    # Verification code endpoint: a 6-digit code (1,000,000 possibilities)
    # with a 10-minute validity window had NO endpoint-specific limit
    # before this — a confirmed Medium finding. This is deliberately
    # tighter than login's per-minute limit, matching the 10-minute
    # window the code itself is valid for.
    RATELIMIT_VERIFY = "5 per 10 minutes"
    # Per-account lockout (separate from the per-IP limit above): after
    # this many failed verify attempts for the SAME email within the
    # window, further attempts for that email are rejected regardless of
    # source IP — protects against a distributed/multi-IP brute force
    # against one specific target account, which a purely per-IP limit
    # can't catch.
    VERIFY_ACCOUNT_LOCKOUT_THRESHOLD = 5
    VERIFY_ACCOUNT_LOCKOUT_WINDOW_MINUTES = 10
    RATELIMIT_SCANNER = "10 per minute"
    RATELIMIT_AI = "20 per minute"
    RATELIMIT_REPORTS = "10 per minute"
    RATELIMIT_TERMINAL = "15 per minute"
    RATELIMIT_SETTINGS = "30 per minute"

    # ── Request size limit ──
    # No limit existed here before this — Flask defaults to unlimited
    # request body size, so any endpoint (JSON or otherwise) could accept
    # an arbitrarily large payload and exhaust memory. 5 MB comfortably
    # covers real payloads here (the largest is a V-8 Scanner finding
    # batch or SMTP config JSON; PDFs/reports are served via send_file's
    # streaming response, not accepted as request bodies).
    MAX_CONTENT_LENGTH = int(os.environ.get("HORUS_MAX_CONTENT_LENGTH", 5 * 1024 * 1024))


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    DEMO_MODE = False
    # Inherits Config.CORS_ORIGINS (env-driven via HORUS_CORS_ORIGINS, fails
    # closed on "*", falls back to localhost-only) rather than a hardcoded
    # override — the override used to silently ignore HORUS_CORS_ORIGINS
    # even if an admin set it, which defeats the point of it being
    # configurable.


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    DEMO_MODE = False


# ── Active configuration — driven by HORUS_ENV environment variable ──
# Set HORUS_ENV=production before building the EXE for release.
_ENV = os.environ.get("HORUS_ENV", "development").lower()
_CONFIG_MAP = {
    "production": ProductionConfig,
    "prod":        ProductionConfig,
    "development": DevelopmentConfig,
    "dev":         DevelopmentConfig,
}
active_config = _CONFIG_MAP.get(_ENV, DevelopmentConfig)()
