"""
HorusShield 2.0 — Main Application
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Team NullByte · WE School · Alexandria 🇪🇬
"""
import atexit
import os, sys, threading, time, subprocess
# pywebview needs a native GUI toolkit (GTK/Qt on Linux) that a headless
# Docker image intentionally doesn't ship. Import lazily, only when actually
# creating the desktop window (see the `if not headless:` branch below), so
# `HORUS_HEADLESS=true` containers work without pywebview or its system deps
# installed at all. Desktop/EXE behavior is unchanged — it still imports and
# uses pywebview exactly as before.
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from config import active_config as config
from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("app", "system")


def _get_ui_dir() -> str:
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def kill_existing_processes():
    """Windows-only startup cleanup — kill any process already squatting on
    our port before we try to bind it. Not reachable from any HTTP
    endpoint; runs once at process startup, before the Flask app exists.

    nosec B602 (both calls below): bandit flags shell=True + an f-string
    as a generic command-injection pattern. Both interpolated values here
    are constrained to a form that cannot contain shell metacharacters
    BEFORE they reach the f-string:
      - config.PORT is int(os.environ.get(...)) — an int can't inject
        shell syntax.
      - pid is filtered through `pid.isdigit()` two lines before use —
        only a pure numeric string reaches the second command.
    Verified as part of a bandit-driven CI security pass, not assumed.
    """
    try:
        result = subprocess.run(f'netstat -ano | findstr :{config.PORT}',
                                shell=True, capture_output=True, text=True)  # nosec B602
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) > 4:
                pid = parts[-1]
                if pid.isdigit() and int(pid) not in (0, os.getpid()):
                    subprocess.run(f'taskkill /F /PID {pid}', shell=True, capture_output=True)  # nosec B602
                    logger.info(f"Killed conflicting PID {pid}")
    except Exception as e:
        logger.debug(f"kill_existing_processes: {e}")


def startup_cleanup():
    """
    On every startup, clean only STALE/OLD data — never wipe the devices table.
    Devices are precious history the user expects to persist across restarts.
    """
    try:
        with db.get_connection() as conn:
            # ── Remove only devices not seen in the last 30 days ──
            conn.execute(
                "DELETE FROM devices WHERE last_seen < datetime('now', '-30 days')"
            )
            # ── Clean old traffic / predictions / logs ──
            conn.execute(
                "DELETE FROM network_traffic WHERE timestamp < datetime('now', '-2 days')"
            )
            conn.execute(
                "DELETE FROM predictions WHERE created_at < datetime('now', '-1 day')"
            )
            conn.execute(
                "DELETE FROM logs WHERE created_at < datetime('now', '-7 days')"
            )
        logger.info("Startup cleanup done — stale devices and old data removed")
    except Exception as e:
        logger.warning(f"Startup cleanup error: {e}")


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH  # oversized-payload protection
    # ── CORS: single place, localhost-only ──
    CORS(app, origins=config.CORS_ORIGINS)

    # ── Rate limiting: single shared instance, bound here (app-factory pattern) ──
    from api.rate_limit import limiter
    app.config["RATELIMIT_ENABLED"] = config.RATELIMIT_ENABLED

    # Redis-backed storage (Phase 7 fix): the previous in-memory-only
    # storage reset on every restart and didn't coordinate across
    # processes. If HORUS_RATELIMIT_STORAGE points at Redis, verify it's
    # actually reachable BEFORE handing the URI to flask-limiter — a
    # broken Redis URI should degrade to working in-memory limiting, not
    # take down rate limiting (or the whole app) silently or loudly.
    storage_uri = config.RATELIMIT_STORAGE_URI
    if storage_uri.startswith("redis://") or storage_uri.startswith("rediss://"):
        try:
            import redis as _redis
            _client = _redis.from_url(storage_uri, socket_connect_timeout=2, socket_timeout=2)
            _client.ping()
            logger.info(f"Rate limiting: connected to Redis at {storage_uri.split('@')[-1]}")
        except Exception as e:
            logger.warning(
                f"Rate limiting: Redis configured ({storage_uri.split('@')[-1]}) but unreachable "
                f"({e}) — falling back to in-memory storage. Rate limits will still work, but "
                f"won't be shared across processes or survive a restart until Redis is reachable."
            )
            storage_uri = "memory://"

    app.config["RATELIMIT_STORAGE_URI"] = storage_uri
    app.config["RATELIMIT_DEFAULT"] = config.RATELIMIT_DEFAULT
    limiter.init_app(app)

    UI_DIR = _get_ui_dir()

    @app.route("/")
    def index():
        return send_from_directory(UI_DIR, "HorusShield_UI.html")

    @app.route("/api/health")
    def health():
        return jsonify({"status": "online", "version": "2.0", "team": "NullByte"})

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(UI_DIR, filename)

    # ── Standardized error responses ──
    # Every unhandled error, from any blueprint, returns the same JSON shape
    # and never leaks a stack trace to the client — full detail still goes
    # to the log for debugging. Individual routes that already return their
    # own {"error": "..."} JSON on caught exceptions are unaffected; this is
    # the safety net for anything that reaches Flask uncaught, plus a
    # consistent shape for Flask's own 404/405/429/500.
    @app.errorhandler(400)
    def _bad_request(e):
        return jsonify({"error": "Bad request", "status": 400}), 400

    @app.errorhandler(401)
    def _unauthorized(e):
        return jsonify({"error": "Authentication required", "status": 401}), 401

    @app.errorhandler(403)
    def _forbidden(e):
        return jsonify({"error": "Forbidden", "status": 403}), 403

    @app.errorhandler(404)
    def _not_found(e):
        return jsonify({"error": "Not found", "status": 404}), 404

    @app.errorhandler(413)
    def _payload_too_large(e):
        return jsonify({"error": "Request body too large", "status": 413}), 413

    @app.errorhandler(429)
    def _rate_limited(e):
        return jsonify({"error": "Rate limit exceeded — please slow down", "status": 429}), 429

    @app.errorhandler(500)
    def _internal_error(e):
        logger.error(f"Unhandled 500: {e}")
        return jsonify({"error": "Internal server error", "status": 500}), 500

    @app.errorhandler(Exception)
    def _unhandled_exception(e):
        # Anything not already an HTTPException (those are handled by the
        # specific handlers above) reaches here. Log full detail server-side,
        # return nothing more than a generic message to the client.
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return jsonify({"error": e.description or "Error", "status": e.code}), e.code
        logger.error(f"Unhandled exception on {request.path}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "status": 500}), 500

    # ── Security headers on every response ──
    # NOTE on Content-Security-Policy: HorusShield_UI.html is a single-file
    # frontend with inline <script>/<style> throughout (no build step, no
    # nonce infrastructure) — that's an existing, deliberate architecture
    # this pass explicitly preserves rather than redesigns. A CSP that
    # forbids 'unsafe-inline' would break the app outright. This CSP is
    # still meaningfully protective (restricts to same-origin + the one
    # actual external script the app loads, blocks framing, blocks
    # plugins/objects) — it's a real improvement over having no CSP at
    # all, but it is NOT the strict nonce-based policy you'd want if the
    # frontend were split into external files. That's the honest tradeoff.
    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://accounts.google.com; "
            "style-src 'self' 'unsafe-inline' https://accounts.google.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.googleusercontent.com https://lh3.googleusercontent.com; "
            "connect-src 'self' ws: wss: https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com; "
            "frame-src 'self' https://accounts.google.com; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
        # HSTS only makes sense over HTTPS — harmless but meaningless to
        # send over plain HTTP (the default for this app's local-only
        # deployment); included so it's active the moment TLS is added in
        # front of HorusShield (e.g. via a reverse proxy).
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    from engine.network_monitor  import NetworkMonitor, traffic_bp
    from engine.device_detector  import DeviceDetector
    from engine.attack_detector  import AttackDetector
    from engine.device_blocker   import DeviceBlocker
    from engine.lockdown         import LockdownManager
    from ai.trainer              import AITrainer
    from ai.security_scorer      import SecurityScorer
    from honeypot.honeypot_manager import HoneypotManager
    from mesh.mesh_defense        import MeshDefense
    from vscanner.orchestrator    import VScannerManager
    from api.websocket            import HorusSocket
    from api.routes_dashboard     import dashboard_bp
    from api.routes_devices       import devices_bp
    from api.routes_attacks       import attacks_bp
    from api.routes_ai            import ai_bp, set_trainer
    from api.routes_reports       import reports_bp
    from api.routes_honeypot      import honeypot_bp
    from api.routes_mesh          import mesh_bp
    from api.routes_settings      import settings_bp
    from api.routes_horus         import horus_bp
    from api.routes_terminal      import terminal_bp
    from api.routes_auth          import auth_bp
    from api.routes_vscanner      import vscanner_bp
    from api.routes_audit         import audit_bp

    ws = HorusSocket(app)

    blocker    = DeviceBlocker(socketio=ws.sio)
    blocker.restore_blocks()   # reconcile firewall rules with DB state after a restart
    lockdown   = LockdownManager(device_blocker=blocker, socketio=ws.sio)
    monitor    = NetworkMonitor(socketio=ws.sio)
    detector   = DeviceDetector(socketio=ws.sio)
    attacker   = AttackDetector(packet_analyzer=monitor.get_analyzer(),
                                device_blocker=blocker, socketio=ws.sio)
    honeypot   = HoneypotManager(socketio=ws.sio)
    mesh       = MeshDefense(socketio=ws.sio)
    vscanner   = VScannerManager(socketio=ws.sio)
    ai_trainer = AITrainer()
    scorer     = SecurityScorer()
    set_trainer(ai_trainer)

    app.extensions['device_blocker'] = blocker
    app.extensions['lockdown']       = lockdown
    app.extensions['socketio']       = ws.sio
    app.extensions['monitor']        = monitor   # ← used by traffic_bp route
    app.extensions['mesh']           = mesh      # ← used by routes_mesh.py
    app.extensions['vscanner']       = vscanner   # ← unified DI: routes_vscanner.py reads this,
                                                    #   same pattern as device_blocker/lockdown/monitor

    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(traffic_bp,   url_prefix="/api/traffic")
    app.register_blueprint(devices_bp,   url_prefix="/api/devices")
    app.register_blueprint(attacks_bp,   url_prefix="/api/attacks")
    app.register_blueprint(ai_bp,        url_prefix="/api/ai")
    app.register_blueprint(reports_bp,   url_prefix="/api/reports")
    app.register_blueprint(honeypot_bp,  url_prefix="/api/honeypot")
    app.register_blueprint(mesh_bp,      url_prefix="/api/mesh")
    app.register_blueprint(settings_bp,  url_prefix="/api/settings")
    app.register_blueprint(horus_bp,     url_prefix="/api/horus")
    app.register_blueprint(terminal_bp,  url_prefix="/api/terminal")
    app.register_blueprint(auth_bp,      url_prefix="/api/auth")
    app.register_blueprint(vscanner_bp,  url_prefix="/api/vscanner")
    app.register_blueprint(audit_bp,     url_prefix="/api/audit")

    def start_engines():
        """Start all monitoring engines (network, device, attack, mesh, honeypot, AI)."""
        logger.info("Starting engines...")
        monitor.start()
        detector.start()
        attacker.start()
        mesh.start()
        honeypot.start()
        ai_trainer.start()
        logger.info("All engines started.")

    def run_scorer():
        """Run the security scorer on a separate dedicated thread."""
        while True:
            try:
                scorer.calculate()
            except Exception as e:
                logger.error(f"Scorer: {e}")
            time.sleep(30)

    if os.environ.get("HORUS_START_ENGINES", "true").lower() != "false":
        threading.Thread(target=start_engines, daemon=True, name="Engines").start()
        threading.Thread(target=run_scorer,    daemon=True, name="Scorer").start()
    return app, ws


if __name__ == "__main__":
    logger.info("=" * 54)
    logger.info("  HORUSSHIELD 2.0 — Team NullByte · WE School")
    logger.info("  Alexandria, Egypt 🇪🇬")
    logger.info("=" * 54)

    kill_existing_processes()
    startup_cleanup()          # ← clears devices for fresh scan
    atexit.register(db.close_all_connections)  # flush WAL + close DB handle on shutdown

    app, ws = create_app()
    server_url = f"http://127.0.0.1:{config.PORT}"

    def run_server():
        try:
            ws.sio.run(app, host="127.0.0.1", port=config.PORT,
                       debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
        except OSError as e:
            logger.error(f"Port {config.PORT} busy! Kill python processes first.")
        except Exception as e:
            logger.error(f"Server: {e}")

    threading.Thread(target=run_server, daemon=True, name="Flask").start()

    # Wait up to 20s for Flask to be ready
    for _ in range(20):
        try:
            import requests
            if requests.get(f"{server_url}/api/health", timeout=1).status_code == 200:
                break
        except Exception as e:
            logger.debug(f"Health check not ready yet: {e}")
        time.sleep(1)

    # HORUS_HEADLESS=true (set by the Docker image) skips the native pywebview
    # window and just keeps the Flask/Socket.IO server running in the
    # foreground — a container has no display for pywebview to attach to.
    # Default (unset) behavior — the desktop app with its native window — is
    # completely unchanged.
    headless = os.environ.get("HORUS_HEADLESS", "false").strip().lower() == "true"
    if headless:
        logger.info(f"Running headless — server available at {server_url}")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            logger.info("Shutting down (headless mode)")
    else:
        import webview
        webview.create_window("HorusShield 2.0 — Egyptian AI Cybersecurity Platform",
                              server_url, width=1400, height=860,
                              resizable=True, min_size=(1024, 600))
        webview.start()
