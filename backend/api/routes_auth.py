"""HorusShield Auth API"""
from api.rate_limit import limiter
from config import active_config as config
import os
from flask import Blueprint, jsonify, request
from auth.auth_manager import auth_manager, test_smtp_connection
from auth.decorators import login_required, admin_required
from database.db_manager import db
from utils.logger import get_logger
from utils.network import get_client_ip

auth_bp = Blueprint('auth', __name__)
logger  = get_logger("routes_auth", "api")

# Backward-compatible alias — this file used to define its own require_auth;
# it's now the shared auth.decorators.login_required so every blueprint uses
# identical logic instead of each reimplementing it.
require_auth = login_required


@auth_bp.route('/register', methods=['POST'])
@limiter.limit(config.RATELIMIT_REGISTER)
def register():
    data     = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    name     = (data.get('name') or '').strip()
    result   = auth_manager.register(email, password, name)
    return jsonify(result), 200 if 'success' in result else 400


@auth_bp.route('/verify', methods=['POST'])
@limiter.limit(config.RATELIMIT_VERIFY)
def verify_email():
    """Fix for a confirmed Medium finding: this endpoint had no
    endpoint-specific rate limit at all (only the global 200/min default),
    despite protecting a brute-forceable 6-digit code. Now has both an
    IP-keyed limit (RATELIMIT_VERIFY, via @limiter.limit above) AND a
    per-account lockout (below) that catches a distributed attack against
    one target account from many source IPs — the IP limit alone can't."""
    data   = request.get_json(silent=True) or {}
    email  = (data.get('email') or '').strip().lower()
    code   = (data.get('code') or '').strip()
    ip     = get_client_ip()

    if email:
        recent_failures = db.count_recent_audit_actions(
            action="email_verify_attempt", username=email,
            since_minutes=config.VERIFY_ACCOUNT_LOCKOUT_WINDOW_MINUTES, status="failure",
        )
        if recent_failures >= config.VERIFY_ACCOUNT_LOCKOUT_THRESHOLD:
            db.add_audit_log(action="email_verify_attempt", username=email, status="failure",
                              ip_address=ip, details="rejected: account temporarily locked after repeated failures")
            return jsonify({
                "error": f"Too many failed verification attempts for this account. "
                         f"Try again in {config.VERIFY_ACCOUNT_LOCKOUT_WINDOW_MINUTES} minutes."
            }), 429

    result = auth_manager.verify_email(email, code)
    ok = 'success' in result
    db.add_audit_log(action="email_verify_attempt", username=email,
                      status="success" if ok else "failure", ip_address=ip,
                      details="" if ok else str(result.get("error", ""))[:200])
    return jsonify(result), 200 if ok else 400


@auth_bp.route('/resend-code', methods=['POST'])
@limiter.limit(config.RATELIMIT_LOGIN)
def resend_code():
    data   = request.get_json(silent=True) or {}
    email  = (data.get('email') or '').strip().lower()
    result = auth_manager.resend_code(email)
    return jsonify(result), 200 if 'success' in result else 400


@auth_bp.route('/login', methods=['POST'])
@limiter.limit(config.RATELIMIT_LOGIN)
def login():
    data     = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    result   = auth_manager.login(email, password)
    code     = 200 if 'success' in result else 401
    db.add_audit_log(
        action="login", username=email,
        status="success" if 'success' in result else "failure",
        ip_address=get_client_ip(),
        details="" if 'success' in result else str(result.get('error', ''))[:200],
    )
    return jsonify(result), code


@auth_bp.route('/google/client-id', methods=['GET'])
def google_client_id():
    """Return the configured Google OAuth Client ID (safe to expose publicly)."""
    client_id = (
        db.get_setting("google_client_id", "") or
        os.environ.get("HORUS_GOOGLE_CLIENT_ID", "") or
        getattr(config, "GOOGLE_CLIENT_ID", "")
    ).strip()
    if not client_id:
        return jsonify({"client_id": "", "configured": False,
                        "setup_guide": (
                            "1. Go to console.cloud.google.com → New project\n"
                            "2. APIs & Services → Credentials → Create OAuth 2.0 Client ID (Web)\n"
                            "3. Authorized JS Origins: http://127.0.0.1:5050\n"
                            "4. Copy the Client ID → Settings → Google Client ID field"
                        )})
    return jsonify({"client_id": client_id, "configured": True})


@auth_bp.route('/google', methods=['POST'])
@limiter.limit(config.RATELIMIT_LOGIN)
def google_login():
    """Verify a Google id_token or access_token and sign-in / register the user."""
    data     = request.get_json(silent=True) or {}
    token    = data.get('id_token') or data.get('credential') or data.get('access_token') or data.get('token') or ''
    if not token:
        return jsonify({"error": "Google token or credential required"}), 400

    client_id = (
        db.get_setting("google_client_id", "") or
        os.environ.get("HORUS_GOOGLE_CLIENT_ID", "") or
        getattr(config, "GOOGLE_CLIENT_ID", "")
    ).strip()
    if not client_id:
        return jsonify({
            "error": "Google Sign-In is not configured on this server. "
                     "Set your OAuth Client ID in Settings → Google Client ID."
        }), 400

    result = auth_manager.google_auth(token, client_id)
    return jsonify(result), 200 if 'success' in result else 400


@auth_bp.route('/logout', methods=['POST'])
def logout():
    token  = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    user   = auth_manager.validate_token(token) if token else None
    result = auth_manager.logout(token)
    db.add_audit_log(
        action="logout",
        username=(user or {}).get('email', '') if user else '',
        status="success" if 'success' in result else "failure",
        ip_address=get_client_ip(),
    )
    return jsonify(result)


@auth_bp.route('/me', methods=['GET'])
@require_auth
def me():
    return jsonify(request.current_user)


# ── SMTP Configuration ────────────────────────────────────────────────────────

@auth_bp.route('/smtp/config', methods=['GET'])
@admin_required
def get_smtp_config():
    """Return current SMTP settings (password masked)."""
    try:
        return jsonify({
            "smtp_host":      db.get_setting("smtp_host", "smtp.gmail.com"),
            "smtp_port":      db.get_setting("smtp_port", "587"),
            "smtp_user":      db.get_setting("smtp_user", ""),
            "smtp_pass":      "••••••••" if db.get_setting("smtp_pass", "") else "",
            "smtp_from_name": db.get_setting("smtp_from_name", "HorusShield Security"),
            "configured":     bool(db.get_setting("smtp_user", "") and db.get_setting("smtp_pass", "")),
        })
    except Exception as e:
        logger.error(f"smtp config GET: {e}")
        return jsonify({"error": str(e)}), 500


@auth_bp.route('/smtp/config', methods=['POST'])
@admin_required
def save_smtp_config():
    """
    Save SMTP credentials to the database.

    Body (JSON):
      smtp_host      — e.g. "smtp.gmail.com"
      smtp_port      — e.g. 587
      smtp_user      — your Gmail address
      smtp_pass      — App Password (16 chars, no spaces)
      smtp_from_name — display name (optional)

    Gmail setup:
      1. Enable 2-Step Verification on your Google account
      2. Go to https://myaccount.google.com/apppasswords
      3. Create an App Password for "Mail" → copy the 16-char code
      4. Use that code as smtp_pass here
    """
    data = request.get_json(silent=True) or {}
    try:
        fields = {
            "smtp_host":      ("SMTP server host",          data.get("smtp_host", "").strip()),
            "smtp_port":      ("SMTP server port",          str(data.get("smtp_port", "587")).strip()),
            "smtp_user":      ("SMTP login email",          data.get("smtp_user", "").strip()),
            "smtp_from_name": ("Sender display name",       data.get("smtp_from_name", "HorusShield Security").strip()),
        }
        # Only update password if a new one was explicitly provided (not the masked placeholder)
        raw_pass = data.get("smtp_pass", "").strip()
        if raw_pass and raw_pass != "••••••••":
            fields["smtp_pass"] = ("SMTP password / App Password", raw_pass)

        for key, (desc, value) in fields.items():
            db.set_setting(key, value, desc)

        logger.info(f"SMTP config saved — user={data.get('smtp_user','')}")
        return jsonify({"success": True, "message": "SMTP settings saved"})
    except Exception as e:
        logger.error(f"smtp config POST: {e}")
        return jsonify({"error": str(e)}), 500


@auth_bp.route('/smtp/test', methods=['POST'])
@admin_required
def smtp_test():
    """
    Test the current SMTP configuration by opening a connection.
    Does NOT send any email.
    """
    result = test_smtp_connection()
    status = 200 if result.get("success") else 400
    return jsonify(result), status


# ── Google Client ID Configuration ───────────────────────────────────────────

@auth_bp.route('/google/client-id', methods=['POST'])
@admin_required
def save_google_client_id():
    """
    Save Google OAuth Client ID.

    Setup steps:
      1. Go to https://console.cloud.google.com → Create or select a project
      2. APIs & Services → Credentials → Create OAuth 2.0 Client ID
      3. Application type: Web application
      4. Authorized JavaScript origins: http://127.0.0.1:5050
      5. Copy the Client ID (ends with .apps.googleusercontent.com)
      6. POST it here as {"client_id": "YOUR_CLIENT_ID"}
    """
    data      = request.get_json(silent=True) or {}
    client_id = data.get('client_id', '').strip()
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400
    if not client_id.endswith('.apps.googleusercontent.com'):
        return jsonify({"error": "Invalid Client ID format — should end with .apps.googleusercontent.com"}), 400
    try:
        db.set_setting('google_client_id', client_id, 'Google OAuth 2.0 Client ID')
        logger.info(f"Google Client ID saved: {client_id[:20]}...")
        return jsonify({"success": True, "message": "Google Client ID saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
