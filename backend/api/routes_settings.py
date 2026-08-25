"""
HorusShield Settings API
━━━━━━━━━━━━━━━━━━━━━━━━
Endpoints for global system configuration.
"""
from api.rate_limit import limiter
from config import active_config as config

from flask import Blueprint, jsonify, request
from database.db_manager import db
from utils.logger import get_logger
from auth.decorators import login_required, admin_required
import re
from utils.network import get_client_ip

settings_bp = Blueprint('settings', __name__)
logger = get_logger("routes_settings", "api")

# Pattern, not a hardcoded enum: setting keys are set from several places
# (frontend toggles, lockdown.py, etc.) and a strict enum risks silently
# breaking a legitimate key this audit didn't happen to find via grep.
# This still rejects anything injection-shaped or absurd — a real setting
# key is always a short lowercase_with_underscores identifier.
_SETTING_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

@settings_bp.route('/', methods=['GET'])
@login_required
def get_all_settings():
    try:
        settings = db.get_all_settings()
        return jsonify(settings)
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        return jsonify({"error": "Internal error"}), 500

@settings_bp.route('/<key>', methods=['GET'])
@login_required
def get_setting(key):
    try:
        if not _SETTING_KEY_RE.match(key):
            return jsonify({"error": "Invalid setting key"}), 400
        val = db.get_setting(key)
        return jsonify({key: val})
    except Exception as e:
        logger.error(f"Error fetching setting {key}: {e}")
        return jsonify({"error": "Internal error"}), 500

@settings_bp.route('/toggle', methods=['POST'])
@admin_required
@limiter.limit(config.RATELIMIT_SETTINGS)
def toggle_setting():
    try:
        data = request.get_json(silent=True) or {}
        key = data.get('key')
        value = data.get('value')
        if not key or not isinstance(key, str) or not _SETTING_KEY_RE.match(key):
            return jsonify({"error": "A valid 'key' (lowercase letters/digits/underscore, max 64 chars) is required"}), 400

        db.set_setting(key, str(value).lower())
        db.add_audit_log(
            action="settings_changed",
            ip_address=get_client_ip(),
            details=f"key={key} value={value}",
        )
        return jsonify({"success": True, "key": key, "value": value})
    except Exception as e:
        logger.error(f"Error toggling setting: {e}")
        return jsonify({"error": "Internal error"}), 500
