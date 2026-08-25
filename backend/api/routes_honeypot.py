"""HorusShield Honeypot API — Fixed"""
from flask import Blueprint, jsonify, request
from database.db_manager import db
from utils.logger import get_logger
from auth.decorators import login_required

honeypot_bp = Blueprint('honeypot', __name__)
logger = get_logger("routes_honeypot", "api")


@honeypot_bp.route('/status', methods=['GET'])
@login_required
def get_honeypot_status():
    try:
        enabled = db.get_setting('honeypot_enabled', 'false') == 'true'
        stats   = db.get_honeypot_stats() or {"total_events": 0, "unique_attackers": 0, "by_type": {}}
        return jsonify({"active": enabled, "statistics": stats})
    except Exception as e:
        logger.error(f"honeypot status: {e}")
        return jsonify({"active": False, "statistics": {"total_events": 0, "unique_attackers": 0}}), 200


@honeypot_bp.route('/events', methods=['GET'])
@login_required
def get_honeypot_events():
    try:
        limit  = request.args.get('limit', 50, type=int)
        events = db.get_honeypot_events(limit=limit)
        return jsonify(events)
    except Exception as e:
        logger.error(f"honeypot events: {e}")
        return jsonify([]), 200
