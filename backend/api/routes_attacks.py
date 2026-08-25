"""HorusShield Attacks API — Fixed"""
from flask import Blueprint, jsonify, request
from database.db_manager import db
from utils.logger import get_logger
from auth.decorators import login_required, analyst_required

attacks_bp = Blueprint('attacks', __name__)
logger = get_logger("routes_attacks", "api")


@attacks_bp.route('/', methods=['GET'])
@login_required
def list_attacks():
    try:
        limit    = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity')
        status   = request.args.get('status')
        return jsonify(db.get_attacks(limit=limit, severity=severity, status=status))
    except Exception as e:
        logger.error(f"list_attacks: {e}")
        return jsonify([]), 200   # always return list not error


@attacks_bp.route('/active', methods=['GET'])
@login_required
def get_active():
    try:
        return jsonify(db.get_attacks(status='active', limit=50))
    except Exception as e:
        logger.error(f"get_active: {e}")
        return jsonify([]), 200


@attacks_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    try:
        return jsonify(db.get_attack_stats(hours=24))
    except Exception as e:
        logger.error(f"get_stats: {e}")
        return jsonify([]), 200


@attacks_bp.route('/<int:attack_id>/mitigate', methods=['POST'])
@analyst_required
def mitigate(attack_id):
    try:
        mitigation = (request.get_json(silent=True) or {}).get('mitigation', 'Manual')
        db.update_attack_status(attack_id, 'mitigated', mitigation)
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"mitigate: {e}")
        return jsonify({"error": "Failed"}), 500
