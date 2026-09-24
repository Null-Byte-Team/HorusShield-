"""HorusShield Dashboard API — Fixed"""
from flask import Blueprint, jsonify
from database.db_manager import db
from utils.logger import get_logger
from auth.decorators import login_required

dashboard_bp = Blueprint('dashboard', __name__)
logger = get_logger("routes_dashboard", "api")


@dashboard_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    try:
        return jsonify(db.get_dashboard_stats())
    except Exception as e:
        logger.error(f"stats: {e}")
        return jsonify({"error": "Dashboard data unavailable"}), 503


@dashboard_bp.route('/traffic/history', methods=['GET'])
@login_required
def get_traffic_history():
    try:
        return jsonify(db.get_traffic_history(minutes=60))
    except Exception as e:
        logger.error(f"traffic history: {e}")
        return jsonify([]), 200


@dashboard_bp.route('/score/history', methods=['GET'])
@login_required
def get_score_history():
    try:
        return jsonify(db.get_score_history(hours=24))
    except Exception as e:
        logger.error(f"score history: {e}")
        return jsonify([]), 200


@dashboard_bp.route('/alerts', methods=['GET'])
@login_required
def get_alerts():
    try:
        return jsonify(db.get_alerts(limit=20))
    except Exception as e:
        logger.error(f"alerts: {e}")
        return jsonify([]), 200
