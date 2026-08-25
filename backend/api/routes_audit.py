"""HorusShield Audit Log API — read-only access to the accountability trail."""
from flask import Blueprint, jsonify, request

from database.db_manager import db
from utils.logger import get_logger
from auth.decorators import admin_required

audit_bp = Blueprint("audit", __name__)
logger = get_logger("routes_audit", "api")


@audit_bp.route("/", methods=["GET"])
@admin_required
def get_audit_log():
    try:
        limit = request.args.get("limit", 100, type=int)
        limit = max(1, min(limit, 500))
        action = request.args.get("action") or None
        username = request.args.get("username") or None
        return jsonify(db.get_audit_log(limit=limit, action=action, username=username))
    except Exception as e:
        logger.error(f"get_audit_log: {e}")
        return jsonify([]), 200
