"""HorusShield Attacks API — Fixed"""
from flask import Blueprint, jsonify, request
from database.db_manager import db
from utils.logger import get_logger
from auth.decorators import login_required, analyst_required
from services.threat_map import threat_map_service

attacks_bp = Blueprint('attacks', __name__)
logger = get_logger("routes_attacks", "api")


@attacks_bp.route('/', methods=['GET'])
@login_required
def list_attacks():
    try:
        limit    = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity')
        status   = request.args.get('status')
        attacks = db.get_attacks(limit=limit, severity=severity, status=status)
        for a in attacks:
            src_ip = a.get('source_ip')
            if src_ip and not threat_map_service.is_local_or_private(src_ip):
                geo = threat_map_service._get_geo_info(src_ip)
                if geo:
                    a['geo_country'] = geo.get('country')
                    a['geo_city'] = geo.get('city')
                    a['geo_lat'] = geo.get('lat')
                    a['geo_lon'] = geo.get('lon')
        return jsonify(attacks)
    except Exception as e:
        logger.error(f"list_attacks: {e}")
        return jsonify([]), 200   # always return list not error


@attacks_bp.route('/active', methods=['GET'])
@login_required
def get_active():
    try:
        attacks = db.get_attacks(status='active', limit=50)
        for a in attacks:
            src_ip = a.get('source_ip')
            if src_ip and not threat_map_service.is_local_or_private(src_ip):
                geo = threat_map_service._get_geo_info(src_ip)
                if geo:
                    a['geo_country'] = geo.get('country')
                    a['geo_city'] = geo.get('city')
                    a['geo_lat'] = geo.get('lat')
                    a['geo_lon'] = geo.get('lon')
        return jsonify(attacks)
    except Exception as e:
        logger.error(f"get_active: {e}")
        return jsonify([]), 200


@attacks_bp.route('/threat-map', methods=['GET'])
@login_required
def get_threat_map():
    """Return real geographic attack points for the 3D globe / threat map."""
    try:
        points = threat_map_service.get_threat_points()
        return jsonify(points)
    except Exception as e:
        logger.error(f"get_threat_map: {e}")
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

