"""HorusShield Devices API — Fixed"""
from flask import Blueprint, jsonify, request, current_app
from auth.decorators import login_required, analyst_required
from database.db_manager import db
from utils.logger import get_logger

devices_bp = Blueprint('devices', __name__)
logger = get_logger("routes_devices", "api")


@devices_bp.route('/', methods=['GET'])
@login_required
def list_devices():
    try:
        status = request.args.get('status')
        devs   = db.get_all_devices(status=status)
        real   = [d for d in devs if d.get('mac_address') not in ('', '00:00:00:00:00:00')]
        return jsonify(real if real else devs)
    except Exception as e:
        logger.error(f"list_devices: {e}")
        return jsonify({"error": "Internal error"}), 500


@devices_bp.route('/clear', methods=['POST'])
@analyst_required
def clear_fake_devices():
    """Remove stale/fake devices, keep real scanned ones."""
    try:
        with db.get_connection() as conn:
            conn.execute("""
                DELETE FROM devices WHERE
                    mac_address IN ('00:00:00:00:00:00', '')
                    OR hostname = 'HorusGateway'
                    OR hostname = 'Unknown-Device'
                    OR (hostname LIKE 'Workstation-%' AND vendor = 'Dell')
            """)
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"clear_fake: {e}")
        return jsonify({"error": "Failed"}), 500


@devices_bp.route('/<int:device_id>', methods=['GET'])
@login_required
def get_device(device_id):
    try:
        d = db.get_device(device_id=device_id)
        return jsonify(d) if d else (jsonify({"error": "Not found"}), 404)
    except Exception as e:
        return jsonify({"error": "Internal error"}), 500


@devices_bp.route('/<int:device_id>/trust', methods=['POST'])
@analyst_required
def trust_device(device_id):
    try:
        db.update_device(device_id, status='trusted')
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": "Failed"}), 500


@devices_bp.route('/<int:device_id>/block', methods=['POST'])
@analyst_required
def block_device_api(device_id):
    try:
        device  = db.get_device(device_id=device_id)
        if not device:
            return jsonify({"error": "Not found"}), 404
        from utils.validation import validate_string
        reason, err = validate_string(
            (request.get_json(silent=True) or {}).get('reason', 'Manual block'),
            field_name="reason", max_length=300, required=False,
        )
        if err:
            return jsonify({"error": err}), 400
        reason = reason or 'Manual block'
        blocker = current_app.extensions.get('device_blocker')
        if blocker:
            blocker.block_device(device['mac_address'],
                                  ip_address=device['ip_address'],
                                  reason=reason, blocked_by='manual')
        else:
            db.block_device(mac_address=device['mac_address'],
                            ip_address=device['ip_address'], reason=reason)
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"block_device: {e}")
        return jsonify({"error": "Failed"}), 500


@devices_bp.route('/<int:device_id>/unblock', methods=['POST'])
@analyst_required
def unblock_device_api(device_id):
    try:
        device  = db.get_device(device_id=device_id)
        if not device:
            return jsonify({"error": "Not found"}), 404
        blocker = current_app.extensions.get('device_blocker')
        if blocker:
            blocker.unblock_device(device['mac_address'])
        else:
            db.unblock_device(device['mac_address'])
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": "Failed"}), 500
