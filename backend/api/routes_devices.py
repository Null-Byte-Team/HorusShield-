"""
HorusShield Devices API — with Device Fingerprinting
"""
from flask import Blueprint, jsonify, request, current_app
from auth.decorators import login_required, analyst_required
from database.db_manager import db
from utils.logger import get_logger

devices_bp = Blueprint('devices', __name__)
logger = get_logger("routes_devices", "api")


def _enrich_device(d: dict) -> dict:
    """Enrich a single device dict with fingerprinting data if richer data is available."""
    try:
        from device_fingerprinting.engine import fingerprint_engine
        mac = d.get("mac_address", "")
        ip = d.get("ip_address", "")
        if not mac or mac in ("", "00:00:00:00:00:00"):
            return d
        cached = fingerprint_engine.get_cached(mac)
        if cached:
            fp = cached.to_dict()
            # Only overwrite if the engine has a better classification
            if cached.confidence > d.get("confidence", 0):
                d = dict(d)
                d.update({
                    "device_type": fp.get("device_type", d.get("device_type")),
                    "vendor": fp.get("vendor", d.get("vendor")),
                    "manufacturer": fp.get("manufacturer", d.get("manufacturer")),
                    "model": fp.get("model") or d.get("model"),
                    "os": fp.get("os", d.get("os_info", "Unknown")),
                    "os_info": fp.get("os", d.get("os_info", "Unknown")),
                    "confidence": fp.get("confidence", d.get("confidence", 0)),
                    "evidence": fp.get("evidence", d.get("evidence", [])),
                    "icon": fp.get("icon", "❓"),
                })
    except Exception:
        pass

    # Always ensure these keys exist for the frontend
    d.setdefault("manufacturer", d.get("vendor", "Unknown"))
    d.setdefault("model", "")
    d.setdefault("os", d.get("os_info", "Unknown"))
    d.setdefault("confidence", 0)
    d.setdefault("evidence", [])
    d.setdefault("icon", _device_icon(d.get("device_type", "")))
    return d


def _device_icon(device_type: str) -> str:
    """Map device type string to emoji icon."""
    try:
        from device_fingerprinting.models import DEVICE_TYPE_ICONS
        return DEVICE_TYPE_ICONS.get(device_type, "❓")
    except Exception:
        icons = {
            "Windows PC": "💻", "Windows Laptop": "💻", "Linux PC": "💻",
            "Linux Server": "🖥️", "macOS Computer": "💻",
            "iPhone": "📱", "iPad": "📱", "Android Phone": "📱",
            "Android Tablet": "📱", "Smart TV": "📺", "Printer": "🖨️",
            "Router": "📡", "Switch": "🔀", "Access Point": "📶",
            "Network Gateway": "🌐", "IoT Device": "🔌",
            "Camera / IP Camera": "📷", "NAS / Storage": "🗄️",
            "Server": "🖥️", "Virtual Machine": "🔲",
            "Network Device": "🌐", "Unknown Device": "❓",
        }
        return icons.get(device_type, "❓")


@devices_bp.route('/', methods=['GET'])
@login_required
def list_devices():
    try:
        status = request.args.get('status')
        devs = db.get_all_devices(status=status)
        real = [d for d in devs if d.get('mac_address') not in ('', '00:00:00:00:00:00')]
        result = real if real else devs
        enriched = [_enrich_device(d) for d in result]
        return jsonify(enriched)
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
        if not d:
            return jsonify({"error": "Not found"}), 404
        return jsonify(_enrich_device(d))
    except Exception as e:
        logger.error(f"get_device: {e}")
        return jsonify({"error": "Internal error"}), 500


@devices_bp.route('/<int:device_id>/fingerprint', methods=['GET'])
@login_required
def get_device_fingerprint(device_id):
    """Return full fingerprint details for a specific device."""
    try:
        d = db.get_device(device_id=device_id)
        if not d:
            return jsonify({"error": "Not found"}), 404

        mac = d.get("mac_address", "")
        ip = d.get("ip_address", "")
        force = request.args.get("refresh") == "1"

        try:
            from device_fingerprinting.engine import fingerprint_engine
            import json as _json

            open_ports = d.get("open_ports", [])
            if isinstance(open_ports, str):
                try:
                    open_ports = _json.loads(open_ports)
                except Exception:
                    open_ports = []

            fp = fingerprint_engine.fingerprint_device(
                ip=ip,
                mac=mac,
                hostname=d.get("hostname"),
                vendor=d.get("vendor"),
                is_gateway=bool(d.get("is_gateway", 0)),
                open_ports=open_ports,
                force_refresh=force,
                background_enrich=True,
            )
            return jsonify(fp.to_dict())
        except Exception as e:
            logger.warning(f"Fingerprint engine unavailable: {e}")
            return jsonify(_enrich_device(d))
    except Exception as e:
        logger.error(f"get_device_fingerprint: {e}")
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
        device = db.get_device(device_id=device_id)
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
        device = db.get_device(device_id=device_id)
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
