"""
HorusShield 2.0 — System Monitor API
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REST endpoints for live system metrics, Windows task manager process monitoring,
and audited process termination.
"""

from flask import Blueprint, jsonify, request, g
from auth.decorators import login_required, analyst_required
from services.system_monitor import system_monitor_service
from utils.logger import get_logger

sysmon_bp = Blueprint("sysmon", __name__)
logger = get_logger("routes_sysmon", "api")


@sysmon_bp.route("/overview", methods=["GET"])
@login_required
def get_overview():
    """Return real-time system metrics (CPU, RAM, Disk, Network, System Info)."""
    try:
        data = system_monitor_service.get_system_overview()
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error fetching system overview: {e}")
        return jsonify({"error": "Failed to collect system metrics"}), 500


@sysmon_bp.route("/processes", methods=["GET"])
@login_required
def get_processes():
    """Return real-time list of running Windows processes with sorting/filtering."""
    try:
        sort_by = request.args.get("sort_by", "cpu")
        order = request.args.get("order", "desc")
        limit = request.args.get("limit", 50, type=int)
        search = request.args.get("search", "")

        processes = system_monitor_service.get_processes(
            sort_by=sort_by,
            order=order,
            limit=limit,
            search=search,
        )
        return jsonify(processes)
    except Exception as e:
        logger.error(f"Error fetching processes: {e}")
        return jsonify([]), 200


@sysmon_bp.route("/process/<int:pid>", methods=["GET"])
@login_required
def get_process_details(pid):
    """Return detailed metadata for a specific PID."""
    try:
        details = system_monitor_service.get_process_details(pid)
        if details is None:
            return jsonify({"error": f"Process with PID {pid} not found"}), 404
        return jsonify(details)
    except Exception as e:
        logger.error(f"Error fetching process details for {pid}: {e}")
        return jsonify({"error": str(e)}), 500


@sysmon_bp.route("/process/<int:pid>/kill", methods=["POST"])
@analyst_required
def kill_process(pid):
    """Safely terminate a running process with audit logging."""
    try:
        user_info = getattr(g, "current_user", None) or {}
        username = user_info.get("username") or user_info.get("email") or "admin"
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()

        result = system_monitor_service.terminate_process(
            pid=pid,
            username=username,
            client_ip=client_ip,
        )
        status_code = result.get("status", 200 if result.get("success") else 400)
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error terminating process {pid}: {e}")
        return jsonify({"success": False, "error": f"Failed to terminate process: {str(e)}"}), 500