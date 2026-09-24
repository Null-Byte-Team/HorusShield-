"""HorusShield V-8 Scanner API"""
from api.rate_limit import limiter
from config import active_config as config
import os
import re
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request, send_file, current_app

from database.db_manager import db
from services.vscan_report_generator import VScanReportGenerator
from utils.logger import get_logger
from utils.network import get_client_ip
from auth.decorators import login_required, analyst_required

vscanner_bp = Blueprint("vscanner", __name__)
logger = get_logger("routes_vscanner", "api")
report_gen = VScanReportGenerator()

_VALID_TOOLS = {"nmap"}
_VALID_REPORT_FORMATS = {"pdf", "html", "json"}


def _get_manager():
    """Retrieve the VScannerManager instance via Flask's app.extensions —
    the same DI mechanism routes_devices.py uses for device_blocker, rather
    than a separate module-global set_manager() pattern. Standardized on
    one approach across the codebase (see docs/PROJECT_STRUCTURE.md)."""
    return current_app.extensions.get("vscanner")


# RFC 1123-ish hostname check: labels of letters/digits/hyphens, dot-separated,
# OR a literal IPv4 address. Rejects spaces and other characters urlparse()
# alone will happily accept into `.hostname` without complaint.
_HOSTNAME_RE = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\.)*"
    r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9])$"
)


def _validate_target_url(raw: str):
    """Parse and validate a target URL with urllib.parse instead of a bare
    startswith() check. Returns (normalized_url, error_message_or_None).

    Two layers, deliberately: the hostname-format regex below catches
    malformed input cheaply before any network call; security.ssrf's
    validate_target() then resolves the hostname and rejects any target
    that points at a private/loopback/link-local/multicast/reserved
    address (including the cloud metadata endpoint) — this closes a
    confirmed SSRF finding where the format check alone let 127.0.0.1,
    RFC1918 ranges, and 169.254.169.254 straight through.
    """
    raw = (raw or "").strip()
    if not raw:
        return None, "target_url is required"
    if " " in raw or "\t" in raw:
        return None, "target_url must not contain whitespace"
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except Exception:
        return None, "target_url could not be parsed"
    if parsed.scheme not in ("http", "https"):
        return None, "target_url must use http or https"
    host = parsed.hostname
    if not host or not _HOSTNAME_RE.match(host):
        return None, "target_url has an invalid hostname"

    from security.ssrf import SSRFValidationError, validate_target

    try:
        validate_target(parsed.geturl(), allow_private=config.VSCAN_ALLOW_PRIVATE_TARGETS)
    except SSRFValidationError as e:
        logger.warning(f"SSRF-protected target rejected: {host} — {e}")
        return None, str(e)

    return parsed.geturl(), None


def _client_ip() -> str:
    return get_client_ip()


def _is_owner_or_admin(scan: dict, current_user: dict) -> bool:
    """Ownership check for the IDOR fix: a confirmed Red Team finding
    showed any authenticated user could read/delete any other user's scan.
    Admins can access everything; everyone else only their own.
    NULL owner_id (a legacy scan created before ownership was enforced) is
    treated as admin-only-accessible, not "everyone's" — safer default.
    """
    if (current_user.get("role") or "").lower() == "admin":
        return True
    owner_id = scan.get("owner_id")
    if owner_id is None:
        return False
    return owner_id == current_user.get("id")


@vscanner_bp.route("/tools", methods=["GET"])
@login_required
def check_tools():
    """Return availability status for each external scanner tool."""
    manager = _get_manager()
    if manager is None:
        return jsonify({"tools": {"nmap": False, "zap": False, "nikto": False, "sqlmap": False}, "details": {}}), 200
    from vscanner.tool_discovery import health
    status = health(
        config.NMAP_PATH,
        getattr(config, "ZAP_PATH", ""),
        getattr(config, "NIKTO_PATH", ""),
        getattr(config, "SQLMAP_PATH", "")
    )
    return jsonify({
        "tools": {name: details.get("available", False) for name, details in status.items()},
        "details": status,
    }), 200


@vscanner_bp.route("/scan/start", methods=["POST"])
@analyst_required
@limiter.limit(config.RATELIMIT_SCANNER)
def start_scan():
    try:
        data = request.get_json(silent=True) or {}
        target_url, err = _validate_target_url(data.get("target_url"))
        if err:
            return jsonify({"error": err}), 400

        requested_tools = data.get("tools") or ["nmap"]
        if not isinstance(requested_tools, list) or not all(isinstance(t, str) for t in requested_tools):
            return jsonify({"error": "tools must be a list of strings"}), 400
        tools = [t for t in requested_tools if t in _VALID_TOOLS]
        if not tools:
            return jsonify({"error": f"tools must include at least one of {sorted(_VALID_TOOLS)}"}), 400

        if data.get("active_scan"):
            return jsonify({
            "error": "Active scanning is not available. The web scanner currently supports Nmap only."
            }), 400
        active_scan = False
        manager = _get_manager()
        if manager is None:
            return jsonify({"error": "Scanner not initialized"}), 500

        # requested_by is display-only metadata, always derived from the
        # authenticated session — never taken from the request body. It
        # used to accept an arbitrary client-supplied string here, which
        # meant it couldn't be trusted for anything; owner_id (below) is
        # what authorization actually checks.
        current_user = request.current_user
        requested_by = current_user.get("email", "")
        result = manager.start_scan(
            target_url=target_url,
            tools=tools,
            active_scan=active_scan,
            requested_by=requested_by,
            owner_id=current_user.get("id"),
        )
        db.add_audit_log(
            action="scan_started",
            username=requested_by,
            status="success" if result.get("success") else "failure",
            ip_address=_client_ip(),
            details=f"target={target_url} tools={tools} active_scan={active_scan}"
                    + ("" if result.get("success") else f" error={result.get('error')}"),
        )
        if not result.get("success"):
            return jsonify({"error": result.get("error", "Failed to start scan")}), 409
        return jsonify(result)
    except Exception as e:
        logger.error(f"start_scan: {e}")
        return jsonify({"error": "Internal error"}), 500


@vscanner_bp.route("/scan/<scan_id>/stop", methods=["POST"])
@analyst_required
def stop_scan(scan_id):
    try:
        scan = db.get_vscan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if not _is_owner_or_admin(scan, request.current_user):
            db.add_audit_log(
                action="authorization_denied", username=request.current_user.get("email", ""),
                status="failure", ip_address=_client_ip(),
                details=f"endpoint=stop_scan scan_id={scan_id} not owner",
            )
            return jsonify({"error": "You do not have access to this scan"}), 403
        manager = _get_manager()
        if manager is None:
            return jsonify({"error": "Scanner not initialized"}), 500
        result = manager.stop_scan(scan_id)
        if not result.get("success"):
            return jsonify({"error": result.get("error", "Could not stop scan")}), 404
        return jsonify(result)
    except Exception as e:
        logger.error(f"stop_scan: {e}")
        return jsonify({"error": "Internal error"}), 500


@vscanner_bp.route("/scan/<scan_id>/status", methods=["GET"])
@login_required
def scan_status(scan_id):
    try:
        scan = db.get_vscan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if not _is_owner_or_admin(scan, request.current_user):
            return jsonify({"error": "You do not have access to this scan"}), 403
        return jsonify(scan)
    except Exception as e:
        logger.error(f"scan_status: {e}")
        return jsonify({"error": "Internal error"}), 500


@vscanner_bp.route("/scan/<scan_id>", methods=["GET"])
@login_required
def scan_details(scan_id):
    try:
        scan = db.get_vscan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if not _is_owner_or_admin(scan, request.current_user):
            return jsonify({"error": "You do not have access to this scan"}), 403
        findings = db.get_vscan_findings(scan_id)
        reports = db.get_vscan_reports(scan_id)
        return jsonify({"scan": scan, "findings": findings, "reports": reports})
    except Exception as e:
        logger.error(f"scan_details: {e}")
        return jsonify({"error": "Internal error"}), 500


@vscanner_bp.route("/scan/<scan_id>", methods=["DELETE"])
@analyst_required
def delete_scan(scan_id):
    try:
        scan = db.get_vscan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if not _is_owner_or_admin(scan, request.current_user):
            db.add_audit_log(
                action="authorization_denied", username=request.current_user.get("email", ""),
                status="failure", ip_address=_client_ip(),
                details=f"endpoint=delete_scan scan_id={scan_id} not owner",
            )
            return jsonify({"error": "You do not have access to this scan"}), 403
        deleted = db.delete_vscan(scan_id)
        if not deleted:
            return jsonify({"error": "Scan not found"}), 404
        db.add_audit_log(
            action="scan_deleted", username=request.current_user.get("email", ""),
            ip_address=_client_ip(), details=f"scan_id={scan_id}",
        )
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"delete_scan: {e}")
        return jsonify({"error": "Internal error"}), 500


@vscanner_bp.route("/history", methods=["GET"])
@login_required
def scan_history():
    try:
        limit = request.args.get("limit", 50, type=int)
        limit = max(1, min(limit, 200))  # clamp to a sane range
        current_user = request.current_user
        is_admin = (current_user.get("role") or "").lower() == "admin"
        owner_filter = None if is_admin else current_user.get("id")
        return jsonify(db.get_vscans(limit=limit, owner_id=owner_filter))
    except Exception as e:
        logger.error(f"scan_history: {e}")
        return jsonify([]), 200


@vscanner_bp.route("/scan/<scan_id>/report/<fmt>", methods=["GET"])
@login_required
def generate_and_download_report(scan_id, fmt):
    try:
        fmt = (fmt or "").lower().strip()
        if fmt not in _VALID_REPORT_FORMATS:
            return jsonify({"success": False, "error": f"format must be one of {sorted(_VALID_REPORT_FORMATS)}"}), 400
        scan = db.get_vscan(scan_id)
        if not scan:
            return jsonify({"success": False, "error": "Scan not found"}), 404
        if not _is_owner_or_admin(scan, request.current_user):
            return jsonify({"success": False, "error": "You do not have access to this scan"}), 403

        path = report_gen.generate(scan_id, fmt)
        if not path or not os.path.exists(path):
            return jsonify({"success": False, "error": "Failed to generate report"}), 500

        # Validate PDF signature if PDF requested
        if fmt == "pdf":
            try:
                with open(path, "rb") as fp:
                    if not fp.read(4).startswith(b"%PDF"):
                        logger.error(f"Generated PDF file {path} has invalid signature")
                        return jsonify({"success": False, "error": "PDF report generation failed"}), 500
            except Exception as e:
                logger.error(f"Failed to verify PDF signature for {path}: {e}")
                return jsonify({"success": False, "error": "PDF report generation failed"}), 500

        db.add_audit_log(
            action="report_generated",
            username=request.current_user.get("email", ""),
            ip_address=_client_ip(),
            details=f"scan_id={scan_id} format={fmt}",
        )

        mimetypes = {
            "pdf": "application/pdf",
            "html": "text/html",
            "json": "application/json",
        }
        safe_scan_id = re.sub(r"[^a-zA-Z0-9_\-]", "", str(scan_id))
        download_filename = f"HorusShield_WebScan_Report_{safe_scan_id}.{fmt}"

        # If user explicitly requests ?download=1, force attachment; otherwise display inline in browser viewer
        as_attachment = request.args.get("download", "0").lower() in ("1", "true", "yes")

        return send_file(
            path,
            mimetype=mimetypes.get(fmt, "application/octet-stream"),
            as_attachment=as_attachment,
            download_name=download_filename,
        )
    except ValueError as e:
        logger.warning(f"generate_and_download_report validation error: {e}")
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.exception(f"Web Scanner report generation failed for scan_id={scan_id} format={fmt}: {e}")
        return jsonify({"success": False, "error": "PDF report generation failed"}), 500
