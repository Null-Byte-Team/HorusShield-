"""HorusShield Reports API"""
from api.rate_limit import limiter
from config import active_config as config
from flask import Blueprint, jsonify, request, send_file
from database.db_manager import db
from services.report_generator import ReportGenerator
from utils.logger import get_logger
import os
from auth.decorators import login_required, analyst_required
from utils.network import get_client_ip

reports_bp = Blueprint('reports', __name__)
logger     = get_logger("routes_reports","report")
generator  = ReportGenerator()

@reports_bp.route('/generate', methods=['POST'])
@analyst_required
@limiter.limit(config.RATELIMIT_REPORTS)
def generate_report():
    try:
        data     = request.get_json(silent=True) or {}
        facility = data.get('facility_name', data.get('name','Facility'))
        language = data.get('language','en')
        path     = generator.generate_daily_report(facility_name=facility, language=language)
        ip = get_client_ip()
        if path and os.path.exists(path):
            db.add_audit_log(action="reports_generated", ip_address=ip,
                              details=f"facility={facility} language={language} file={os.path.basename(path)}")
            return jsonify({"success":True,"message":"Report generated","filename":os.path.basename(path)})
        db.add_audit_log(action="reports_generated", status="failure", ip_address=ip,
                          details=f"facility={facility} language={language}")
        return jsonify({"error":"Failed to generate report"}), 500
    except Exception as e:
        logger.error(f"generate: {e}")
        return jsonify({"error":str(e)}), 500

@reports_bp.route('/download/<filename>', methods=['GET'])
@login_required
def download_report(filename):
    try:
        # os.path.basename() already strips traversal on both POSIX and
        # Windows (ntpath.basename splits on both '/' and '\'), but this
        # adds a second, independent check — the resolved absolute path
        # must still be inside the reports directory — rather than relying
        # on a single layer of defense against path traversal.
        from utils.validation import safe_join_and_verify
        path, err = safe_join_and_verify(generator.output_dir, filename)
        if err:
            return jsonify({"error": err}), 400
        if os.path.exists(path):
            return send_file(path, as_attachment=True)
        return jsonify({"error":"File not found"}), 404
    except Exception as e:
        logger.error(f"download_report failed for {filename}: {e}")
        return jsonify({"error":"Internal error"}), 500

@reports_bp.route('/list', methods=['GET'])
@login_required
def list_reports():
    try:
        files=[]
        for f in sorted(os.listdir(generator.output_dir), reverse=True):
            if f.endswith('.pdf'):
                full=os.path.join(generator.output_dir,f)
                files.append({"filename":f,"size_kb":os.path.getsize(full)//1024,"created":os.path.getmtime(full)})
        return jsonify(files[:20])
    except Exception as e:
        logger.error(f"list_reports failed: {e}")
        return jsonify([]), 200
