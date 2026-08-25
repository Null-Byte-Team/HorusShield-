"""HorusShield AI API — Fixed"""
from api.rate_limit import limiter
from config import active_config as config
from flask import Blueprint, jsonify, request
from database.db_manager import db
from utils.logger import get_logger
from datetime import datetime
from auth.decorators import login_required, admin_required
from utils.network import get_client_ip

ai_bp = Blueprint('ai', __name__)
logger = get_logger("routes_ai", "api")

_trainer_ref = {"instance": None}

def set_trainer(trainer):
    _trainer_ref["instance"] = trainer

def _trainer():
    return _trainer_ref["instance"]


@ai_bp.route('/predictions', methods=['GET'])
@login_required
def get_predictions():
    try:
        preds = db.get_recent_predictions(limit=20)
        return jsonify(preds if preds else [])
    except Exception as e:
        logger.error(f"predictions: {e}")
        return jsonify([]), 200


@ai_bp.route('/anomalies', methods=['GET'])
@login_required
def get_anomalies():
    try:
        anoms = db.get_attacks(attack_type='anomaly', limit=20)
        return jsonify(anoms if anoms else [])
    except Exception as e:
        logger.error(f"anomalies: {e}")
        return jsonify([]), 200


@ai_bp.route('/train/status', methods=['GET'])
@login_required
def get_train_status():
    try:
        t = _trainer()
        progress = t.get_progress() if t else {"stage": "idle", "percent": 0, "model": None}
        return jsonify({
            "status": "running" if t and getattr(t,'_running',False) else "idle",
            "progress": progress,
            "last_trained": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "models": [
                {"name": "anomaly_detector",  "loaded": bool(t and getattr(getattr(t,'anomaly_detector',None),'model',None))},
                {"name": "attack_predictor",  "loaded": bool(t and getattr(getattr(t,'attack_predictor',None),'model',None))},
                {"name": "threat_classifier", "loaded": bool(t and getattr(getattr(t,'threat_classifier',None),'model',None))},
            ]
        })
    except Exception as e:
        logger.error(f"train status: {e}")
        return jsonify({"status": "idle", "progress": {}, "models": []}), 200


@ai_bp.route('/train/metadata', methods=['GET'])
@login_required
def get_train_metadata():
    """Real training metrics per model — accuracy/precision/recall/F1 for
    the classifier, MSE/MAE/R2 for the regressor, self-consistency rate for
    the unsupervised anomaly detector. Any metric that doesn't apply to a
    given model type is null, with metrics_note explaining why (see
    ai/threat_classifier.py, ai/attack_predictor.py, ai/anomaly_detector.py
    train() docstrings) — never a fabricated number."""
    try:
        model_name = request.args.get('model')
        limit = request.args.get('limit', 10, type=int)
        limit = max(1, min(limit, 100))
        if model_name and model_name not in ("anomaly_detector", "attack_predictor", "threat_classifier"):
            return jsonify({"error": "model must be one of: anomaly_detector, attack_predictor, threat_classifier"}), 400
        return jsonify(db.get_model_metadata(model_name=model_name, limit=limit))
    except Exception as e:
        logger.error(f"train metadata: {e}")
        return jsonify([]), 200


@ai_bp.route('/train', methods=['POST'])
@admin_required
@limiter.limit(config.RATELIMIT_AI)
def trigger_training():
    try:
        t = _trainer()
        if not t:
            return jsonify({"error": "AI trainer not initialized"}), 503
        data = request.get_json(silent=True) or {}
        training_type = data.get('type', 'history')
        if training_type not in ('history', 'synthetic'):
            return jsonify({"error": "'type' must be 'history' or 'synthetic'"}), 400
        if training_type == 'history':
            result = t.train_on_history()
        else:
            result = t.train_on_synthetic_data()
        db.add_audit_log(
            action="ai_analysis", status="success" if result else "failure",
            ip_address=get_client_ip(),
            details=f"type={training_type}",
        )
        return jsonify({"success": result, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        logger.error(f"train: {e}")
        return jsonify({"error": str(e)}), 500
