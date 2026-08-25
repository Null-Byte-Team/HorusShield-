"""HorusShield Horus API"""
from flask import Blueprint, jsonify, request
from services.horus_assistant import HorusAssistant
from utils.logger import get_logger
from utils.validation import validate_string
from auth.decorators import login_required

horus_bp = Blueprint('horus', __name__)
logger   = get_logger("routes_horus", "api")
_assistant = HorusAssistant()


@horus_bp.route('/ask', methods=['POST'])
@login_required
def ask_horus():
    try:
        data     = request.get_json(silent=True) or {}
        query, err = validate_string(data.get('query'), field_name="query", max_length=2000)
        if err:
            return jsonify({"error": err}), 400
        language = data.get('language', 'en')
        if language not in ('en', 'ar'):
            return jsonify({"error": "language must be 'en' or 'ar'"}), 400
        user_id, err = validate_string(data.get('user_id', 'default'), field_name="user_id", max_length=100, required=False)
        if err:
            return jsonify({"error": err}), 400
        response, engine = _assistant.ask_with_engine(query, language=language, user_id=user_id or 'default')
        return jsonify({"response": response, "engine": engine})
    except Exception as e:
        logger.error(f"Horus route error: {e}")
        return jsonify({"error": "Internal error"}), 500


@horus_bp.route('/history', methods=['GET'])
@login_required
def get_history():
    user_id = request.args.get('user_id', 'default')
    return jsonify(_assistant.get_history(user_id))


@horus_bp.route('/clear', methods=['POST'])
@login_required
def clear_history():
    user_id = (request.get_json(silent=True) or {}).get('user_id', 'default')
    cleared = _assistant.clear_history(user_id)
    return jsonify({"cleared": cleared})
