"""
HorusShield — Shared Auth Decorators
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Single source of truth for endpoint authentication/authorization, so every
blueprint uses the same logic instead of each reimplementing (or skipping)
its own auth check.

Role model: `users.role` (see database/models.py) is a plain string column,
currently either 'admin' or 'analyst'. Every user created before this role
model existed defaults to 'admin' (the column's DB default), so no existing
account loses access — this mirrors the frontend's pre-existing login/token
flow (see HorusShield_UI.html's authState), which was already built and
simply never had server-side enforcement wired up until now.

Hierarchy: admin > analyst > (authenticated, no specific role requirement).
An admin can do anything an analyst can; analyst_required rejects a plain
non-privileged/unknown role the same way login_required rejects no token
at all.
"""
from functools import wraps

from flask import jsonify, request

from auth.auth_manager import auth_manager
from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("auth_decorators", "api")

_ADMIN_ROLES = {"admin"}
_ANALYST_ROLES = {"admin", "analyst"}


def _extract_token():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    if auth_header:
        return auth_header.strip()
    query_token = request.args.get("token", "").strip()
    if query_token:
        return query_token
    cookie_token = request.cookies.get("token", "").strip()
    if cookie_token:
        return cookie_token
    return ""


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def login_required(f):
    """Require a valid Bearer token. Sets request.current_user on success."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        user = auth_manager.validate_token(token)
        if not user:
            return jsonify({"error": "Invalid or expired session"}), 401
        request.current_user = user
        return f(*args, **kwargs)

    return decorated


def _role_required(allowed_roles, label):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = _extract_token()
            if not token:
                return jsonify({"error": "Authentication required"}), 401
            user = auth_manager.validate_token(token)
            if not user:
                return jsonify({"error": "Invalid or expired session"}), 401
            role = (user.get("role") or "").lower()
            if role not in allowed_roles:
                logger.warning(
                    f"Authorization denied: user={user.get('email','?')} role={role} "
                    f"required={label} endpoint={request.path} ip={_client_ip()}"
                )
                db.add_audit_log(
                    action="authorization_denied",
                    username=user.get("email", ""),
                    status="failure",
                    ip_address=_client_ip(),
                    details=f"endpoint={request.path} role={role} required={label}",
                )
                return jsonify({"error": f"{label.capitalize()} privileges required"}), 403
            request.current_user = user
            return f(*args, **kwargs)

        return decorated

    return decorator


def admin_required(f):
    """Require an authenticated user with the 'admin' role."""
    return _role_required(_ADMIN_ROLES, "admin")(f)


def analyst_required(f):
    """Require an authenticated user with 'admin' or 'analyst' role."""
    return _role_required(_ANALYST_ROLES, "analyst")(f)
