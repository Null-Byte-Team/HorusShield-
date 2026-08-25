"""
HorusShield — Shared Input Validation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository-wide validation helpers, so every blueprint validates the same
way instead of each reimplementing (or skipping) its own checks. Every
function here returns (value_or_None, error_message_or_None) — never
raises — so callers can do:

    value, err = validate_hostname(request.args.get("host"))
    if err:
        return jsonify({"error": err}), 400

Nothing here duplicates vscanner's existing target-URL/hostname validation
(api/routes_vscanner.py) or terminal's target-host validation
(api/routes_terminal.py) — those are intentionally left as-is per the
"don't modify already-verified features" rule; this module is for the
endpoints that had no validation at all.
"""
import ipaddress
import os
import re
from urllib.parse import urlparse

# ── Patterns ──
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HOSTNAME_RE = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\.)*"
    r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9])$"
)
# Filenames: letters/digits/dot/dash/underscore only — no path separators,
# no leading dot (hidden files), no null bytes. Deliberately conservative.
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,254}$")

MAX_STRING_LENGTH = 500        # generic free-text field ceiling
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024   # 2 MB — see config.MAX_CONTENT_LENGTH for the Flask-level limit


def validate_email(value):
    if not value or not isinstance(value, str):
        return None, "email is required"
    value = value.strip()
    if len(value) > 254 or not _EMAIL_RE.match(value):
        return None, "email is not a valid address"
    return value.lower(), None


def validate_hostname(value):
    if not value or not isinstance(value, str):
        return None, "hostname is required"
    value = value.strip()
    if len(value) > 253 or not _HOSTNAME_RE.match(value):
        return None, "hostname is not valid"
    return value, None


def validate_ipv4(value):
    if not value or not isinstance(value, str):
        return None, "IPv4 address is required"
    try:
        ipaddress.IPv4Address(value.strip())
        return value.strip(), None
    except ValueError:
        return None, "not a valid IPv4 address"


def validate_ipv6(value):
    if not value or not isinstance(value, str):
        return None, "IPv6 address is required"
    try:
        ipaddress.IPv6Address(value.strip())
        return value.strip(), None
    except ValueError:
        return None, "not a valid IPv6 address"


def validate_ip(value):
    """Accepts either IPv4 or IPv6."""
    if not value or not isinstance(value, str):
        return None, "IP address is required"
    try:
        ipaddress.ip_address(value.strip())
        return value.strip(), None
    except ValueError:
        return None, "not a valid IP address (v4 or v6)"


def validate_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None, "port must be an integer"
    if not (1 <= port <= 65535):
        return None, "port must be between 1 and 65535"
    return port, None


def validate_url(value, require_scheme=("http", "https")):
    """General-purpose URL validator. NOTE: routes_vscanner.py has its own
    _validate_target_url() with V-8-Scanner-specific behavior (auto-prepend
    http://, etc.) that is intentionally left untouched — this is the
    generic version for any other endpoint that takes a URL."""
    if not value or not isinstance(value, str):
        return None, "url is required"
    value = value.strip()
    if len(value) > 2048:
        return None, "url is too long"
    try:
        parsed = urlparse(value)
    except Exception:
        return None, "url could not be parsed"
    if parsed.scheme not in require_scheme:
        return None, f"url must use one of: {', '.join(require_scheme)}"
    if not parsed.hostname or not _HOSTNAME_RE.match(parsed.hostname):
        return None, "url has an invalid hostname"
    return value, None


def validate_filename(value, allowed_extensions=None):
    """Strict allowlist-pattern filename check — rejects anything with a
    path separator, leading dot, or character outside [A-Za-z0-9._-].
    Use this in addition to (not instead of) os.path.basename() +
    a resolved-path containment check at the call site — see
    safe_join_and_verify() below for that second layer."""
    if not value or not isinstance(value, str):
        return None, "filename is required"
    value = value.strip()
    if not _SAFE_FILENAME_RE.match(value):
        return None, "filename contains invalid characters"
    if allowed_extensions:
        ext = value.rsplit(".", 1)[-1].lower() if "." in value else ""
        if ext not in allowed_extensions:
            return None, f"filename extension must be one of: {', '.join(allowed_extensions)}"
    return value, None


def safe_join_and_verify(base_dir, filename):
    """Defense-in-depth for file downloads: join with os.path.basename()
    (already traversal-safe on both POSIX and Windows — ntpath.basename
    splits on both '/' and '\\'), then additionally verify the resolved
    absolute path is still inside base_dir before returning it. Returns
    (full_path_or_None, error_or_None).
    """
    safe_name = os.path.basename(filename)
    candidate = os.path.realpath(os.path.join(base_dir, safe_name))
    base_real = os.path.realpath(base_dir)
    if os.path.commonpath([candidate, base_real]) != base_real:
        return None, "invalid filename"
    return candidate, None


def validate_positive_int(value, field_name="value", max_value=None):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None, f"{field_name} must be an integer"
    if n < 0:
        return None, f"{field_name} must be non-negative"
    if max_value is not None and n > max_value:
        return None, f"{field_name} must be <= {max_value}"
    return n, None


def validate_bool(value, field_name="value"):
    if isinstance(value, bool):
        return value, None
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true", None
    return None, f"{field_name} must be true or false"


def validate_enum(value, allowed, field_name="value"):
    if value not in allowed:
        return None, f"{field_name} must be one of: {', '.join(map(str, allowed))}"
    return value, None


def validate_string(value, field_name="value", max_length=MAX_STRING_LENGTH, required=True):
    if value is None or value == "":
        if required:
            return None, f"{field_name} is required"
        return "", None
    if not isinstance(value, str):
        return None, f"{field_name} must be a string"
    if len(value) > max_length:
        return None, f"{field_name} must be at most {max_length} characters"
    return value, None
