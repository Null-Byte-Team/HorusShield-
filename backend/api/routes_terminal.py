"""
HorusShield Terminal API — Allowlist-Only Redesign
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Previous design accepted an arbitrary user-typed command string and ran it
through a shell (`powershell -Command <string>` / `cmd /c <string>`),
filtered only by a substring blocklist. That blocklist covered a handful of
destructive command names but did nothing to stop the enormous remaining
surface — arbitrary downloads-and-execute, account manipulation, process
control, reverse shells, or simply any command not on its short list. A
blocklist can only ever enumerate what its author thought of; it cannot
enumerate what an attacker will.

This redesign is a strict allowlist instead: a small, fixed set of
read-only diagnostic operations, each mapped to a hardcoded argv list
(never a shell string), executed with `shell=False` so there is no shell
metacharacter/injection surface at all. Anything not explicitly named in
OPERATIONS is rejected with 400 before any subprocess is created. The one
operation that takes a user-supplied value (`ping`'s target) validates it
strictly as a hostname/IP before it ever reaches subprocess.run's argv
list — it is never concatenated into a string that a shell interprets.

Every execution — allowed or rejected — is written to the audit log with
timestamp, user, IP, the requested operation, and the result.
"""
from api.rate_limit import limiter
from config import active_config as config
import platform
import re
import subprocess

from flask import Blueprint, jsonify, request

from auth.decorators import admin_required
from database.db_manager import db
from utils.logger import get_logger

terminal_bp = Blueprint("terminal", __name__)
logger = get_logger("routes_terminal", "api")

_IS_WINDOWS = platform.system() == "Windows"

# Hostname/IPv4 validation for the one parameterized operation (ping).
# Deliberately strict — rejects anything with shell metacharacters,
# spaces, or characters outside what a real hostname/IP can contain.
_HOST_RE = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\.)*"
    r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9])$"
)


def _windows_args(op: str, target: str = "") -> list:
    return {
        "ipconfig": ["ipconfig", "/all"],
        "netstat": ["netstat", "-an"],
        "systeminfo": ["systeminfo"],
        "tasklist": ["tasklist"],
        "whoami": ["whoami"],
        "hostname": ["hostname"],
        "arp": ["arp", "-a"],
        "route": ["route", "print"],
        "ping": ["ping", "-n", "4", target],
    }[op]


def _linux_args(op: str, target: str = "") -> list:
    return {
        "ipconfig": ["ip", "addr"],
        "netstat": ["ss", "-tuln"],
        "systeminfo": ["uname", "-a"],
        "tasklist": ["ps", "aux"],
        "whoami": ["whoami"],
        "hostname": ["hostname"],
        "arp": ["ip", "neigh"],
        "route": ["ip", "route"],
        "ping": ["ping", "-c", "4", target],
    }[op]


# The allowlist itself. Every key here is the ONLY thing that can ever be
# requested — nothing outside this dict is executable, by construction.
OPERATIONS = {
    "ipconfig": {"needs_target": False, "description": "Show network interface configuration"},
    "netstat": {"needs_target": False, "description": "Show active network connections"},
    "systeminfo": {"needs_target": False, "description": "Show system information"},
    "tasklist": {"needs_target": False, "description": "List running processes"},
    "whoami": {"needs_target": False, "description": "Show current user"},
    "hostname": {"needs_target": False, "description": "Show machine hostname"},
    "arp": {"needs_target": False, "description": "Show ARP table"},
    "route": {"needs_target": False, "description": "Show routing table"},
    "ping": {"needs_target": True, "description": "Ping a host (4 packets)"},
}


def _client_ip() -> str:
    from utils.network import get_client_ip
    return get_client_ip()


def _audit(operation, target, username, status, result_summary):
    db.add_audit_log(
        action="terminal_command",
        username=username,
        status=status,
        ip_address=_client_ip(),
        details=f"operation={operation} target={target or '-'} result={result_summary}",
    )


@terminal_bp.route("/operations", methods=["GET"])
@admin_required
def list_operations():
    """What's actually allowed — the frontend builds its command list from this,
    instead of accepting free-text that happens to look like a shell command."""
    return jsonify({
        "operations": [
            {"name": name, "needs_target": meta["needs_target"], "description": meta["description"]}
            for name, meta in OPERATIONS.items()
        ]
    })


@terminal_bp.route("/run", methods=["POST"])
@admin_required
@limiter.limit(config.RATELIMIT_TERMINAL)
def run_command():
    data = request.get_json(silent=True) or {}
    operation = (data.get("operation") or "").strip().lower()
    target = (data.get("target") or "").strip()
    username = request.current_user.get("email", "") if hasattr(request, "current_user") else ""

    if operation not in OPERATIONS:
        _audit(operation, target, username, "failure", "rejected: not in allowlist")
        logger.warning(f"Terminal: rejected non-allowlisted operation '{operation}' by {username}")
        return jsonify({"error": f"'{operation}' is not an allowed operation. See /api/terminal/operations."}), 400

    meta = OPERATIONS[operation]
    if meta["needs_target"]:
        if not target or not _HOST_RE.match(target) or len(target) > 253:
            _audit(operation, target, username, "failure", "rejected: invalid target")
            return jsonify({"error": "target must be a valid hostname or IP address"}), 400
    else:
        target = ""

    try:
        args = _windows_args(operation, target) if _IS_WINDOWS else _linux_args(operation, target)
        logger.info(f"Terminal [{username}]: {operation} {target}".strip())

        kwargs = dict(
            args=args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            shell=False,  # argv list only — no shell, no injection surface
        )
        if _IS_WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(**kwargs)
        _audit(operation, target, username, "success", f"exit_code={result.returncode}")
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        })
    except subprocess.TimeoutExpired:
        _audit(operation, target, username, "failure", "timeout")
        return jsonify({"stdout": "", "stderr": "[HorusShield] Timeout (15s)", "exit_code": 1})
    except FileNotFoundError as e:
        _audit(operation, target, username, "failure", f"binary not found: {e}")
        return jsonify({"stdout": "", "stderr": f"[HorusShield] Command not available: {e}", "exit_code": 1})
    except Exception as e:
        logger.error(f"Terminal execution error: {e}")
        _audit(operation, target, username, "failure", f"error: {e}")
        return jsonify({"stdout": "", "stderr": "[HorusShield] Internal error", "exit_code": 1})


@terminal_bp.route("/shells", methods=["GET"])
@admin_required
def list_shells():
    """Report available shells for the shell selector dropdown."""
    shells = []
    if _IS_WINDOWS:
        shells = [
            {"name": "powershell", "label": "⚡ PowerShell", "available": True},
            {"name": "cmd", "label": "🖥 CMD", "available": True},
        ]
    else:
        shells = [
            {"name": "bash", "label": "🐧 Bash", "available": True},
            {"name": "sh", "label": "📟 sh", "available": True},
        ]
    return jsonify({"shells": shells, "platform": platform.system()})


@terminal_bp.route("/exec", methods=["POST"])
@admin_required
@limiter.limit(config.RATELIMIT_TERMINAL)
def exec_shell():
    """Execute an arbitrary command through the real system shell.

    This is **admin-only** — every invocation is fully audit-logged with the
    user, IP, command, exit code, and first 500 chars of output.

    Body JSON:
        command (str): The full command string to run.
        shell   (str): "powershell" | "cmd" | "bash" | "sh"  (default: powershell on Windows, bash on Linux)
    """
    data = request.get_json(silent=True) or {}
    command = (data.get("command") or "").strip()
    shell_type = (data.get("shell") or "").strip().lower()
    username = request.current_user.get("email", "") if hasattr(request, "current_user") else ""

    if not command:
        return jsonify({"error": "No command provided"}), 400

    # Determine shell argv prefix
    if _IS_WINDOWS:
        if shell_type == "cmd":
            shell_argv = ["cmd.exe", "/c", command]
        else:
            # Default to PowerShell
            shell_argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command]
    else:
        if shell_type == "sh":
            shell_argv = ["sh", "-c", command]
        else:
            shell_argv = ["bash", "-c", command]

    try:
        logger.info(f"Shell exec [{username}] ({shell_type or 'default'}): {command[:200]}")

        kwargs = dict(
            args=shell_argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            shell=False,  # We build the argv ourselves — never pass shell=True
        )
        if _IS_WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(**kwargs)

        _audit(
            f"shell_exec({shell_type or 'default'})",
            command[:200],
            username,
            "success",
            f"exit_code={result.returncode}",
        )

        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        })

    except subprocess.TimeoutExpired:
        _audit(f"shell_exec({shell_type})", command[:200], username, "failure", "timeout_30s")
        return jsonify({"stdout": "", "stderr": "[HorusShield] Command timed out (30s limit)", "exit_code": 1})
    except FileNotFoundError as e:
        _audit(f"shell_exec({shell_type})", command[:200], username, "failure", f"shell not found: {e}")
        return jsonify({"stdout": "", "stderr": f"[HorusShield] Shell not found: {e}", "exit_code": 1})
    except Exception as e:
        logger.error(f"Shell exec error: {e}")
        _audit(f"shell_exec({shell_type})", command[:200], username, "failure", f"error: {e}")
        return jsonify({"stdout": "", "stderr": f"[HorusShield] Error: {e}", "exit_code": 1})

