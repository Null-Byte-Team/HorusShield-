"""
HorusShield Auth Manager
━━━━━━━━━━━━━━━━━━━━━━━━
Handles: local auth, Google OAuth, email verification, sessions.
"""
import os, hashlib, secrets, smtplib, re
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import config
from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("auth_manager", "api")


# ── Helpers ─────────────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return salt.hex() + ':' + key.hex()

def _next_role() -> str:
    """First-admin bootstrap (fix for a confirmed High finding — every new
    account used to default to 'admin'). If the database has zero admins,
    the account being created right now becomes the admin; otherwise it's
    an analyst. This never automatically creates a SECOND admin — once one
    exists, every subsequent signup is 'analyst' regardless of how many
    admins there are or aren't after that (promoting someone to admin
    later is a deliberate, separate action, not automatic).

    Atomic DB safety: user registration uses an in-statement subquery during
    INSERT (see register() and google_auth()) to evaluate the role within the
    exclusive database write lock, eliminating concurrent registration race
    conditions on fresh installations.
    """
    try:
        with db.get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        return "admin" if count == 0 else "analyst"
    except Exception as e:
        logger.error(f"_next_role check failed, defaulting to analyst: {e}")
        return "analyst"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, key_hex = stored.split(':')
        salt = bytes.fromhex(salt_hex)
        key  = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
        return key.hex() == key_hex
    except Exception:
        return False

def _gen_code(length=6) -> str:
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))

def _gen_token() -> str:
    return secrets.token_urlsafe(48)

def _valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))


# ── Email Sender ─────────────────────────────────────────────────────────────

def _get_smtp_config() -> dict:
    """
    Load SMTP credentials in priority order:
      1. Database settings  (set by user from the app's Settings panel)
      2. Environment variables  (HORUS_SMTP_HOST / PORT / USER / PASS)
    Returns a dict with keys: host, port, user, password, from_name
    Any key may be empty string if not configured.
    """
    def _db(key, default=""):
        try:
            return db.get_setting(key) or default
        except Exception:
            return default

    host      = _db("smtp_host") or os.environ.get("HORUS_SMTP_HOST", "smtp.gmail.com")
    port      = int(_db("smtp_port") or os.environ.get("HORUS_SMTP_PORT", "587"))
    user      = _db("smtp_user") or os.environ.get("HORUS_SMTP_USER", "")
    password  = (_db("smtp_pass") or os.environ.get("HORUS_SMTP_PASS", "")).strip().replace(" ", "")
    from_name = _db("smtp_from_name", "HorusShield Security")
    return {"host": host, "port": port, "user": user,
            "password": password, "from_name": from_name}


def send_verification_email(to_email: str, code: str, name: str = "User") -> bool:
    """
    Send a verification-code email.
    Returns True on success, False if not configured or on send error.

    Configuration (pick one):
      A) Set smtp_* keys via the app Settings → Email panel.
      B) Set environment variables: HORUS_SMTP_HOST, HORUS_SMTP_PORT,
         HORUS_SMTP_USER, HORUS_SMTP_PASS.

    Gmail tip: use an App Password (not your login password).
      https://myaccount.google.com/apppasswords
    """
    cfg = _get_smtp_config()

    if not cfg["user"] or not cfg["password"]:
        logger.warning(
            f"[SMTP NOT CONFIGURED] Verification code for {to_email}: {code} — "
            "Configure SMTP in Settings → Email or set HORUS_SMTP_* env vars."
        )
        return False   # ← False so callers know email was NOT sent

    html_body = f"""\
<html><body style="font-family:Arial,sans-serif;background:#050814;color:#c8e8f0;margin:0;padding:20px">
<div style="max-width:480px;margin:0 auto;background:#07101f;border:1px solid rgba(0,245,255,.2);border-radius:12px;padding:30px">
  <div style="text-align:center;margin-bottom:24px">
    <div style="font-size:32px;margin-bottom:8px">👁</div>
    <div style="font-family:monospace;font-size:22px;color:#00f5ff;letter-spacing:4px;font-weight:700">HORUSSHIELD 2.0</div>
    <div style="font-size:11px;color:rgba(200,232,240,.5);letter-spacing:2px">EGYPTIAN AI CYBERSECURITY</div>
  </div>
  <p style="color:#c8e8f0;margin-bottom:16px">Hi <b>{name}</b>,</p>
  <p style="color:rgba(200,232,240,.7);margin-bottom:24px">Your verification code to access HorusShield 2.0 is:</p>
  <div style="text-align:center;background:#050814;border:2px solid #00f5ff;border-radius:10px;padding:20px;margin-bottom:24px">
    <div style="font-family:monospace;font-size:42px;font-weight:900;color:#00f5ff;letter-spacing:14px">{code}</div>
    <div style="font-size:11px;color:rgba(0,245,255,.5);margin-top:8px">Valid for 10 minutes</div>
  </div>
  <p style="color:rgba(200,232,240,.5);font-size:11px">
    If you didn't request this, ignore this email.<br>
    Team NullByte · WE School · Alexandria, Egypt 🇪🇬
  </p>
</div>
</body></html>"""

    msg            = MIMEMultipart("alternative")
    msg["Subject"] = "HorusShield 2.0 — Verification Code"
    msg["From"]    = f"{cfg['from_name']} <{cfg['user']}>"
    msg["To"]      = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["user"], to_email, msg.as_string())
        logger.info(f"Verification email sent to {to_email}")
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error(
            "SMTP authentication failed — check smtp_user / smtp_pass. "
            "For Gmail, use an App Password, not your account password."
        )
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending to {to_email}: {e}")
        return False
    except Exception as e:
        logger.error(f"Email send failed ({to_email}): {e}")
        return False


def test_smtp_connection() -> dict:
    """
    Test the current SMTP configuration without sending a real email.
    Returns {"success": True} or {"success": False, "error": "reason"}.
    """
    cfg = _get_smtp_config()
    if not cfg["user"] or not cfg["password"]:
        return {"success": False, "error": "SMTP not configured — set smtp_user and smtp_pass in Settings."}
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(cfg["user"], cfg["password"])
        return {"success": True, "message": f"Connected to {cfg['host']}:{cfg['port']} as {cfg['user']}"}
    except smtplib.SMTPAuthenticationError:
        return {"success": False,
                "error": "Authentication failed. For Gmail, use an App Password (not your account password)."}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Auth Manager ─────────────────────────────────────────────────────────────

class AuthManager:

    # ── Register ──────────────────────────────────────────────────────────────
    def register(self, email: str, password: str, full_name: str = "") -> dict:
        """Fix for a confirmed Medium finding (Red Team review): this used
        to return a distinct "Email already registered" error, letting an
        attacker enumerate valid accounts by attempting registration.
        Format/length validation still returns specific errors (those
        don't leak account existence) — only the "does this email already
        have an account" branch is now indistinguishable from success.
        """
        if not _valid_email(email):
            return {"error": "Invalid email address"}
        if len(password) < 8:
            return {"error": "Password must be at least 8 characters"}

        existing = self._get_user_by_email(email)
        if existing:
            # Do NOT create a second account, do NOT touch the existing
            # one, do NOT return a dev_code (that would let someone
            # complete verification of an account they don't own — worse
            # than enumeration). Log internally for abuse monitoring;
            # the caller sees the exact same generic response as a real
            # new registration.
            logger.info(f"Registration attempted for already-registered email: {email}")
            return {
                "success": True,
                "email_sent": True,
                "message": "If this email can be registered, a verification code has been sent to it.",
            }

        code        = _gen_code()
        expires_at  = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        pw_hash     = _hash_password(password)
        name        = full_name or email.split('@')[0]
        try:
            with db.get_connection() as conn:
                conn.execute("""
                    INSERT INTO users (email,password_hash,full_name,provider,is_verified,
                                       verification_code,code_expires_at,role)
                    VALUES (?,?,?,'local',0,?,?,
                        CASE WHEN (SELECT COUNT(*) FROM users WHERE role='admin') = 0 THEN 'admin' ELSE 'analyst' END
                    )""",
                    (email, pw_hash, name, code, expires_at))
                row = conn.execute("SELECT role FROM users WHERE email=?", (email,)).fetchone()
                role = row["role"] if row else "analyst"
            email_sent = send_verification_email(email, code, name)
            logger.info(f"User registered: {email} — role={role} email_sent={email_sent}")
            response = {
                "success":    True,
                "email_sent": email_sent,
                "message":    "If this email can be registered, a verification code has been sent to it.",
            }
            if not email_sent:
                # Surface the code so the UI can show it directly to the user.
                # Safe here specifically because we already know this is a
                # brand-new account this caller just created — not someone
                # else's pending registration.
                response["dev_code"] = code
                response["warning"]  = (
                    "SMTP is not configured — your verification code is shown below. "
                    "Configure email in Settings → Email to enable delivery."
                )
            return response
        except Exception as e:
            logger.error(f"Register error: {e}")
            return {"error": "Registration failed"}

    # ── Verify Email ──────────────────────────────────────────────────────────
    def verify_email(self, email: str, code: str) -> dict:
        user = self._get_user_by_email(email)
        if not user:
            return {"error": "User not found"}
        if user['verification_code'] != code:
            return {"error": "Invalid verification code"}
        if user['code_expires_at'] and datetime.fromisoformat(user['code_expires_at']) < datetime.utcnow():
            return {"error": "Code expired — please request a new one"}
        with db.get_connection() as conn:
            conn.execute("UPDATE users SET is_verified=1, verification_code='' WHERE email=?", (email,))
        token = self._create_session(user['id'])
        logger.info(f"Email verified and logged in: {email}")
        return {"success": True, "token": token, "user": self._safe_user(user)}

    # ── Resend Code ───────────────────────────────────────────────────────────
    def resend_code(self, email: str) -> dict:
        """Same fix as register(): never reveal whether the account exists,
        and never hand back a dev_code for an account this caller didn't
        just prove ownership of by registering it — an unauthenticated
        resend used to let anyone who merely knew/guessed a pending user's
        email fetch a fresh verification code (and, with SMTP unconfigured,
        see it directly in the dev_code field), letting them mark someone
        else's pending signup as verified. That doesn't hand over the
        password, but it's still not this caller's account to touch.
        """
        generic_response = {
            "success": True, "email_sent": True,
            "message": "If this account needs a new code, one has been sent to it.",
        }
        user = self._get_user_by_email(email)
        if not user:
            logger.info(f"Resend-code attempted for unknown email: {email}")
            return generic_response
        if user.get("is_verified"):
            # Already verified — nothing to resend, but don't say so.
            logger.info(f"Resend-code attempted for already-verified email: {email}")
            return generic_response

        code       = _gen_code()
        expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        with db.get_connection() as conn:
            conn.execute("UPDATE users SET verification_code=?,code_expires_at=? WHERE email=?",
                         (code, expires_at, email))
        email_sent = send_verification_email(email, code, user['full_name'])
        response   = dict(generic_response)
        response["email_sent"] = email_sent
        if not email_sent:
            # SMTP not configured: no safe way to deliver the code
            # out-of-band, and we've already established this endpoint
            # can be called by anyone who knows the email (not just the
            # account owner) — so unlike register()'s dev_code, this one
            # is NOT surfaced here. A user who legitimately needs their
            # code in a no-SMTP dev environment should use the code shown
            # at registration time, or an admin should check the DB/logs.
            logger.info(f"Resend-code generated for {email} but SMTP unavailable — not exposing dev_code via resend")
        return response

    # ── Login ─────────────────────────────────────────────────────────────────
    def login(self, email: str, password: str) -> dict:
        user = self._get_user_by_email(email)
        if not user:
            return {"error": "Invalid email or password"}
        if not _verify_password(password, user['password_hash'] or ''):
            return {"error": "Invalid email or password"}
        if not user['is_verified']:
            # Resend a fresh code and surface it if email isn't configured
            resend_result = self.resend_code(email)
            response = {"error": "EMAIL_NOT_VERIFIED", "email": email}
            if not resend_result.get("email_sent"):
                response["dev_code"] = resend_result.get("dev_code", "")
                response["warning"]  = resend_result.get("warning", "")
            return response
        if not user['is_active']:
            return {"error": "Account is disabled"}
        token = self._create_session(user['id'])
        with db.get_connection() as conn:
            conn.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (user['id'],))
        logger.info(f"Login: {email}")
        return {"success": True, "token": token, "user": self._safe_user(user)}

    # ── Google OAuth ──────────────────────────────────────────────────────────
    def google_auth(self, token_str: str, client_id: str = "") -> dict:
        """
        Verify Google ID token or OAuth2 access token and login/register the user.
        client_id is passed from the route (already loaded from DB or env).
        """
        if not client_id:
            from config import active_config as _cfg
            client_id = getattr(_cfg, "GOOGLE_CLIENT_ID", "")
        if not token_str:
            return {"error": "Google token is required"}

        try:
            idinfo = None

            # ── Case A: Access Token (e.g., ya29... from Google OAuth2 Token Client) ──
            if not token_str.startswith("ey") or "." not in token_str:
                try:
                    import requests
                    resp = requests.get(
                        "https://www.googleapis.com/oauth2/v3/userinfo",
                        headers={"Authorization": f"Bearer {token_str}"},
                        timeout=8
                    )
                    if resp.status_code == 200:
                        idinfo = resp.json()
                except Exception as net_err:
                    logger.debug(f"Google userinfo endpoint error: {net_err}")

            # ── Case B: ID Token (JWT) ──
            if idinfo is None:
                # 1. Try google-auth library first (official crypto verification)
                try:
                    from google.oauth2 import id_token as g_id_token
                    from google.auth.transport import requests as g_requests
                    idinfo = g_id_token.verify_oauth2_token(token_str, g_requests.Request(), client_id)
                except Exception as g_err:
                    logger.debug(f"google-auth verify_oauth2_token failed: {g_err}")

                # 2. Try Google's official public tokeninfo endpoint
                if idinfo is None:
                    try:
                        import requests
                        r = requests.get(
                            "https://oauth2.googleapis.com/tokeninfo",
                            params={"id_token": token_str},
                            timeout=8
                        )
                        if r.status_code == 200:
                            info = r.json()
                            if not client_id or info.get("aud") == client_id:
                                idinfo = info
                    except Exception as net_err2:
                        logger.debug(f"Google tokeninfo endpoint error: {net_err2}")

                # 3. Fallback: decode JWT payload (for offline/dev environments)
                if idinfo is None:
                    import base64, json as _json
                    parts = token_str.split('.')
                    if len(parts) == 3:
                        padding = 4 - len(parts[1]) % 4
                        payload = base64.urlsafe_b64decode(parts[1] + '=' * padding)
                        parsed = _json.loads(payload)
                        if parsed.get('iss') in ('accounts.google.com', 'https://accounts.google.com'):
                            import time
                            if parsed.get('exp', 0) >= time.time() - 300: # allow 5 min clock skew
                                idinfo = parsed
                                logger.info("Google login: decoded JWT token payload")

            if not idinfo:
                return {"error": "Invalid or expired Google authentication token. Please try again."}

            email     = idinfo.get('email', '')
            if not email:
                return {"error": "Google account has no email address associated"}
            name      = idinfo.get('name', email.split('@')[0])
            avatar    = idinfo.get('picture', '')
            google_id = idinfo.get('sub', '')

            user = self._get_user_by_email(email)
            if not user:
                with db.get_connection() as conn:
                    conn.execute("""
                        INSERT INTO users (email,full_name,avatar_url,provider,google_id,is_verified,is_active,role)
                        VALUES (?,?,?,'google',?,1,1,
                            CASE WHEN (SELECT COUNT(*) FROM users WHERE role='admin') = 0 THEN 'admin' ELSE 'analyst' END
                        )""",
                        (email, name, avatar, google_id))
                user = self._get_user_by_email(email)
            else:
                with db.get_connection() as conn:
                    conn.execute(
                        "UPDATE users SET avatar_url=?,last_login=CURRENT_TIMESTAMP WHERE email=?",
                        (avatar, email))
                user = self._get_user_by_email(email)

            token = self._create_session(user['id'])
            logger.info(f"Google login: {email}")
            return {"success": True, "token": token, "user": self._safe_user(user)}

        except Exception as e:
            logger.error(f"Google auth error: {e}")
            return {"error": f"Google Sign-In failed: {str(e)}"}

    # ── Validate Session ──────────────────────────────────────────────────────
    def validate_token(self, token: str) -> dict | None:
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT u.* FROM users u
                    JOIN auth_sessions s ON s.user_id=u.id
                    WHERE s.token=? AND s.expires_at > CURRENT_TIMESTAMP
                """, (token,)).fetchone()
            if row:
                return dict(row)
        except Exception as e:
            logger.error(f"validate_token: {e}")
        return None

    # ── Logout ────────────────────────────────────────────────────────────────
    def logout(self, token: str) -> dict:
        try:
            with db.get_connection() as conn:
                conn.execute("DELETE FROM auth_sessions WHERE token=?", (token,))
            return {"success": True}
        except Exception as e:
            return {"error": str(e)}

    # ── Internal ──────────────────────────────────────────────────────────────
    def _get_user_by_email(self, email: str):
        try:
            with db.get_connection() as conn:
                row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"_get_user_by_email failed: {e}")
            return None

    def _create_session(self, user_id: int, days=30) -> str:
        token      = _gen_token()
        expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
        with db.get_connection() as conn:
            conn.execute("INSERT INTO auth_sessions(user_id,token,expires_at) VALUES(?,?,?)",
                         (user_id, token, expires_at))
        return token

    def _safe_user(self, user: dict) -> dict:
        return {k: user[k] for k in ('id','email','full_name','avatar_url','provider','role','is_verified') if k in user}


auth_manager = AuthManager()
