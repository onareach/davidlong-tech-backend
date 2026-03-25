# app.py
# davidlong.tech — Backend API
# Flask app for Research Studio and site auth.
# Deploys to Heroku; frontend (Vercel) proxies /api/* to this backend.

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import psycopg2
import os
import jwt
import bcrypt
import hashlib
import secrets
import json
import urllib.request
from datetime import datetime, timedelta
from openai import OpenAI

app = Flask(__name__)

# CORS: allowed origins for browser requests from frontend.
# Add more via env CORS_ORIGINS (comma-separated, no spaces).
_default_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "https://davidlong.tech",
    "https://www.davidlong.tech",
]
_extra_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
CORS(
    app,
    origins=_default_origins + _extra_origins,
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
)

# Config
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "postgresql://dev_user:dev123@localhost:5432/davidlong_tech?sslmode=disable"
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")
AUTH_COOKIE_NAME = "davidlong_tech_token"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENAI_EDIT_MODEL = os.environ.get("OPENAI_EDIT_MODEL", "gpt-4o-mini")

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")
RESET_EXPIRY_HOURS = 1


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _auth_db():
    sslmode = "require" if DATABASE_URL.startswith("postgres://") else "disable"
    return psycopg2.connect(DATABASE_URL, sslmode=sslmode)


def _create_jwt(user_id, email):
    payload = {"sub": user_id, "email": email, "exp": datetime.utcnow() + timedelta(days=7)}
    raw = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return raw if isinstance(raw, str) else raw.decode("utf-8")


def _password_hash_bytes(stored):
    """Normalize stored password hash to bytes for bcrypt.checkpw."""
    if stored is None:
        return None
    if isinstance(stored, bytes):
        return stored
    return stored.encode("utf-8")


def _verify_jwt(token):
    if not token:
        return None
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {"user_id": payload["sub"], "email": payload["email"]}
    except jwt.InvalidTokenError:
        return None


def _get_current_user():
    """Auth from cookie or Authorization: Bearer header."""
    token = request.cookies.get(AUTH_COOKIE_NAME)
    if not token and request.headers.get("Authorization"):
        parts = request.headers.get("Authorization", "").strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    claims = _verify_jwt(token)
    if not claims:
        return None
    # Inactive accounts lose effective session immediately.
    conn = _auth_db()
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(is_active, true) FROM tbl_user WHERE user_id = %s;", (claims["user_id"],))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not row[0]:
        return None
    return claims


def _user_response(user_row):
    """user_row: (user_id, email, display_name) or (..., is_admin[, is_active])"""
    is_admin = bool(user_row[3]) if len(user_row) > 3 else False
    is_active = bool(user_row[4]) if len(user_row) > 4 else True
    return {
        "id": user_row[0],
        "email": user_row[1],
        "display_name": user_row[2],
        "is_admin": is_admin,
        "is_active": is_active,
    }


def _require_admin():
    """Require authenticated admin. Returns (claims, None) or (None, (response, status))."""
    claims = _get_current_user()
    if not claims:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    conn = _auth_db()
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(is_admin, false) FROM tbl_user WHERE user_id = %s;", (claims["user_id"],))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not row[0]:
        return None, (jsonify({"error": "Admin access required"}), 403)
    return claims, None


def _send_password_reset_email(to_email: str, reset_link: str) -> bool:
    """Send password reset via SendGrid; log link if no API key."""
    sendgrid_key = os.environ.get("SENDGRID_API_KEY")
    if sendgrid_key:
        try:
            personalizations = [{"to": [{"email": to_email}]}]
            bcc = (os.environ.get("SENDGRID_BCC") or "").strip()
            if bcc:
                personalizations[0]["bcc"] = [{"email": bcc}]
            from_email = os.environ.get("RESET_EMAIL_FROM", "noreply@example.com")
            req = urllib.request.Request(
                "https://api.sendgrid.com/v3/mail/send",
                data=json.dumps(
                    {
                        "personalizations": personalizations,
                        "from": {"email": from_email, "name": "Research Studio (davidlong.tech)"},
                        "subject": "Reset your password",
                        "content": [
                            {
                                "type": "text/plain",
                                "value": (
                                    f"Use this link to set a new password (valid for {RESET_EXPIRY_HOURS} hour):\n\n"
                                    f"{reset_link}\n\nIf you didn't request this, you can ignore this email."
                                ),
                            }
                        ],
                    }
                ).encode(),
                headers={"Authorization": f"Bearer {sendgrid_key}", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 202)
        except Exception as e:
            app.logger.warning("SendGrid send failed: %s", e)
            return False
    app.logger.info("Password reset link (no SENDGRID_API_KEY): %s", reset_link)
    return True


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """Health check for Heroku and monitoring."""
    return jsonify({"ok": True, "service": "davidlong-tech-backend"}), 200


# ---------------------------------------------------------------------------
# Auth: register, login, logout, me
# ---------------------------------------------------------------------------

@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        display_name = (data.get("display_name") or "").strip() or None
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute("SELECT user_id, email, display_name FROM tbl_user WHERE email = %s;", (email,))
        existing = cur.fetchone()
        if existing:
            cur.close()
            conn.close()
            return jsonify({"error": "An account with this email already exists"}), 409
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cur.execute(
            "INSERT INTO tbl_user (email, password_hash, display_name) VALUES (%s, %s, %s) "
            "RETURNING user_id, email, display_name, COALESCE(is_admin, false), COALESCE(is_active, true);",
            (email, password_hash, display_name),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        token = _create_jwt(row[0], row[1])
        resp = make_response(jsonify({"user": _user_response(row), "token": token}))
        resp.set_cookie(
            AUTH_COOKIE_NAME,
            str(token),
            path="/",
            httponly=True,
            secure=request.is_secure or not app.debug,
            samesite="None" if (request.is_secure or not app.debug) else "Lax",
            # Session cookie: no max_age so cookie is cleared when browser session ends (close tab/browser = sign out)
        )
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, email, display_name, password_hash, COALESCE(is_admin, false), COALESCE(is_active, true) FROM tbl_user WHERE email = %s;",
            (email,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        pw_hash = _password_hash_bytes(row[3]) if row else None
        if not row or not pw_hash or not row[5]:
            return jsonify({"error": "Invalid email or password"}), 401
        try:
            if not bcrypt.checkpw(password.encode("utf-8"), pw_hash):
                return jsonify({"error": "Invalid email or password"}), 401
        except (ValueError, TypeError) as e:
            app.logger.warning("bcrypt.checkpw failed: %s", e)
            return jsonify({"error": "Invalid email or password"}), 401
        token = _create_jwt(row[0], row[1])
        resp = make_response(
            jsonify({"user": _user_response((row[0], row[1], row[2], row[4], row[5])), "token": token})
        )
        resp.set_cookie(
            AUTH_COOKIE_NAME,
            str(token),
            path="/",
            httponly=True,
            secure=request.is_secure or not app.debug,
            samesite="None" if (request.is_secure or not app.debug) else "Lax",
            # Session cookie: no max_age so cookie is cleared when browser session ends (close tab/browser = sign out)
        )
        return resp
    except Exception as e:
        app.logger.exception("Login failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(
        AUTH_COOKIE_NAME,
        "",
        path="/",
        httponly=True,
        max_age=0,
        secure=request.is_secure or not app.debug,
        samesite="None" if (request.is_secure or not app.debug) else "Lax",
    )
    return resp


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    try:
        claims = _get_current_user()
        if not claims:
            return jsonify({"user": None}), 200
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, email, display_name, COALESCE(is_admin, false), COALESCE(is_active, true) FROM tbl_user WHERE user_id = %s;",
            (claims["user_id"],),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"user": None}), 200
        return jsonify({"user": _user_response(row)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/me", methods=["PATCH"])
def auth_me_update():
    try:
        claims = _get_current_user()
        if not claims:
            return jsonify({"error": "Not authenticated"}), 401
        data = request.get_json() or {}
        conn = _auth_db()
        cur = conn.cursor()
        if data.get("new_password"):
            new_password = data["new_password"]
            current_password = data.get("current_password") or ""
            if len(new_password) < 8:
                cur.close()
                conn.close()
                return jsonify({"error": "New password must be at least 8 characters"}), 400
            cur.execute("SELECT password_hash FROM tbl_user WHERE user_id = %s;", (claims["user_id"],))
            row_pw = cur.fetchone()
            pw_hash = _password_hash_bytes(row_pw[0]) if row_pw else None
            if not row_pw or not pw_hash or not bcrypt.checkpw(current_password.encode("utf-8"), pw_hash):
                cur.close()
                conn.close()
                return jsonify({"error": "Current password is incorrect"}), 401
            password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            cur.execute(
                "UPDATE tbl_user SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s;",
                (password_hash, claims["user_id"]),
            )
        if "email" in data:
            new_email = (data.get("email") or "").strip().lower()
            if not new_email:
                cur.close()
                conn.close()
                return jsonify({"error": "Email cannot be empty"}), 400
            cur.execute(
                "SELECT user_id FROM tbl_user WHERE email = %s AND user_id != %s;",
                (new_email, claims["user_id"]),
            )
            if cur.fetchone():
                cur.close()
                conn.close()
                return jsonify({"error": "That email is already in use"}), 409
            cur.execute(
                "UPDATE tbl_user SET email = %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s;",
                (new_email, claims["user_id"]),
            )
        if "display_name" in data:
            display_name = (data.get("display_name") or "").strip() or None
            cur.execute(
                "UPDATE tbl_user SET display_name = %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s;",
                (display_name, claims["user_id"]),
            )
        cur.execute(
            "SELECT user_id, email, display_name, COALESCE(is_admin, false), COALESCE(is_active, true) FROM tbl_user WHERE user_id = %s;",
            (claims["user_id"],),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"user": _user_response(row)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/forgot-password", methods=["POST"])
def auth_forgot_password():
    """Request reset link. Same response whether or not email exists (no enumeration)."""
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        if not email:
            return jsonify({"error": "Email is required"}), 400
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM tbl_user WHERE email = %s;", (email,))
        found = cur.fetchone() is not None
        if found:
            cur.execute("DELETE FROM tbl_password_reset WHERE email = %s;", (email,))
            token = secrets.token_urlsafe(32)
            token_lookup = hashlib.sha256(token.encode()).hexdigest()
            token_hash = bcrypt.hashpw(token.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            expires_at = datetime.utcnow() + timedelta(hours=RESET_EXPIRY_HOURS)
            cur.execute(
                "INSERT INTO tbl_password_reset (email, token_lookup, token_hash, expires_at) VALUES (%s, %s, %s, %s);",
                (email, token_lookup, token_hash, expires_at),
            )
            conn.commit()
            reset_link = f"{FRONTEND_URL.rstrip('/')}/reset-password?token={token}"
            _send_password_reset_email(email, reset_link)
        else:
            conn.commit()
        cur.close()
        conn.close()
        return jsonify(
            {
                "ok": True,
                "message": "If that email is registered, you will receive password reset instructions shortly.",
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/reset-password", methods=["POST"])
def auth_reset_password():
    try:
        data = request.get_json() or {}
        token = (data.get("token") or "").strip()
        new_password = data.get("new_password") or ""
        if not token:
            return jsonify({"error": "Reset token is required"}), 400
        if len(new_password) < 8:
            return jsonify({"error": "New password must be at least 8 characters"}), 400
        token_lookup = hashlib.sha256(token.encode()).hexdigest()
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, token_hash, expires_at FROM tbl_password_reset WHERE token_lookup = %s AND expires_at > %s;",
            (token_lookup, datetime.utcnow()),
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid or expired reset link. Request a new one."}), 400
        _id, email, stored_hash, _exp = row
        stored_bytes = _password_hash_bytes(stored_hash)
        if not stored_bytes or not bcrypt.checkpw(token.encode("utf-8"), stored_bytes):
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid or expired reset link. Request a new one."}), 400
        password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cur.execute(
            "UPDATE tbl_user SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE email = %s;",
            (password_hash, email),
        )
        cur.execute("DELETE FROM tbl_password_reset WHERE id = %s;", (_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify(
            {
                "ok": True,
                "message": "Password has been reset. You can sign in with your new password.",
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    claims, err = _require_admin()
    if err:
        return err[0], err[1]
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, email, display_name, COALESCE(is_admin, false), COALESCE(is_active, true) "
            "FROM tbl_user ORDER BY email;"
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"users": [_user_response(r) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/users/<int:target_user_id>", methods=["PATCH"])
def admin_update_user(target_user_id):
    claims, err = _require_admin()
    if err:
        return err[0], err[1]
    data = request.get_json() or {}
    if data.get("is_admin") is None:
        return jsonify({"error": "is_admin is required"}), 400
    is_admin = bool(data.get("is_admin"))
    try:
        conn = _auth_db()
        cur = conn.cursor()
        if not is_admin and target_user_id == claims["user_id"]:
            cur.execute("SELECT COUNT(*) FROM tbl_user WHERE is_admin = true;")
            admin_count = cur.fetchone()[0]
            if admin_count <= 1:
                cur.close()
                conn.close()
                return jsonify(
                    {"error": "Cannot revoke your own admin rights when you are the only admin."}
                ), 400
        cur.execute(
            "UPDATE tbl_user SET is_admin = %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s "
            "RETURNING user_id, email, display_name, COALESCE(is_admin, false), COALESCE(is_active, true);",
            (is_admin, target_user_id),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"user": _user_response(row)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/users/<int:target_user_id>/activation", methods=["PATCH"])
def admin_update_user_activation(target_user_id):
    """Toggle account activation. Admin accounts cannot be inactivated."""
    claims, err = _require_admin()
    if err:
        return err[0], err[1]
    data = request.get_json() or {}
    if data.get("is_active") is None:
        return jsonify({"error": "is_active is required"}), 400
    is_active = bool(data.get("is_active"))
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, COALESCE(is_admin, false), COALESCE(is_active, true) FROM tbl_user WHERE user_id = %s;",
            (target_user_id,),
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404
        _id, target_is_admin, _target_is_active = row
        if target_is_admin and not is_active:
            cur.close()
            conn.close()
            return jsonify({"error": "Admin accounts cannot be inactivated. Remove admin first."}), 400

        cur.execute(
            "UPDATE tbl_user SET is_active = %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s "
            "RETURNING user_id, email, display_name, COALESCE(is_admin, false), COALESCE(is_active, true);",
            (is_active, target_user_id),
        )
        updated = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"user": _user_response(updated)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

@app.route("/api/prompts/today", methods=["GET"])
def prompts_today():
    """Return today's writing prompt. Requires auth. Priority: continuity prompts, then random fallback."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _auth_db()
        cur = conn.cursor()
        # TODO: Add continuity prompts (from prior entries). For MVP, use random fallback.
        cur.execute(
            """
            SELECT research_prompt_id, research_prompt_text, is_fallback
            FROM tbl_research_prompts
            WHERE is_fallback = true
            ORDER BY RANDOM()
            LIMIT 1
            """
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"error": "No prompts available"}), 404
        return jsonify({
            "prompt": {
                "id": row[0],
                "text": row[1],
                "is_fallback": row[2],
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/prompts", methods=["GET", "POST"])
def prompts_list_or_create():
    """GET: list prompts for replacement. POST: create custom prompt. Body: { "text": "..." }. Requires auth."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    if request.method == "GET":
        try:
            conn = _auth_db()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT research_prompt_id, research_prompt_text, is_fallback
                FROM tbl_research_prompts
                ORDER BY is_fallback DESC, research_prompt_text
                """
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()
            return jsonify({
                "prompts": [
                    {"id": r[0], "text": r[1], "is_fallback": r[2]}
                    for r in rows
                ]
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    # POST
    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO tbl_research_prompts (research_prompt_text, research_prompt_type, is_fallback, research_prompt_status)
            VALUES (%s, 'custom', false, 'pending')
            RETURNING research_prompt_id, research_prompt_text, is_fallback
            """,
            (text,),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"id": row[0], "text": row[1], "is_fallback": row[2]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/prompts/<int:prompt_id>", methods=["PATCH"])
def prompts_update(prompt_id):
    """Update a prompt's text. Requires auth. Body: { "text": "..." }."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE tbl_research_prompts
            SET research_prompt_text = %s
            WHERE research_prompt_id = %s
            RETURNING research_prompt_id, research_prompt_text, is_fallback
            """,
            (text, prompt_id),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"error": "Prompt not found"}), 404
        return jsonify({"id": row[0], "text": row[1], "is_fallback": row[2]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Branches and Mysteries (read-only for dropdowns)
# ---------------------------------------------------------------------------


def _branch_visible_to_user(cur, branch_id, user_id):
    if branch_id is None:
        return True
    cur.execute(
        """
        SELECT 1 FROM tbl_research_branches
        WHERE research_branch_id = %s AND (user_id IS NULL OR user_id = %s)
        """,
        (branch_id, user_id),
    )
    return cur.fetchone() is not None


def _mystery_visible_to_user(cur, mystery_id, user_id):
    if mystery_id is None:
        return True
    cur.execute(
        """
        SELECT 1 FROM tbl_research_mysteries
        WHERE research_mystery_id = %s AND (user_id IS NULL OR user_id = %s)
        """,
        (mystery_id, user_id),
    )
    return cur.fetchone() is not None


@app.route("/api/branches", methods=["GET"])
def branches_list():
    """List all research branches. Requires auth."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT research_branch_id, research_branch_handle, research_branch_name
            FROM tbl_research_branches
            WHERE user_id IS NULL OR user_id = %s
            ORDER BY research_branch_name
            """,
            (claims["user_id"],),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({
            "branches": [
                {"id": r[0], "handle": r[1], "name": r[2]}
                for r in rows
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mysteries", methods=["GET"])
def mysteries_list():
    """List all research mysteries. Requires auth."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT research_mystery_id, research_mystery_handle, research_mystery_question
            FROM tbl_research_mysteries
            WHERE user_id IS NULL OR user_id = %s
            ORDER BY research_mystery_question
            """,
            (claims["user_id"],),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({
            "mysteries": [
                {"id": r[0], "handle": r[1], "question": r[2]}
                for r in rows
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _slugify(text):
    """Make a URL-safe handle: lowercase, non-alphanumeric to underscore, collapse underscores, max 80 chars."""
    if not text or not isinstance(text, str):
        return "unnamed"
    s = "".join(c if c.isalnum() else "_" for c in text.lower().strip())
    while "__" in s:
        s = s.replace("__", "_")
    s = s.strip("_") or "unnamed"
    return s[:80]


def _unique_branch_handle(cur, base_handle):
    """Return base_handle or base_handle_2, base_handle_3, ... that doesn't exist."""
    cur.execute(
        "SELECT research_branch_handle FROM tbl_research_branches WHERE research_branch_handle = %s",
        (base_handle,),
    )
    if cur.fetchone() is None:
        return base_handle
    for i in range(2, 1000):
        candidate = f"{base_handle}_{i}"
        cur.execute(
            "SELECT research_branch_handle FROM tbl_research_branches WHERE research_branch_handle = %s",
            (candidate,),
        )
        if cur.fetchone() is None:
            return candidate
    return f"{base_handle}_{hash(base_handle) % 100000}"


def _unique_mystery_handle(cur, base_handle):
    """Return base_handle or base_handle_2, ... that doesn't exist."""
    cur.execute(
        "SELECT research_mystery_handle FROM tbl_research_mysteries WHERE research_mystery_handle = %s",
        (base_handle,),
    )
    if cur.fetchone() is None:
        return base_handle
    for i in range(2, 1000):
        candidate = f"{base_handle}_{i}"
        cur.execute(
            "SELECT research_mystery_handle FROM tbl_research_mysteries WHERE research_mystery_handle = %s",
            (candidate,),
        )
        if cur.fetchone() is None:
            return candidate
    return f"{base_handle}_{hash(base_handle) % 100000}"


@app.route("/api/branches", methods=["POST"])
def branches_create():
    """Create a new research branch. Requires auth. Body: { "name": "Branch name" }. Handle is derived from name (unique)."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    description = (data.get("description") or "").strip() or None
    try:
        conn = _auth_db()
        cur = conn.cursor()
        base_handle = _slugify(name)
        handle = _unique_branch_handle(cur, base_handle)
        cur.execute(
            """
            INSERT INTO tbl_research_branches (research_branch_handle, research_branch_name, research_branch_description, user_id)
            VALUES (%s, %s, %s, %s)
            RETURNING research_branch_id, research_branch_handle, research_branch_name
            """,
            (handle, name, description, claims["user_id"]),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"id": row[0], "handle": row[1], "name": row[2]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mysteries", methods=["POST"])
def mysteries_create():
    """Create a new research mystery. Requires auth. Body: { "question": "The question?" }. Handle is derived from question (unique)."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    data = request.get_json() or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 400
    description = (data.get("description") or "").strip() or None
    try:
        conn = _auth_db()
        cur = conn.cursor()
        base_handle = _slugify(question)
        handle = _unique_mystery_handle(cur, base_handle)
        cur.execute(
            """
            INSERT INTO tbl_research_mysteries (research_mystery_handle, research_mystery_question, research_mystery_description, user_id)
            VALUES (%s, %s, %s, %s)
            RETURNING research_mystery_id, research_mystery_handle, research_mystery_question
            """,
            (handle, question, description, claims["user_id"]),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"id": row[0], "handle": row[1], "question": row[2]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Entries (CRUD)
# ---------------------------------------------------------------------------

def _entry_response(row):
    """row: (id, user_id, prompt_id, title, raw_text, edited_text, summary, why_it_matters, branch_id, mystery_id, status, created_ts, updated_ts)"""
    return {
        "id": row[0],
        "user_id": row[1],
        "research_prompt_id": row[2],
        "title": row[3],
        "raw_text": row[4],
        "edited_text": row[5],
        "summary": row[6],
        "why_it_matters": row[7],
        "research_branch_id": row[8],
        "research_mystery_id": row[9],
        "status": row[10],
        "created_at": row[11].isoformat() if row[11] else None,
        "updated_at": row[12].isoformat() if row[12] else None,
    }


@app.route("/api/entries", methods=["GET"])
def entries_list():
    """List entries for the current user. Requires auth."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT research_entry_id, user_id, research_prompt_id, research_entry_title,
                   research_entry_raw_text, research_entry_edited_text, research_entry_summary,
                   research_entry_why_it_matters, research_branch_id, research_mystery_id,
                   research_entry_status, research_entries_timestamp, research_entry_updated_timestamp
            FROM tbl_research_entries
            WHERE user_id = %s
            ORDER BY research_entries_timestamp DESC
            """,
            (claims["user_id"],),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"entries": [_entry_response(r) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/entries", methods=["POST"])
def entries_create():
    """Create a new entry. Requires auth."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        data = request.get_json() or {}
        raw_text = (data.get("raw_text") or "").strip()
        research_prompt_id = data.get("research_prompt_id")
        if not raw_text:
            return jsonify({"error": "raw_text is required"}), 400
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO tbl_research_entries (user_id, research_prompt_id, research_entry_raw_text)
            VALUES (%s, %s, %s)
            RETURNING research_entry_id, user_id, research_prompt_id, research_entry_title,
                      research_entry_raw_text, research_entry_edited_text, research_entry_summary,
                      research_entry_why_it_matters, research_branch_id, research_mystery_id,
                      research_entry_status, research_entries_timestamp, research_entry_updated_timestamp
            """,
            (claims["user_id"], research_prompt_id, raw_text),
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"entry": _entry_response(row)}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _random_fallback_prompt(cur):
    """Return (id, text, is_fallback) or None."""
    cur.execute(
        """
        SELECT research_prompt_id, research_prompt_text, is_fallback
        FROM tbl_research_prompts
        WHERE is_fallback = true
        ORDER BY RANDOM()
        LIMIT 1
        """
    )
    row = cur.fetchone()
    return row


@app.route("/api/entries/today", methods=["GET"])
def entries_today():
    """Get today's entry (most recent from current UTC date) and its prompt. If no entry, return a random prompt for a fresh session. Requires auth."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT research_entry_id, user_id, research_prompt_id, research_entry_title,
                   research_entry_raw_text, research_entry_edited_text, research_entry_summary,
                   research_entry_why_it_matters, research_branch_id, research_mystery_id,
                   research_entry_status, research_entries_timestamp, research_entry_updated_timestamp
            FROM tbl_research_entries
            WHERE user_id = %s AND DATE(research_entries_timestamp AT TIME ZONE 'UTC') = CURRENT_DATE
            ORDER BY research_entries_timestamp DESC
            LIMIT 1
            """,
            (claims["user_id"],),
        )
        row = cur.fetchone()
        prompt_row = None
        if row:
            prompt_id = row[2]
            if prompt_id is not None:
                cur.execute(
                    """
                    SELECT research_prompt_id, research_prompt_text, is_fallback
                    FROM tbl_research_prompts
                    WHERE research_prompt_id = %s
                    """,
                    (prompt_id,),
                )
                prompt_row = cur.fetchone()
            if prompt_row is None:
                prompt_row = _random_fallback_prompt(cur)
        else:
            prompt_row = _random_fallback_prompt(cur)
        cur.close()
        conn.close()
        entry = _entry_response(row) if row else None
        prompt = (
            {"id": prompt_row[0], "text": prompt_row[1], "is_fallback": prompt_row[2]}
            if prompt_row
            else None
        )
        return jsonify({"entry": entry, "prompt": prompt})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/entries/<int:entry_id>", methods=["GET"])
def entries_get(entry_id):
    """Get a single entry. Requires auth; user must own the entry."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT research_entry_id, user_id, research_prompt_id, research_entry_title,
                   research_entry_raw_text, research_entry_edited_text, research_entry_summary,
                   research_entry_why_it_matters, research_branch_id, research_mystery_id,
                   research_entry_status, research_entries_timestamp, research_entry_updated_timestamp
            FROM tbl_research_entries
            WHERE research_entry_id = %s AND user_id = %s
            """,
            (entry_id, claims["user_id"]),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"error": "Entry not found"}), 404
        return jsonify({"entry": _entry_response(row)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/entries/<int:entry_id>", methods=["PATCH"])
def entries_update(entry_id):
    """Update an entry (e.g. autosave). Requires auth; user must own the entry."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        data = request.get_json() or {}
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT research_entry_id FROM tbl_research_entries WHERE research_entry_id = %s AND user_id = %s",
            (entry_id, claims["user_id"]),
        )
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Entry not found"}), 404

        if "research_branch_id" in data:
            bid = data.get("research_branch_id")
            if bid is not None and not _branch_visible_to_user(cur, bid, claims["user_id"]):
                cur.close()
                conn.close()
                return jsonify({"error": "Invalid or inaccessible branch"}), 400
        if "research_mystery_id" in data:
            mid = data.get("research_mystery_id")
            if mid is not None and not _mystery_visible_to_user(cur, mid, claims["user_id"]):
                cur.close()
                conn.close()
                return jsonify({"error": "Invalid or inaccessible mystery"}), 400

        updates = []
        params = []
        if "raw_text" in data:
            updates.append("research_entry_raw_text = %s")
            params.append(data.get("raw_text") or "")
        if "edited_text" in data:
            updates.append("research_entry_edited_text = %s")
            params.append(data.get("edited_text"))
        if "title" in data:
            updates.append("research_entry_title = %s")
            params.append(data.get("title"))
        if "research_prompt_id" in data:
            updates.append("research_prompt_id = %s")
            params.append(data.get("research_prompt_id"))
        if "research_branch_id" in data:
            updates.append("research_branch_id = %s")
            params.append(data.get("research_branch_id"))
        if "research_mystery_id" in data:
            updates.append("research_mystery_id = %s")
            params.append(data.get("research_mystery_id"))
        if "status" in data:
            updates.append("research_entry_status = %s")
            params.append(data.get("status"))
        if "summary" in data:
            updates.append("research_entry_summary = %s")
            params.append(data.get("summary"))
        if "why_it_matters" in data:
            updates.append("research_entry_why_it_matters = %s")
            params.append(data.get("why_it_matters"))

        if not updates:
            cur.close()
            conn.close()
            return jsonify({"error": "No fields to update"}), 400

        updates.append("research_entry_updated_timestamp = NOW()")
        params.extend([entry_id, claims["user_id"]])

        cur.execute(
            f"""
            UPDATE tbl_research_entries
            SET {", ".join(updates)}
            WHERE research_entry_id = %s AND user_id = %s
            RETURNING research_entry_id, user_id, research_prompt_id, research_entry_title,
                      research_entry_raw_text, research_entry_edited_text, research_entry_summary,
                      research_entry_why_it_matters, research_branch_id, research_mystery_id,
                      research_entry_status, research_entries_timestamp, research_entry_updated_timestamp
            """,
            params,
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"entry": _entry_response(row)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/entries/<int:entry_id>", methods=["DELETE"])
def entries_delete(entry_id):
    """Delete an entry. Requires auth; user must own the entry."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM tbl_research_entries WHERE research_entry_id = %s AND user_id = %s",
            (entry_id, claims["user_id"]),
        )
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        if deleted == 0:
            return jsonify({"error": "Entry not found"}), 404
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


LIGHT_EDIT_SYSTEM_PROMPT = (
    "You are an editor. Improve clarity and flow without changing the author's voice. "
    "Output only the revised text, no commentary or meta-comment."
)


def _log_ai_operation(cur, entry_id, op_type, model_name, prompt_used, response_text, success, error_message=None):
    cur.execute(
        """
        INSERT INTO tbl_ai_operations (
            research_entry_id, ai_operation_type, ai_model_name, ai_prompt_used,
            ai_response_text, ai_operation_success, ai_operation_error_message
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            entry_id,
            op_type,
            model_name,
            (prompt_used or "")[:10000],
            (response_text or "")[:100000],
            success,
            (error_message or "")[:2000] if error_message else None,
        ),
    )


@app.route("/api/entries/<int:entry_id>/light-edit", methods=["POST"])
def entries_light_edit(entry_id):
    """Run AI light edit on entry raw text; store result in edited_text. Requires auth; user must own the entry."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    if not OPENAI_API_KEY:
        return jsonify({"error": "AI edit is not configured"}), 503
    try:
        conn = _auth_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT research_entry_id, user_id, research_prompt_id, research_entry_title,
                   research_entry_raw_text, research_entry_edited_text, research_entry_summary,
                   research_entry_why_it_matters, research_branch_id, research_mystery_id,
                   research_entry_status, research_entries_timestamp, research_entry_updated_timestamp
            FROM tbl_research_entries
            WHERE research_entry_id = %s AND user_id = %s
            """,
            (entry_id, claims["user_id"]),
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"error": "Entry not found"}), 404
        raw_text = (row[4] or "").strip()
        if not raw_text:
            cur.close()
            conn.close()
            return jsonify({"error": "Draft is empty; add text to the raw draft first"}), 400

        client = OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model=OPENAI_EDIT_MODEL,
            messages=[
                {"role": "system", "content": LIGHT_EDIT_SYSTEM_PROMPT},
                {"role": "user", "content": raw_text},
            ],
        )
        choice = response.choices[0] if response.choices else None
        if not choice or not getattr(choice, "message", None):
            _log_ai_operation(
                cur, entry_id, "light_edit", OPENAI_EDIT_MODEL, LIGHT_EDIT_SYSTEM_PROMPT,
                None, False, "Empty or invalid response from OpenAI",
            )
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"error": "AI edit failed: no response"}), 502
        edited_text = (choice.message.content or "").strip()

        cur.execute(
            """
            UPDATE tbl_research_entries
            SET research_entry_edited_text = %s, research_entry_updated_timestamp = NOW()
            WHERE research_entry_id = %s AND user_id = %s
            RETURNING research_entry_id, user_id, research_prompt_id, research_entry_title,
                      research_entry_raw_text, research_entry_edited_text, research_entry_summary,
                      research_entry_why_it_matters, research_branch_id, research_mystery_id,
                      research_entry_status, research_entries_timestamp, research_entry_updated_timestamp
            """,
            (edited_text, entry_id, claims["user_id"]),
        )
        updated = cur.fetchone()
        _log_ai_operation(
            cur, entry_id, "light_edit", OPENAI_EDIT_MODEL, LIGHT_EDIT_SYSTEM_PROMPT,
            edited_text, True, None,
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"entry": _entry_response(updated)})
    except Exception as e:
        err_msg = str(e)
        try:
            conn = _auth_db()
            cur = conn.cursor()
            _log_ai_operation(
                cur, entry_id, "light_edit", OPENAI_EDIT_MODEL or "", LIGHT_EDIT_SYSTEM_PROMPT,
                None, False, err_msg,
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            pass
        return jsonify({"error": "AI edit failed. Try again."}), 502


# ---------------------------------------------------------------------------
# ABCs of AI — playground: prompt + optional model/params from request body
# ---------------------------------------------------------------------------

@app.route("/api/abc", methods=["POST"])
def api_abc():
    """Run a single user prompt through OpenAI with optional model and params. Requires auth. Model and params come from the request body (not env)."""
    claims = _get_current_user()
    if not claims:
        return jsonify({"error": "Authentication required"}), 401
    if not OPENAI_API_KEY:
        return jsonify({"error": "AI is not configured (OPENAI_API_KEY missing)"}), 503
    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400
    model = (data.get("model") or "").strip() or "gpt-4o-mini"
    temperature = data.get("temperature")
    if temperature is None:
        temperature = 1.0
    else:
        try:
            temperature = float(temperature)
            temperature = max(0.0, min(2.0, temperature))
        except (TypeError, ValueError):
            temperature = 1.0
    max_tokens = data.get("max_tokens")
    if max_tokens is not None:
        try:
            max_tokens = int(max_tokens)
            max_tokens = max(1, min(128000, max_tokens))
        except (TypeError, ValueError):
            max_tokens = 4096
    else:
        max_tokens = 4096
    top_p = data.get("top_p")
    if top_p is None:
        top_p = 1.0
    else:
        try:
            top_p = float(top_p)
            top_p = max(0.0, min(1.0, top_p))
        except (TypeError, ValueError):
            top_p = 1.0
    frequency_penalty = data.get("frequency_penalty")
    if frequency_penalty is None:
        frequency_penalty = 0.0
    else:
        try:
            frequency_penalty = float(frequency_penalty)
            frequency_penalty = max(-2.0, min(2.0, frequency_penalty))
        except (TypeError, ValueError):
            frequency_penalty = 0.0
    presence_penalty = data.get("presence_penalty")
    if presence_penalty is None:
        presence_penalty = 0.0
    else:
        try:
            presence_penalty = float(presence_penalty)
            presence_penalty = max(-2.0, min(2.0, presence_penalty))
        except (TypeError, ValueError):
            presence_penalty = 0.0
    stream = bool(data.get("stream", False))
    system_content = (data.get("system") or "").strip()
    messages = []
    if system_content:
        messages.append({"role": "system", "content": system_content})
    messages.append({"role": "user", "content": prompt})
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        kwargs = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": top_p,
            "frequency_penalty": frequency_penalty,
            "presence_penalty": presence_penalty,
            "stream": stream,
        }
        response = client.chat.completions.create(**kwargs)
        if stream:
            # For stream we'd need to iterate; this endpoint returns one blob for simplicity
            return jsonify({"error": "stream=true not supported in this UI; use stream=false"}), 400
        choice = response.choices[0] if response.choices else None
        if not choice or not getattr(choice, "message", None):
            return jsonify({"error": "No response from model"}), 502
        content = (choice.message.content or "").strip()
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
