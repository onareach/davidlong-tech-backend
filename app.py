# app.py
# davidlong.tech — Backend API
# Flask app for Research Studio and site auth.
# Deploys to Heroku; frontend (Vercel) proxies /api/* to this backend.

from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import psycopg2
import os
import jwt
import bcrypt
from datetime import datetime, timedelta

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
    return _verify_jwt(token)


def _user_response(user_row):
    """user_row: (user_id, email, display_name)"""
    return {"id": user_row[0], "email": user_row[1], "display_name": user_row[2]}


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
            "INSERT INTO tbl_user (email, password_hash, display_name) VALUES (%s, %s, %s) RETURNING user_id, email, display_name;",
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
            max_age=7 * 24 * 3600,
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
            "SELECT user_id, email, display_name, password_hash FROM tbl_user WHERE email = %s;",
            (email,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        pw_hash = _password_hash_bytes(row[3]) if row else None
        if not row or not pw_hash:
            return jsonify({"error": "Invalid email or password"}), 401
        try:
            if not bcrypt.checkpw(password.encode("utf-8"), pw_hash):
                return jsonify({"error": "Invalid email or password"}), 401
        except (ValueError, TypeError) as e:
            app.logger.warning("bcrypt.checkpw failed: %s", e)
            return jsonify({"error": "Invalid email or password"}), 401
        token = _create_jwt(row[0], row[1])
        resp = make_response(jsonify({"user": _user_response((row[0], row[1], row[2])), "token": token}))
        resp.set_cookie(
            AUTH_COOKIE_NAME,
            str(token),
            path="/",
            httponly=True,
            secure=request.is_secure or not app.debug,
            samesite="None" if (request.is_secure or not app.debug) else "Lax",
            max_age=7 * 24 * 3600,
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
            "SELECT user_id, email, display_name FROM tbl_user WHERE user_id = %s;",
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


@app.route("/api/entries/today", methods=["GET"])
def entries_today():
    """Get today's entry (most recent from current UTC date). Requires auth."""
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
        cur.close()
        conn.close()
        if not row:
            return jsonify({"entry": None})
        return jsonify({"entry": _entry_response(row)})
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
        if "research_branch_id" in data:
            updates.append("research_branch_id = %s")
            params.append(data.get("research_branch_id"))
        if "research_mystery_id" in data:
            updates.append("research_mystery_id = %s")
            params.append(data.get("research_mystery_id"))
        if "status" in data:
            updates.append("research_entry_status = %s")
            params.append(data.get("status"))

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
