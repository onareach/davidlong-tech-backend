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
        if not row or not pw_hash or not bcrypt.checkpw(password.encode("utf-8"), pw_hash):
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
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
