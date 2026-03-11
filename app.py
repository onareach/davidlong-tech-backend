# app.py
# davidlong.tech — Backend API
# Flask app for Research Studio and site auth.
# Deploys to Heroku; frontend (Vercel) proxies /api/* to this backend.

from flask import Flask, jsonify
from flask_cors import CORS
import os

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

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """Health check for Heroku and monitoring."""
    return jsonify({"ok": True, "service": "davidlong-tech-backend"}), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
