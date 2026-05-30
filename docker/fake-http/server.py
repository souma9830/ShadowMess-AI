"""
ShadowMesh — Task 4.2A: Fake HTTP Honeypot
===========================================
A Flask-based fake HTTP honeypot server that:
  - Listens on port 80 inside the container
  - Presents a premium look internal employee login portal for GET /
  - Provides realistic API endpoints (/api/, /api/users, /api/config)
  - Simulates a delayed credential validation on POST /api/login (600ms delay, returns failure)
  - Returns realistic nginx-style 404 pages for unknown routes
  - Returns Apache and PHP banners in headers (Server: Apache/2.4.41 (Ubuntu), X-Powered-By: PHP/7.4.33)
  - Posts callback action telemetry back to the ShadowMesh FastAPI backend
  - Never accesses actual databases or systems

Environment variables:
  NODE_ID              — The honeypot node ID injected by the container_manager
  ATTACKER_CALLBACK_URL — Base URL of the ShadowMesh backend (default: http://backend:8000)
"""

import os
import time
import logging
import threading
import requests
from flask import Flask, jsonify, request, Response, abort

# Override Werkzeug WSGI server header output in local testing
try:
    import werkzeug.serving
    _orig_send_header = werkzeug.serving.WSGIRequestHandler.send_header
    
    def _patched_send_header(self, keyword, value):
        # Skip Werkzeug's default/empty Server header to avoid duplication
        if keyword.lower() == 'server' and (not value or "Werkzeug" in value or value.strip() == ""):
            return
        _orig_send_header(self, keyword, value)
        
    werkzeug.serving.WSGIRequestHandler.send_header = _patched_send_header
except Exception:
    pass

# ---------------------------------------------------------------------------
# Configuration & Setup
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("HTTP_PORT", 80))
NODE_ID = os.environ.get("NODE_ID", "fake-http-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-http")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Fake Data Stores
# ---------------------------------------------------------------------------
FAKE_EMPLOYEES = [
    {"name": "Alice Smith", "role": "Network Administrator", "email": "alice.smith@corp.internal"},
    {"name": "Bob Jones", "role": "Database Administrator", "email": "bob.jones@corp.internal"},
    {"name": "Charlie Brown", "role": "DevOps Engineer", "email": "charlie.brown@corp.internal"},
    {"name": "Diana Prince", "role": "Security Analyst", "email": "diana.prince@corp.internal"},
    {"name": "Ethan Hunt", "role": "Systems Engineer", "email": "ethan.hunt@corp.internal"},
    {"name": "Fiona Gallagher", "role": "HR Director", "email": "fiona.gallagher@corp.internal"},
    {"name": "George Clark", "role": "CTO", "email": "george.clark@corp.internal"},
    {"name": "Hannah Abbott", "role": "QA Engineer", "email": "hannah.abbott@corp.internal"}
]

FAKE_CONFIG = {
    "db_host": "172.20.0.12",
    "db_port": 3306,
    "environment": "production",
    "debug": False
}

# Nginx-style 404 HTML Page
NGINX_404_HTML = """<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
"""

# Premium corporate HTML portal page
PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internal Employee Portal — Login Required</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }
        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            overflow: hidden;
        }
        .container {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            animation: fadeIn 0.6s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .header {
            text-align: center;
            margin-bottom: 32px;
        }
        .logo {
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #38bdf8, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #94a3b8;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
            position: relative;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 13px;
            font-weight: 500;
            color: #cbd5e1;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            background: rgba(15, 23, 42, 0.6);
            color: #ffffff;
            font-size: 15px;
            transition: all 0.3s ease;
        }
        input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
        }
        .btn-submit {
            display: block;
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: #ffffff;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.2);
            margin-top: 24px;
        }
        .btn-submit:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(37, 99, 235, 0.35);
        }
        .btn-submit:active {
            transform: translateY(1px);
        }
        .alert-error {
            display: none;
            margin-top: 16px;
            padding: 12px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #f87171;
            border-radius: 8px;
            font-size: 13px;
            text-align: center;
        }
        .footer {
            margin-top: 32px;
            text-align: center;
            font-size: 12px;
            color: #64748b;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">CORP_NET</div>
            <div class="subtitle">Internal Employee Portal — Login Required</div>
        </div>
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="e.g. employee@corp.internal" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••••••" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn-submit">Sign In</button>
            <div id="errorMessage" class="alert-error">Invalid credentials</div>
        </form>
        <div class="footer">
            Secured by CORP_NET Access Gateways<br>
            Server: Apache/2.4.41 (Ubuntu) PHP/7.4.33
        </div>
    </div>

    <script>
        function handleLogin(e) {
            e.preventDefault();
            const btn = document.querySelector('.btn-submit');
            const alert = document.getElementById('errorMessage');
            btn.textContent = 'Authenticating...';
            btn.disabled = true;
            alert.style.display = 'none';

            const payload = {
                username: document.getElementById('username').value,
                password: document.getElementById('password').value
            };

            fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => res.json())
            .then(data => {
                btn.textContent = 'Sign In';
                btn.disabled = false;
                alert.textContent = data.error || 'Connection Failed';
                alert.style.display = 'block';
            })
            .catch(() => {
                btn.textContent = 'Sign In';
                btn.disabled = false;
                alert.textContent = 'Internal Server Authentication Error';
                alert.style.display = 'block';
            });
        }
    </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Background Callbacks Engine
# ---------------------------------------------------------------------------
def _fire_callback(attacker_ip: str, action_type: str, detail: str) -> None:
    """POST request metrics back to FastAPI backend core."""
    payload = {
        "attacker_ip": attacker_ip,
        "action_type": action_type,
        "target_node_id": NODE_ID,
        "detail": detail,
        "timestamp": time.time(),
    }
    try:
        resp = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
        log.info("[callback] POST %s → %s (%s)", CALLBACK_ENDPOINT, resp.status_code, action_type)
    except Exception as exc:
        log.warning("[callback] Failed to reach backend: %s", exc)


def _fire_callback_async(attacker_ip: str, action_type: str, detail: str) -> None:
    """Spawn daemon thread to handle telemetry callback without blocking server responses."""
    t = threading.Thread(
        target=_fire_callback,
        args=(attacker_ip, action_type, detail),
        daemon=True,
    )
    t.start()

# ---------------------------------------------------------------------------
# Middleware: Add server banners and fire callback telemetry
# ---------------------------------------------------------------------------
@app.after_request
def modify_response(response: Response) -> Response:
    # Set headers mandated by senior specs
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.33"
    
    # Extract attacker details
    # Handle cases behind proxies (e.g. Docker container networks)
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    # Classify action type: POST login is an attempt, general queries are data_access
    if request.path == "/api/login" and request.method == "POST":
        action_type = "login_attempt"
        # Safely capture detail without leaking plain text passwords if too sensitive
        detail = f"HTTP login attempt — URL: {request.path}"
    else:
        action_type = "data_access"
        detail = f"HTTP access — {request.method} {request.path}"
        
    # Standardize 404 alerts if route does not exist
    if response.status_code == 404:
        detail = f"HTTP 404 Not Found — {request.method} {request.path}"
        
    _fire_callback_async(attacker_ip, action_type, detail)
    return response

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return Response(PORTAL_HTML, mimetype="text/html")


@app.route("/api/", methods=["GET"])
def api_root():
    endpoints = {
        "version": "2.3.1",
        "endpoints": [
            "/api/users",
            "/api/reports",
            "/api/config"
        ]
    }
    return jsonify(endpoints)


@app.route("/api/users", methods=["GET"])
def get_users():
    canary_url = os.environ.get("CANARY_WIKI_URL", "")
    employees = [dict(e) for e in FAKE_EMPLOYEES]
    if canary_url:
        for emp in employees:
            emp["internal_wiki_url"] = canary_url
    return jsonify(employees)


@app.route("/api/config", methods=["GET"])
def get_config():
    return jsonify(FAKE_CONFIG)


@app.route("/api/login", methods=["POST"])
def post_login():
    # Mandated 600ms delay to simulate standard corporate database verification (T4.2A)
    time.sleep(0.6)
    
    resp = {
        "success": False,
        "error": "Invalid credentials"
    }
    return jsonify(resp)

# ---------------------------------------------------------------------------
# Realistic nginx-style 404 Handler
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return Response(NGINX_404_HTML, status=404, mimetype="text/html")

# Let's ensure other HTTP error handlers fallback properly
@app.errorhandler(405)
def method_not_allowed(e):
    return Response(NGINX_404_HTML, status=404, mimetype="text/html")


if __name__ == "__main__":
    log.info("=== ShadowMesh Fake HTTP Honeypot ===")
    log.info("NODE_ID            : %s", NODE_ID)
    log.info("ATTACKER_CALLBACK  : %s", CALLBACK_ENDPOINT)
    log.info("Listening on       : %s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, threaded=True)
