"""
ShadowMesh — Task 4.2B: Fake DB Honeypot
========================================
A Flask-based fake DB honeypot server that:
  - Listens on port 3306 inside the container
  - Presents an authentic, premium phpMyAdmin login portal on GET /
  - Rejects POST /login attempts with HTTP 401 and "Access denied" after 400ms
  - Exposes fake tables and fake employee payroll dump endpoints
  - Binds headers indicating Server: nginx/1.14.0 and MySQL 8.0.28 engine
  - Posts callback action telemetry back to the ShadowMesh FastAPI backend
  - Runs in isolation and maintains statelessness

Environment variables:
  NODE_ID              — Injected by container manager (default: fake-db-node)
  ATTACKER_CALLBACK_URL — FastAPI core backend base URL (default: http://backend:8000)
"""

import os
import time
import logging
import threading
import requests
from flask import Flask, jsonify, request, Response, abort

# ---------------------------------------------------------------------------
# Configuration & Setup
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("DB_PORT", 3306))
NODE_ID = os.environ.get("NODE_ID", "fake-db-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-db")

app = Flask(__name__)

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
# Fake Data Stores
# ---------------------------------------------------------------------------
FAKE_TABLES = [
    "users",
    "transactions",
    "employee_payroll",
    "audit_log",
    "customer_pii"
]

FAKE_PAYROLL = [
    {"employee_id": "EMP-9401", "name": "Alice Smith", "department": "Executive", "salary": 185000},
    {"employee_id": "EMP-1024", "name": "Bob Jones", "department": "Engineering", "salary": 140000},
    {"employee_id": "EMP-8830", "name": "Charlie Brown", "department": "DevOps", "salary": 125000},
    {"employee_id": "EMP-4105", "name": "Diana Prince", "department": "Security", "salary": 138000},
    {"employee_id": "EMP-2391", "name": "Ethan Hunt", "department": "Operations", "salary": 115000},
    {"employee_id": "EMP-7742", "name": "Fiona Gallagher", "department": "HR", "salary": 92000},
    {"employee_id": "EMP-0912", "name": "George Clark", "department": "Engineering", "salary": 155000},
    {"employee_id": "EMP-5043", "name": "Hannah Abbott", "department": "Quality Assurance", "salary": 88000},
    {"employee_id": "EMP-6610", "name": "Ian Malcolm", "department": "Data Science", "salary": 165000},
    {"employee_id": "EMP-3049", "name": "Julia Roberts", "department": "Marketing", "salary": 95000}
]

# High-fidelity phpMyAdmin login HTML
PMA_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>phpMyAdmin</title>
    <style>
        body {
            font-family: sans-serif;
            background-color: #f3f3f3;
            color: #333333;
            margin: 0;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container {
            width: 480px;
            background: #ffffff;
            border: 1px solid #d3d3d3;
            border-radius: 5px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.06);
            overflow: hidden;
        }
        .header {
            background-color: #f8f8f8;
            border-bottom: 1px solid #d3d3d3;
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            font-size: 24px;
            font-weight: normal;
            margin: 0;
            color: #ff9900; /* phpMyAdmin logo orange */
        }
        .header h1 span {
            color: #6c757d;
            font-size: 16px;
        }
        .content {
            padding: 30px;
        }
        .section-title {
            font-size: 14px;
            font-weight: bold;
            border-bottom: 1px solid #eeeeee;
            padding-bottom: 8px;
            margin-bottom: 20px;
            color: #555555;
        }
        .form-group {
            margin-bottom: 16px;
            display: flex;
            align-items: center;
        }
        label {
            width: 120px;
            font-size: 12px;
            color: #666666;
        }
        .input-container {
            flex-grow: 1;
        }
        input, select {
            width: 100%;
            padding: 8px 10px;
            border: 1px solid #cccccc;
            border-radius: 3px;
            font-size: 13px;
            box-sizing: border-box;
        }
        input:focus {
            outline: none;
            border-color: #ff9900;
            box-shadow: 0 0 4px rgba(255, 153, 0, 0.25);
        }
        .error-box {
            display: none;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 13px;
            text-align: center;
        }
        .btn-submit {
            display: block;
            width: 100px;
            padding: 8px 16px;
            background-color: #f8f8f8;
            border: 1px solid #cccccc;
            border-radius: 3px;
            color: #333333;
            font-size: 13px;
            font-weight: bold;
            cursor: pointer;
            margin-left: auto;
            transition: all 0.1s ease;
        }
        .btn-submit:hover {
            background-color: #e8e8e8;
            border-color: #adadad;
        }
        .footer {
            background-color: #f8f8f8;
            border-top: 1px solid #eeeeee;
            padding: 15px;
            text-align: center;
            font-size: 11px;
            color: #888888;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>phpMyAdmin <span>Database Server Management</span></h1>
        </div>
        <div class="content">
            <div class="error-box" id="errorBox">Access denied</div>
            
            <div class="section-title">Language Selection</div>
            <div class="form-group">
                <label>Language</label>
                <div class="input-container">
                    <select disabled>
                        <option>English</option>
                    </select>
                </div>
            </div>

            <div class="section-title">Database Administration Login</div>
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label for="pma_username">Username</label>
                    <div class="input-container">
                        <input type="text" id="pma_username" name="pma_username" required autocomplete="username" value="root">
                    </div>
                </div>
                <div class="form-group">
                    <label for="pma_password">Password</label>
                    <div class="input-container">
                        <input type="password" id="pma_password" name="pma_password" required autocomplete="current-password" placeholder="••••••••">
                    </div>
                </div>
                <button type="submit" class="btn-submit" id="submitBtn">Go</button>
            </form>
        </div>
        <div class="footer">
            Server Engine: nginx/1.14.0 | Database: MySQL 8.0.28
        </div>
    </div>

    <script>
        function handleLogin(e) {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const errorBox = document.getElementById('errorBox');
            
            btn.textContent = 'Loading...';
            btn.disabled = true;
            errorBox.style.display = 'none';

            const payload = {
                username: document.getElementById('pma_username').value,
                password: document.getElementById('pma_password').value
            };

            fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => {
                if (res.status === 401) {
                    return res.json().then(data => {
                        errorBox.textContent = data.error || 'Access denied';
                        errorBox.style.display = 'block';
                    });
                }
                errorBox.textContent = 'Unexpected server response';
                errorBox.style.display = 'block';
            })
            .catch(() => {
                errorBox.textContent = 'Database Connection Timeout';
                errorBox.style.display = 'block';
            })
            .finally(() => {
                btn.textContent = 'Go';
                btn.disabled = false;
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
    response.headers["Server"] = "nginx/1.14.0"
    response.headers["X-Database-Engine"] = "MySQL/8.0.28"
    
    # Extract attacker details
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    # Classify action type: POST login is an attempt, general queries are data_access
    if request.path == "/login" and request.method == "POST":
        action_type = "login_attempt"
        detail = "Database login attempt — URL: /login"
    else:
        action_type = "data_access"
        detail = f"Database access — {request.method} {request.path}"
        
    if response.status_code == 404:
        detail = f"Database 404 Not Found — {request.method} {request.path}"
        
    _fire_callback_async(attacker_ip, action_type, detail)
    return response

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return Response(PMA_LOGIN_HTML, mimetype="text/html")


@app.route("/login", methods=["POST"])
def post_login():
    # Mandated 400ms delay to simulate secure LDAP/hashed credentials lookup (T4.2B)
    time.sleep(0.4)
    
    resp = {
        "error": "Access denied"
    }
    return jsonify(resp), 401


@app.route("/tables", methods=["GET"])
def get_tables():
    return jsonify(FAKE_TABLES)


@app.route("/dump", methods=["GET"])
def get_dump():
    return jsonify(FAKE_PAYROLL)


# Custom 404 handler matching database gateway behavior
@app.errorhandler(404)
def page_not_found(e):
    # Standard minimal text error
    return Response("Not Found", status=404, mimetype="text/plain")


if __name__ == "__main__":
    log.info("=== ShadowMesh Fake Database Honeypot ===")
    log.info("NODE_ID            : %s", NODE_ID)
    log.info("ATTACKER_CALLBACK  : %s", CALLBACK_ENDPOINT)
    log.info("Listening on       : %s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, threaded=True)
