"""
ShadowMesh — Task 4.2C: Fake API Honeypot
=========================================
A Flask-based fake API honeypot server that:
  - Listens on port 8443 inside the container
  - Simulates an internal enterprise API gateway exposing multiple microservices
  - Rejects POST /v1/auth/token attempts with HTTP 401 after 300ms
  - Exposes fake endpoints (/v1/health, /v1/services, /v1/employees, /v1/tokens)
  - Logs specific 'credential_theft' callbacks on /v1/tokens
  - Binds headers indicating Server: nginx/1.18.0 and X-API-Version: 3.1.4
  - Posts callback action telemetry back to the ShadowMesh FastAPI backend
  - Runs in isolation and maintains statelessness

Environment variables:
  NODE_ID              — Injected by container manager (default: fake-api-node)
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
PORT = int(os.environ.get("API_PORT", 8443))
NODE_ID = os.environ.get("NODE_ID", "fake-api-node")
ATTACKER_CALLBACK_URL = os.environ.get("ATTACKER_CALLBACK_URL", "http://backend:8000")
CALLBACK_ENDPOINT = f"{ATTACKER_CALLBACK_URL.rstrip('/')}/api/attacker/action"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fake-api")

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
FAKE_SERVICES = [
    {"name": "employee-service", "endpoint": "/v1/employees"},
    {"name": "payroll-service", "endpoint": "/v1/payroll"},
    {"name": "billing-service", "endpoint": "/v1/billing"},
    {"name": "auth-service", "endpoint": "/v1/auth"},
    {"name": "reporting-service", "endpoint": "/v1/reports"},
    {"name": "customer-pii-service", "endpoint": "/v1/customers"},
]

FAKE_EMPLOYEES = [
    {"employee_id": "EMP-9401", "name": "Alice Smith", "department": "Executive", "salary": 185000, "ssn": "XXX-XX-1234"},
    {"employee_id": "EMP-1024", "name": "Bob Jones", "department": "Engineering", "salary": 140000, "ssn": "XXX-XX-5678"},
    {"employee_id": "EMP-8830", "name": "Charlie Brown", "department": "DevOps", "salary": 125000, "ssn": "XXX-XX-9012"},
    {"employee_id": "EMP-4105", "name": "Diana Prince", "department": "Security", "salary": 138000, "ssn": "XXX-XX-3456"},
    {"employee_id": "EMP-2391", "name": "Ethan Hunt", "department": "Operations", "salary": 115000, "ssn": "XXX-XX-7890"},
    {"employee_id": "EMP-7742", "name": "Fiona Gallagher", "department": "HR", "salary": 92000, "ssn": "XXX-XX-2345"},
    {"employee_id": "EMP-0912", "name": "George Clark", "department": "Engineering", "salary": 155000, "ssn": "XXX-XX-6789"},
    {"employee_id": "EMP-5043", "name": "Hannah Abbott", "department": "Quality Assurance", "salary": 88000, "ssn": "XXX-XX-0123"},
    {"employee_id": "EMP-6610", "name": "Ian Malcolm", "department": "Data Science", "salary": 165000, "ssn": "XXX-XX-4567"},
    {"employee_id": "EMP-3049", "name": "Julia Roberts", "department": "Marketing", "salary": 95000, "ssn": "XXX-XX-8901"},
    {"employee_id": "EMP-1122", "name": "Kevin Bacon", "department": "Sales", "salary": 105000, "ssn": "XXX-XX-2233"},
    {"employee_id": "EMP-3344", "name": "Laura Dern", "department": "Legal", "salary": 175000, "ssn": "XXX-XX-4455"},
    {"employee_id": "EMP-5566", "name": "Michael Scott", "department": "Management", "salary": 110000, "ssn": "XXX-XX-6677"},
    {"employee_id": "EMP-7788", "name": "Nancy Drew", "department": "Investigation", "salary": 98000, "ssn": "XXX-XX-8899"},
    {"employee_id": "EMP-9900", "name": "Oscar Isaac", "department": "Design", "salary": 120000, "ssn": "XXX-XX-0011"},
]

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
    response.headers["Server"] = "nginx/1.18.0"
    response.headers["X-API-Version"] = "3.1.4"
    
    # Extract attacker details
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    # Classify action type based on endpoint
    if request.path == "/v1/tokens" and request.method == "GET":
        action_type = "credential_theft"
        detail = "API token access attempt — GET /v1/tokens"
    elif request.path == "/v1/auth/token" and request.method == "POST":
        action_type = "login_attempt"
        detail = "API auth attempt — POST /v1/auth/token"
    else:
        action_type = "data_access"
        detail = f"API access — {request.method} {request.path}"
        
    if response.status_code == 404:
        detail = f"API 404 Not Found — {request.method} {request.path}"
        
    _fire_callback_async(attacker_ip, action_type, detail)
    return response

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/v1/health", methods=["GET"])
def get_health():
    return jsonify({
        "status": "ok",
        "version": "3.1.4",
        "env": "production"
    })


@app.route("/v1/services", methods=["GET"])
def get_services():
    return jsonify(FAKE_SERVICES)


@app.route("/v1/tokens", methods=["GET"])
def get_tokens():
    return jsonify({
        "api_key": f"/api/creds/{NODE_ID}/aws_key",
        "expires": "2025-12-31"
    })


@app.route("/v1/employees", methods=["GET"])
def get_employees():
    canary_url = os.environ.get("CANARY_WIKI_URL", "")
    employees = [dict(e) for e in FAKE_EMPLOYEES]
    if canary_url:
        for emp in employees:
            emp["note_url"] = canary_url
    return jsonify(employees)


@app.route("/v1/auth/token", methods=["POST"])
def post_auth_token():
    # Mandated 300ms delay
    time.sleep(0.3)
    
    return jsonify({
        "error": "unauthorized"
    }), 401


# Custom 404 handler
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    log.info("=== ShadowMesh Fake API Honeypot ===")
    log.info("NODE_ID            : %s", NODE_ID)
    log.info("ATTACKER_CALLBACK  : %s", CALLBACK_ENDPOINT)
    log.info("Listening on       : %s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, threaded=True)
