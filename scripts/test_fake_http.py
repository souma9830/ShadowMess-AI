"""
test_fake_http.py — Task 4.2A Verification Suite
=================================================
Tests for the ShadowMesh Fake HTTP Honeypot (docker/fake-http/server.py).

Covers:
  T4.2A.1  GET / returns internal portal HTML containing required string
  T4.2A.2  GET /api/ returns correct version and endpoints JSON
  T4.2A.3  GET /api/users returns 8 fake employee profiles
  T4.2A.4  GET /api/config returns DB address and production environment
  T4.2A.5  POST /api/login returns credentials error after 600ms delay
  T4.2A.6  Unknown route returns realistic Nginx-style 404
  T4.2A.7  Custom headers (Server: Apache/2.4.41 (Ubuntu) & X-Powered-By: PHP/7.4.33)
  T4.2A.8  Callback POST matches target NODE_ID and standard payload schema

Usage:
    python scripts/test_fake_http.py
"""

import os
import sys
import time
import socket
import threading
import unittest
import requests
from unittest.mock import patch, MagicMock

# Inject docker/fake-http into sys.path to run tests in-process
SERVER_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docker", "fake-http",
)
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

os.environ.setdefault("NODE_ID", "test-http-node-402")
os.environ.setdefault("ATTACKER_CALLBACK_URL", "http://mock-backend:8000")

import server  # noqa: E402

# Terminal styles
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
_results = []

def _record(test_id: str, passed: bool, detail: str = "") -> None:
    _results.append((test_id, passed, detail))
    status = PASS if passed else FAIL
    print(f"  {status} {test_id}" + (f" — {detail}" if detail else ""))

class HTTPHarness:
    """Manages the Flask server execution context locally on an ephemeral port."""
    def __init__(self):
        self.port = self._find_free_port()
        self._thread = None
        
    def _find_free_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
            
    def start(self):
        # We start the Flask app in-process using standard threading
        self._thread = threading.Thread(
            target=lambda: server.app.run(host="127.0.0.1", port=self.port, debug=False, use_reloader=False),
            daemon=True
        )
        self._thread.start()
        # Sleep slightly to let the WSGI app spawn and listen
        time.sleep(0.3)

_harness = None

def _get_harness():
    global _harness
    if _harness is None:
        _harness = HTTPHarness()
        _harness.start()
    return _harness

# ---------------------------------------------------------------------------
# Test Executions
# ---------------------------------------------------------------------------
def test_get_index():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/"
    try:
        resp = requests.get(url, timeout=3)
        has_str = "Internal Employee Portal — Login Required" in resp.text
        has_server = resp.headers.get("Server") == "Apache/2.4.41 (Ubuntu)"
        has_powered = resp.headers.get("X-Powered-By") == "PHP/7.4.33"
        
        ok = has_str and has_server and has_powered
        _record("T4.2A.1 GET / matches Portal HTML specifications", ok, f"Headers: Server={resp.headers.get('Server')}")
    except Exception as e:
        _record("T4.2A.1 GET / matches Portal HTML specifications", False, str(e))

def test_get_api_root():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/api/"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = data.get("version") == "2.3.1" and "/api/users" in data.get("endpoints", [])
        _record("T4.2A.2 GET /api/ returns version metadata", ok, f"version={data.get('version')}")
    except Exception as e:
        _record("T4.2A.2 GET /api/ returns version metadata", False, str(e))

def test_get_users():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/api/users"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = isinstance(data, list) and len(data) == 8
        detail = f"found {len(data)} employee profiles" if ok else "list layout mismatch"
        _record("T4.2A.3 GET /api/users returns 8 employee profiles", ok, detail)
    except Exception as e:
        _record("T4.2A.3 GET /api/users returns 8 employee profiles", False, str(e))

def test_get_config():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/api/config"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = data.get("db_host") == "172.20.0.12" and data.get("db_port") == 3306
        _record("T4.2A.4 GET /api/config returns fake credentials configuration", ok, f"db_host={data.get('db_host')}")
    except Exception as e:
        _record("T4.2A.4 GET /api/config returns fake credentials configuration", False, str(e))

def test_post_login():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/api/login"
    t0 = time.perf_counter()
    try:
        resp = requests.post(url, json={"username": "admin", "password": "password123"}, timeout=5)
        elapsed = time.perf_counter() - t0
        data = resp.json()
        
        has_error = data.get("success") is False and "Invalid credentials" in data.get("error", "")
        delay_ok = elapsed >= 0.55 # Assert 600ms login verification simulation delay
        
        ok = has_error and delay_ok
        _record("T4.2A.5 POST /api/login rejects credentials with 600ms delay", ok, f"elapsed={elapsed*1000:.0f}ms")
    except Exception as e:
        _record("T4.2A.5 POST /api/login rejects credentials with 600ms delay", False, str(e))

def test_unknown_route():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/api/some/random/unmapped/endpoint"
    try:
        resp = requests.get(url, timeout=3)
        ok = resp.status_code == 404 and "nginx" in resp.text and "404 Not Found" in resp.text
        _record("T4.2A.6 GET unknown route returns Nginx-style 404 page", ok, f"Status code: {resp.status_code}")
    except Exception as e:
        _record("T4.2A.6 GET unknown route returns Nginx-style 404 page", False, str(e))

def test_headers():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/api/users"
    try:
        resp = requests.get(url, timeout=3)
        server_header = resp.headers.get("Server")
        powered_header = resp.headers.get("X-Powered-By")
        ok = server_header == "Apache/2.4.41 (Ubuntu)" and powered_header == "PHP/7.4.33"
        _record("T4.2A.7 Banners match requirements (Apache/Ubuntu + PHP)", ok, f"Server: {server_header} | X-Powered-By: {powered_header}")
    except Exception as e:
        _record("T4.2A.7 Banners match requirements (Apache/Ubuntu + PHP)", False, str(e))

def test_callbacks():
    captured_payloads = []
    
    # Mocking standard requests.post inside server module to track telemetry dispatching
    def mock_post(url, json=None, timeout=None):
        if json:
            captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.status_code = 200
        return mock_response
        
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/api/users"
    
    with patch("server.requests.post", side_effect=mock_post):
        try:
            # Trigger request that sets off background telemetry daemon
            requests.get(url, timeout=3)
            # Sleep slightly to let the daemon thread complete its POST execution
            time.sleep(0.2)
        except Exception as e:
            _record("T4.2A.8 Telemetry callback dispatches successfully", False, str(e))
            return
            
    ok = len(captured_payloads) > 0
    if ok:
        payload = captured_payloads[0]
        correct_fields = {"attacker_ip", "action_type", "target_node_id", "detail", "timestamp"}.issubset(payload.keys())
        node_id_ok = payload.get("target_node_id") == "test-http-node-402"
        action_type_ok = payload.get("action_type") == "data_access"
        
        all_passed = correct_fields and node_id_ok and action_type_ok
        _record("T4.2A.8 Telemetry callback dispatches successfully", all_passed, f"Payload structure verified: node_id={payload.get('target_node_id')}")
    else:
        _record("T4.2A.8 Telemetry callback dispatches successfully", False, "No callback payloads captured during execution")

def _print_summary():
    total = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = total - passed
    print("\n" + "="*60)
    print(f"Total: {total} | PASS: {passed} | FAIL: {failed}")
    print("="*60)
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    print("\n" + "═"*60)
    print("═══ TASK 4.2A — Fake HTTP Honeypot Verification Suite ═══")
    print("═"*60)
    
    test_get_index()
    test_get_api_root()
    test_get_users()
    test_get_config()
    test_post_login()
    test_unknown_route()
    test_headers()
    test_callbacks()
    
    sys.exit(_print_summary())
