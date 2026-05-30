"""
test_fake_api.py — Task 4.2C Verification Suite
================================================
Tests for the ShadowMesh Fake API Honeypot (docker/fake-api/server.py).

Covers:
  1. GET /v1/health returns expected JSON
  2. GET /v1/services returns 6 fake services
  3. GET /v1/tokens returns expected JSON
  4. GET /v1/employees returns 15 fake employees
  5. POST /v1/auth/token rejects with HTTP 401 after 300ms delay
  6. Headers present (nginx/1.18.0 and 3.1.4)
  7. credential_theft callback fires on /v1/tokens
  8. data_access callback fires on normal endpoints

Usage:
    python scripts/test_fake_api.py
"""

import os
import sys
import time
import socket
import threading
import unittest
import requests
from unittest.mock import patch, MagicMock

# Inject docker/fake-api into sys.path to run tests in-process
SERVER_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docker", "fake-api",
)
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

os.environ.setdefault("NODE_ID", "test-api-node-402c")
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

class APIHarness:
    """Manages the Flask API server execution context locally on an ephemeral port."""
    def __init__(self):
        self.port = self._find_free_port()
        self._thread = None
        
    def _find_free_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
            
    def start(self):
        self._thread = threading.Thread(
            target=lambda: server.app.run(host="127.0.0.1", port=self.port, debug=False, use_reloader=False),
            daemon=True
        )
        self._thread.start()
        time.sleep(0.3)

_harness = None

def _get_harness():
    global _harness
    if _harness is None:
        _harness = APIHarness()
        _harness.start()
    return _harness

# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------
def test_get_health():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/v1/health"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = data.get("status") == "ok" and data.get("version") == "3.1.4" and data.get("env") == "production"
        _record("1. GET /v1/health returns expected JSON", ok, f"data={data}")
    except Exception as e:
        _record("1. GET /v1/health returns expected JSON", False, str(e))

def test_get_services():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/v1/services"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = isinstance(data, list) and len(data) == 6
        _record("2. GET /v1/services returns 6 fake services", ok, f"len={len(data)}")
    except Exception as e:
        _record("2. GET /v1/services returns 6 fake services", False, str(e))

def test_get_tokens():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/v1/tokens"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = "api_key" in data and "expires" in data
        _record("3. GET /v1/tokens returns expected JSON", ok, f"keys={list(data.keys())}")
    except Exception as e:
        _record("3. GET /v1/tokens returns expected JSON", False, str(e))

def test_get_employees():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/v1/employees"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = isinstance(data, list) and len(data) == 15
        item = data[0] if ok else {}
        item_ok = "employee_id" in item and "name" in item and "department" in item and "salary" in item and "ssn" in item
        _record("4. GET /v1/employees returns 15 fake employees", ok and item_ok, f"len={len(data)}")
    except Exception as e:
        _record("4. GET /v1/employees returns 15 fake employees", False, str(e))

def test_post_auth_token():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/v1/auth/token"
    t0 = time.perf_counter()
    try:
        resp = requests.post(url, json={"username": "root", "password": "password123"}, timeout=5)
        elapsed = time.perf_counter() - t0
        data = resp.json()
        
        status_ok = resp.status_code == 401
        has_error = data.get("error") == "unauthorized"
        delay_ok = elapsed >= 0.25 # Assert 300ms delay
        
        ok = status_ok and has_error and delay_ok
        _record("5. POST /v1/auth/token returns 401 with 300ms delay", ok, f"elapsed={elapsed*1000:.0f}ms | status={resp.status_code}")
    except Exception as e:
        _record("5. POST /v1/auth/token returns 401 with 300ms delay", False, str(e))

def test_headers():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/v1/health"
    try:
        resp = requests.get(url, timeout=3)
        server_header = resp.headers.get("Server")
        api_header = resp.headers.get("X-API-Version")
        
        ok = server_header == "nginx/1.18.0" and api_header == "3.1.4"
        _record("6. Headers present (nginx/1.18.0 and 3.1.4)", ok, f"Server: {server_header} | X-API-Version: {api_header}")
    except Exception as e:
        _record("6. Headers present (nginx/1.18.0 and 3.1.4)", False, str(e))

def test_callbacks():
    captured_payloads = []
    
    def mock_post(url, json=None, timeout=None):
        if json:
            captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.status_code = 200
        return mock_response
        
    harness = _get_harness()
    
    with patch("server.requests.post", side_effect=mock_post):
        try:
            requests.get(f"http://127.0.0.1:{harness.port}/v1/tokens", timeout=3)
            time.sleep(0.1)
            requests.get(f"http://127.0.0.1:{harness.port}/v1/health", timeout=3)
            time.sleep(0.2)
        except Exception as e:
            _record("7 & 8. Callbacks fire correctly", False, str(e))
            return
            
    ok = len(captured_payloads) == 2
    if ok:
        token_payload = captured_payloads[0]
        health_payload = captured_payloads[1]
        
        token_ok = token_payload.get("action_type") == "credential_theft"
        health_ok = health_payload.get("action_type") == "data_access"
        
        _record("7. credential_theft callback fires on /v1/tokens", token_ok, f"action_type={token_payload.get('action_type')}")
        _record("8. data_access callback fires on normal endpoints", health_ok, f"action_type={health_payload.get('action_type')}")
    else:
        _record("7 & 8. Callbacks fire correctly", False, f"captured={len(captured_payloads)}")

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
    print("═══ TASK 4.2C — Fake API Honeypot Verification Suite ═══")
    print("═"*60)
    
    test_get_health()
    test_get_services()
    test_get_tokens()
    test_get_employees()
    test_post_auth_token()
    test_headers()
    test_callbacks()
    
    sys.exit(_print_summary())
