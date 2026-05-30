"""
test_fake_db.py — Task 4.2B Verification Suite
================================================
Tests for the ShadowMesh Fake Database Honeypot (docker/fake-db/server.py).

Covers:
  T4.2B.1  GET / returns phpMyAdmin login page containing required string
  T4.2B.2  POST /login rejects with HTTP 401 and Access denied JSON after 400ms delay
  T4.2B.3  GET /tables returns exact 5 tables in JSON list
  T4.2B.4  GET /dump returns exactly 10 mock payroll records
  T4.2B.5  Response headers contain Server: nginx/1.14.0 and MySQL engine banner
  T4.2B.6  Callback posts metrics correctly with target NODE_ID

Usage:
    python scripts/test_fake_db.py
"""

import os
import sys
import time
import socket
import threading
import unittest
import requests
from unittest.mock import patch, MagicMock

# Inject docker/fake-db into sys.path to run tests in-process
SERVER_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docker", "fake-db",
)
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

os.environ.setdefault("NODE_ID", "test-db-node-402b")
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

class DBHarness:
    """Manages the Flask database server execution context locally on an ephemeral port."""
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
        _harness = DBHarness()
        _harness.start()
    return _harness

# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------
def test_get_index():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/"
    try:
        resp = requests.get(url, timeout=3)
        has_str = "phpMyAdmin" in resp.text and "Database Administration Login" in resp.text
        has_server = resp.headers.get("Server") == "nginx/1.14.0"
        has_engine = "MySQL/8.0.28" in resp.headers.get("X-Database-Engine", "")
        
        ok = has_str and has_server and has_engine
        _record("T4.2B.1 GET / matches phpMyAdmin specifications", ok, f"Headers: Server={resp.headers.get('Server')}")
    except Exception as e:
        _record("T4.2B.1 GET / matches phpMyAdmin specifications", False, str(e))

def test_post_login():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/login"
    t0 = time.perf_counter()
    try:
        resp = requests.post(url, json={"username": "root", "password": "password123"}, timeout=5)
        elapsed = time.perf_counter() - t0
        data = resp.json()
        
        status_ok = resp.status_code == 401
        has_error = data.get("error") == "Access denied"
        delay_ok = elapsed >= 0.35 # Assert 400ms login verification delay
        
        ok = status_ok and has_error and delay_ok
        _record("T4.2B.2 POST /login returns 401 with 400ms delay", ok, f"elapsed={elapsed*1000:.0f}ms | status={resp.status_code}")
    except Exception as e:
        _record("T4.2B.2 POST /login returns 401 with 400ms delay", False, str(e))

def test_get_tables():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/tables"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        expected = ["users", "transactions", "employee_payroll", "audit_log", "customer_pii"]
        ok = isinstance(data, list) and data == expected
        _record("T4.2B.3 GET /tables returns correct database schemas", ok, f"tables={data}")
    except Exception as e:
        _record("T4.2B.3 GET /tables returns correct database schemas", False, str(e))

def test_get_dump():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/dump"
    try:
        resp = requests.get(url, timeout=3)
        data = resp.json()
        ok = isinstance(data, list) and len(data) == 10
        item = data[0] if ok and len(data) > 0 else {}
        item_ok = "employee_id" in item and "name" in item and "department" in item and "salary" in item
        
        all_passed = ok and item_ok
        _record("T4.2B.4 GET /dump returns 10 detailed payroll rows", all_passed, f"rows={len(data)} | sample={list(item.keys()) if item else None}")
    except Exception as e:
        _record("T4.2B.4 GET /dump returns 10 detailed payroll rows", False, str(e))

def test_headers():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/tables"
    try:
        resp = requests.get(url, timeout=3)
        server_header = resp.headers.get("Server")
        engine_header = resp.headers.get("X-Database-Engine")
        
        ok = server_header == "nginx/1.14.0" and engine_header == "MySQL/8.0.28"
        _record("T4.2B.5 Header banners correctly mimic custom server", ok, f"Server: {server_header} | Engine: {engine_header}")
    except Exception as e:
        _record("T4.2B.5 Header banners correctly mimic custom server", False, str(e))

def test_callbacks():
    captured_payloads = []
    
    def mock_post(url, json=None, timeout=None):
        if json:
            captured_payloads.append(json)
        mock_response = MagicMock()
        mock_response.status_code = 200
        return mock_response
        
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/tables"
    
    with patch("server.requests.post", side_effect=mock_post):
        try:
            requests.get(url, timeout=3)
            # Let daemon finish dispatching background POST
            time.sleep(0.2)
        except Exception as e:
            _record("T4.2B.6 Callback dispatches telemetry successfully", False, str(e))
            return
            
    ok = len(captured_payloads) > 0
    if ok:
        payload = captured_payloads[0]
        correct_fields = {"attacker_ip", "action_type", "target_node_id", "detail", "timestamp"}.issubset(payload.keys())
        node_id_ok = payload.get("target_node_id") == "test-db-node-402b"
        
        all_passed = correct_fields and node_id_ok
        _record("T4.2B.6 Callback dispatches telemetry successfully", all_passed, f"node_id={payload.get('target_node_id')}")
    else:
        _record("T4.2B.6 Callback dispatches telemetry successfully", False, "No callback payloads intercepted")

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
    print("═══ TASK 4.2B — Fake Database Honeypot Verification Suite ═══")
    print("═"*60)
    
    test_get_index()
    test_post_login()
    test_get_tables()
    test_get_dump()
    test_headers()
    test_callbacks()
    
    sys.exit(_print_summary())
