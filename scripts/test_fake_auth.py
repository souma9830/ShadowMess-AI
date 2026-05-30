"""
test_fake_auth.py — Task 4.2D Verification Suite
=================================================
Tests for the ShadowMesh Fake LDAP/SSO Honeypot (docker/fake-auth/server.py).

Covers:
  1. GET /ldap/search returns valid XML with 20 users
  2. POST /ldap/bind always returns invalidCredentials/49
  3. GET /sso/metadata returns valid SAML XML
  4. POST /sso/login fails with 500ms delay
  5. Headers present (Microsoft-IIS/10.0 and ASP.NET)
  6. Callback firing (login_attempt)

Usage:
    python scripts/test_fake_auth.py
"""

import os
import sys
import time
import socket
import threading
import xml.etree.ElementTree as ET
import requests
from unittest.mock import patch, MagicMock

# Inject docker/fake-auth into sys.path to run tests in-process
SERVER_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docker", "fake-auth",
)
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

os.environ.setdefault("NODE_ID", "test-auth-node-402d")
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

class AuthHarness:
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
        _harness = AuthHarness()
        _harness.start()
    return _harness

# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------
def test_get_ldap_search():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/ldap/search"
    try:
        resp = requests.get(url, timeout=3)
        # Verify XML validity
        root = ET.fromstring(resp.content)
        users = root.findall('user')
        ok = len(users) == 20
        _record("1 & 7. GET /ldap/search returns valid XML with 20 users", ok, f"users={len(users)}")
    except Exception as e:
        _record("1 & 7. GET /ldap/search returns valid XML with 20 users", False, str(e))

def test_post_ldap_bind():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/ldap/bind"
    try:
        resp = requests.post(url, json={"username": "admin", "password": "password"}, timeout=3)
        data = resp.json()
        ok = resp.status_code == 401 and data.get("result") == "invalidCredentials" and data.get("code") == 49
        _record("2. POST /ldap/bind always returns invalidCredentials/49", ok, f"status={resp.status_code}")
    except Exception as e:
        _record("2. POST /ldap/bind always returns invalidCredentials/49", False, str(e))

def test_get_sso_metadata():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/sso/metadata"
    try:
        resp = requests.get(url, timeout=3)
        # Verify XML validity
        root = ET.fromstring(resp.content)
        ok = "EntityDescriptor" in root.tag or root.tag.endswith("EntityDescriptor")
        _record("3 & 7. GET /sso/metadata returns valid SAML XML", ok, f"tag={root.tag}")
    except Exception as e:
        _record("3 & 7. GET /sso/metadata returns valid SAML XML", False, str(e))

def test_post_sso_login():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/sso/login"
    t0 = time.perf_counter()
    try:
        resp = requests.post(url, data={"SAMLResponse": "fake"}, timeout=5)
        elapsed = time.perf_counter() - t0
        
        status_ok = resp.status_code == 401
        delay_ok = elapsed >= 0.45 # Assert 500ms delay
        
        ok = status_ok and delay_ok
        _record("4. POST /sso/login fails with 500ms delay", ok, f"elapsed={elapsed*1000:.0f}ms | status={resp.status_code}")
    except Exception as e:
        _record("4. POST /sso/login fails with 500ms delay", False, str(e))

def test_headers():
    harness = _get_harness()
    url = f"http://127.0.0.1:{harness.port}/ldap/search"
    try:
        resp = requests.get(url, timeout=3)
        server_header = resp.headers.get("Server")
        powered_header = resp.headers.get("X-Powered-By")
        
        ok = server_header == "Microsoft-IIS/10.0" and powered_header == "ASP.NET"
        _record("5. Headers present (Microsoft-IIS/10.0 and ASP.NET)", ok, f"Server: {server_header} | X-Powered-By: {powered_header}")
    except Exception as e:
        _record("5. Headers present (Microsoft-IIS/10.0 and ASP.NET)", False, str(e))

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
            requests.get(f"http://127.0.0.1:{harness.port}/ldap/search", timeout=3)
            time.sleep(0.1)
        except Exception as e:
            _record("6. Callback firing (login_attempt)", False, str(e))
            return
            
    ok = len(captured_payloads) == 1
    if ok:
        payload = captured_payloads[0]
        action_ok = payload.get("action_type") == "login_attempt"
        node_id_ok = payload.get("target_node_id") == "test-auth-node-402d"
        _record("6. Callback firing (login_attempt)", action_ok and node_id_ok, f"action_type={payload.get('action_type')}")
    else:
        _record("6. Callback firing (login_attempt)", False, f"captured={len(captured_payloads)}")

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
    print("═══ TASK 4.2D — Fake Auth Honeypot Verification Suite ═══")
    print("═"*60)
    
    test_get_ldap_search()
    test_post_ldap_bind()
    test_get_sso_metadata()
    test_post_sso_login()
    test_headers()
    test_callbacks()
    
    sys.exit(_print_summary())
