"""
Task 4.6 — Canary Token System Verification Suite
"""
import asyncio
import time
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.deception.canary import CanaryManager

PASS = "[PASS]"
FAIL = "[FAIL]"
results = []

def check(label, condition):
    tag = PASS if condition else FAIL
    results.append(condition)
    print(f"  {tag} {label}")


# ── 1. Token generation ──────────────────────────────────────────────────────
mgr = CanaryManager()
tokens = mgr.generate_for_node("node_test_01")
check("1. generate_for_node returns 2 tokens", len(tokens) == 2)

# ── 2. Unique token IDs ──────────────────────────────────────────────────────
ids = [t.token_id for t in tokens]
check("2. Token IDs are unique", len(set(ids)) == 2)

# ── 3. URL generation ────────────────────────────────────────────────────────
for t in tokens:
    check(f"3. token_url format correct ({t.token_type})", t.token_url == f"/api/canary/{t.token_id}")

# ── 4. get_token lookup ──────────────────────────────────────────────────────
fetched = mgr.get_token(tokens[0].token_id)
check("4. get_token returns correct token", fetched is not None and fetched.token_id == tokens[0].token_id)
check("4b. get_token returns None for unknown id", mgr.get_token("nonexistent") is None)

# ── 5. Triggering ────────────────────────────────────────────────────────────
triggered = mgr.mark_triggered(tokens[0].token_id, "10.0.0.1")
check("5. mark_triggered sets triggered=True", triggered.triggered is True)
check("5b. triggered_by_ip stored", triggered.triggered_by_ip == "10.0.0.1")
check("5c. triggered_at is a float", isinstance(triggered.triggered_at, float))

# ── 6. Duplicate trigger prevention ─────────────────────────────────────────
original_time = triggered.triggered_at
time.sleep(0.01)
mgr.mark_triggered(tokens[0].token_id, "10.0.0.2")
check("6. Duplicate trigger does not overwrite triggered_by_ip",
      mgr.get_token(tokens[0].token_id).triggered_by_ip == "10.0.0.1")
check("6b. Duplicate trigger does not overwrite triggered_at",
      mgr.get_token(tokens[0].token_id).triggered_at == original_time)

# ── 7. get_all_for_node ──────────────────────────────────────────────────────
mgr2 = CanaryManager()
mgr2.generate_for_node("node_A")
mgr2.generate_for_node("node_B")
node_a_tokens = mgr2.get_all_for_node("node_A")
check("7. get_all_for_node returns only matching node tokens", len(node_a_tokens) == 2)
check("7b. All returned tokens belong to node_A", all(t.node_id == "node_A" for t in node_a_tokens))

# ── 8. Route behavior — 404 on unknown token ────────────────────────────────
async def test_route_404():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from backend.api.routes import router, set_sio
    set_sio(None)
    app = FastAPI()
    app.include_router(router, prefix="/api")
    client = TestClient(app)
    resp = client.get("/api/canary/doesnotexist")
    check("8. Route returns 404 for unknown token", resp.status_code == 404)

asyncio.run(test_route_404())

# ── 9. Route behavior — 403 on valid token ───────────────────────────────────
async def test_route_403():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from backend.api.routes import router, set_sio
    from backend.deception.canary import canary_manager

    set_sio(None)
    planted = canary_manager.generate_for_node("node_route_test")
    token_id = planted[0].token_id

    app = FastAPI()
    app.include_router(router, prefix="/api")
    client = TestClient(app)
    resp = client.get(f"/api/canary/{token_id}")
    check("9. Route returns 403 for valid token", resp.status_code == 403)
    check("9b. Response body contains 'Forbidden'", "Forbidden" in resp.text)

asyncio.run(test_route_403())

# ── 10. Socket.IO event emission ─────────────────────────────────────────────
async def test_socket_emit():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from backend.api.routes import router, set_sio
    from backend.deception.canary import canary_manager

    mock_sio = AsyncMock()
    set_sio(mock_sio)
    planted = canary_manager.generate_for_node("node_socket_test")
    token_id = planted[0].token_id

    app = FastAPI()
    app.include_router(router, prefix="/api")
    client = TestClient(app)
    client.get(f"/api/canary/{token_id}")

    emitted_events = [call.args[0] for call in mock_sio.emit.call_args_list]
    check("10. CANARY_TRIGGERED event emitted", "canary_triggered" in emitted_events)
    set_sio(None)

asyncio.run(test_socket_emit())

# ── 11. Alert integration failure handling ───────────────────────────────────
async def test_alert_failure():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from backend.api.routes import router, set_sio
    from backend.deception.canary import canary_manager

    set_sio(None)
    planted = canary_manager.generate_for_node("node_alert_test")
    token_id = planted[0].token_id

    app = FastAPI()
    app.include_router(router, prefix="/api")
    client = TestClient(app)

    with patch("backend.alerting.slack.alert_canary_triggered", side_effect=Exception("slack down")):
        resp = client.get(f"/api/canary/{token_id}")
    check("11. Route still returns 403 when Slack alert fails", resp.status_code == 403)

asyncio.run(test_alert_failure())

# ── Summary ──────────────────────────────────────────────────────────────────
total = len(results)
passed = sum(results)
print()
print("=" * 60)
print(f"Total: {total} | PASS: {passed} | FAIL: {total - passed}")
print("=" * 60)
