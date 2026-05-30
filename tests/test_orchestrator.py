"""
tests/test_orchestrator.py
==========================
Task 9.5 — Automated Test Suite

7 test scenarios as required by the spec:
  1. Health endpoint
  2. Spawn endpoint (valid image)
  3. Spawn with invalid image
  4. Teardown single container endpoint
  5. Teardown-all endpoint
  6. Backend ↔ orchestrator integration (via httpx mock)
  7. Docker daemon unavailable scenario

Usage:
    python tests/test_orchestrator.py
"""

import sys
import os
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

# Ensure project root on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
_results = []

def _record(label: str, ok: bool, detail: str = "") -> None:
    _results.append((label, ok))
    status = PASS if ok else FAIL
    print(f"  {status} {label}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Test 1: Health endpoint
# ---------------------------------------------------------------------------
def test_health_endpoint():
    """Orchestrator /health returns status=ok."""
    # Import orchestrator Flask app and use test client
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "orchestrator"))
    try:
        import importlib
        orch = importlib.import_module("app") if "app" in sys.modules else None
        
        # Re-import fresh
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "orch_app",
            os.path.join(PROJECT_ROOT, "orchestrator", "app.py")
        )
        orch_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(orch_mod)
        
        with orch_mod.app.test_client() as client:
            resp = client.get("/health")
            data = resp.get_json()
            ok = resp.status_code == 200 and data.get("status") == "ok"
            _record("1. /health returns status=ok", ok, f"status={resp.status_code} body={data}")
    except Exception as e:
        _record("1. /health returns status=ok", False, str(e))


# ---------------------------------------------------------------------------
# Test 2: Spawn endpoint — valid image
# ---------------------------------------------------------------------------
def test_spawn_valid():
    """Spawn with valid node_type returns container_id."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "orch_app2",
        os.path.join(PROJECT_ROOT, "orchestrator", "app.py")
    )
    orch_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch_mod)

    # Mock Docker client
    mock_container = MagicMock()
    mock_container.short_id = "abc12345"
    mock_docker = MagicMock()
    mock_docker.containers.run.return_value = mock_container
    orch_mod._docker = mock_docker
    orch_mod._docker_ok = True
    # Clear active containers state
    orch_mod._active.clear()

    try:
        with orch_mod.app.test_client() as client:
            resp = client.post("/spawn", json={
                "node_id": "node_test_01",
                "node_type": "web_server",
                "callback_url": "http://backend:8000",
                "canary_url": ""
            })
            data = resp.get_json()
            ok = resp.status_code == 200 and data.get("container_id") == "abc12345"
            _record("2. /spawn (valid) returns container_id", ok, f"body={data}")
    except Exception as e:
        _record("2. /spawn (valid) returns container_id", False, str(e))


# ---------------------------------------------------------------------------
# Test 3: Spawn with invalid image
# ---------------------------------------------------------------------------
def test_spawn_invalid_image():
    """Spawn with unknown node_type is rejected with 400."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "orch_app3",
        os.path.join(PROJECT_ROOT, "orchestrator", "app.py")
    )
    orch_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch_mod)
    orch_mod._active.clear()

    try:
        with orch_mod.app.test_client() as client:
            resp = client.post("/spawn", json={
                "node_id": "node_evil",
                "node_type": "malicious_image_not_in_whitelist",
                "callback_url": "http://backend:8000",
                "canary_url": ""
            })
            data = resp.get_json()
            ok = resp.status_code == 400 and "not allowed" in data.get("error", "").lower()
            _record("3. /spawn (invalid) returns 400", ok, f"status={resp.status_code} body={data}")
    except Exception as e:
        _record("3. /spawn (invalid) returns 400", False, str(e))


# ---------------------------------------------------------------------------
# Test 4: Teardown single container
# ---------------------------------------------------------------------------
def test_teardown_single():
    """DELETE /teardown/<node_id> removes a tracked container."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "orch_app4",
        os.path.join(PROJECT_ROOT, "orchestrator", "app.py")
    )
    orch_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch_mod)
    
    # Pre-populate active registry
    orch_mod._active["node_del_01"] = "cid_deadbeef"
    
    mock_container = MagicMock()
    mock_docker = MagicMock()
    mock_docker.containers.get.return_value = mock_container
    orch_mod._docker = mock_docker
    orch_mod._docker_ok = True

    try:
        with orch_mod.app.test_client() as client:
            resp = client.delete("/teardown/node_del_01")
            data = resp.get_json()
            ok = resp.status_code == 200 and data.get("status") == "stopped"
            _record("4. /teardown/<node_id> stops container", ok, f"body={data}")
    except Exception as e:
        _record("4. /teardown/<node_id> stops container", False, str(e))


# ---------------------------------------------------------------------------
# Test 5: Teardown-all
# ---------------------------------------------------------------------------
def test_teardown_all():
    """DELETE /teardown-all clears all tracked containers."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "orch_app5",
        os.path.join(PROJECT_ROOT, "orchestrator", "app.py")
    )
    orch_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch_mod)
    
    orch_mod._active["node_a"] = "cid_001"
    orch_mod._active["node_b"] = "cid_002"

    mock_container = MagicMock()
    mock_docker = MagicMock()
    mock_docker.containers.get.return_value = mock_container
    orch_mod._docker = mock_docker
    orch_mod._docker_ok = True

    try:
        with orch_mod.app.test_client() as client:
            resp = client.delete("/teardown-all")
            data = resp.get_json()
            ok = resp.status_code == 200 and data.get("stopped") == 2
            _record("5. /teardown-all stops all containers", ok, f"body={data}")
    except Exception as e:
        _record("5. /teardown-all stops all containers", False, str(e))


# ---------------------------------------------------------------------------
# Test 6: Backend ↔ Orchestrator via httpx (integration mock)
# ---------------------------------------------------------------------------
def test_backend_orchestrator_integration():
    """Backend spawn_container calls the orchestrator via httpx (no Docker SDK)."""
    from backend.deception import container_manager
    from backend.models import NetworkNode

    # Verify docker.from_env is NOT imported anywhere in the module
    module_source = open(
        os.path.join(PROJECT_ROOT, "backend", "deception", "container_manager.py")
    ).read()

    no_docker_sdk = "docker.from_env()" not in module_source
    uses_httpx = "import httpx" in module_source or "httpx" in module_source
    _record("6a. container_manager does NOT use docker.from_env()", no_docker_sdk)
    _record("6b. container_manager uses httpx", uses_httpx)

    # Mock httpx response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"container_id": "cid_mocked123"}

    async def run():
        node = NetworkNode(
            node_id="node_x",
            node_type="web_server",
            ip="172.20.0.10",
            ports=[80],
            banner="Apache/2.4.41",
            os="Ubuntu 20.04"
        )
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_cls.return_value.__aenter__.return_value = mock_client
            result = await container_manager.spawn_container(node)
            called = mock_client.post.called
            return result, called

    try:
        result, was_called = asyncio.run(run())
        ok = result == "cid_mocked123" and was_called
        _record("6c. spawn_container calls orchestrator /spawn via httpx", ok, f"result={result}")
    except Exception as e:
        _record("6c. spawn_container calls orchestrator /spawn via httpx", False, str(e))


# ---------------------------------------------------------------------------
# Test 7: Docker unavailable scenario
# ---------------------------------------------------------------------------
def test_docker_unavailable():
    """When orchestrator cannot reach Docker, /spawn returns 503 and backend returns None."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "orch_app7",
        os.path.join(PROJECT_ROOT, "orchestrator", "app.py")
    )
    orch_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch_mod)
    orch_mod._docker = None
    orch_mod._docker_ok = False
    orch_mod._active.clear()

    try:
        with orch_mod.app.test_client() as client:
            resp = client.post("/spawn", json={
                "node_id": "node_no_docker",
                "node_type": "web_server",
                "callback_url": "http://backend:8000",
                "canary_url": ""
            })
            data = resp.get_json()
            ok = resp.status_code == 503 and "unavailable" in data.get("error", "").lower()
            _record("7. Orchestrator returns 503 when Docker unavailable", ok, f"status={resp.status_code} body={data}")
    except Exception as e:
        _record("7. Orchestrator returns 503 when Docker unavailable", False, str(e))


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def _summary():
    total  = len(_results)
    passed = sum(1 for _, ok in _results if ok)
    failed = total - passed
    print("\n" + "=" * 60)
    print(f"Total: {total} | PASS: {passed} | FAIL: {failed}")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("═══ TASK 9.5 — Orchestrator Test Suite ═══")
    print("═" * 60)

    test_health_endpoint()
    test_spawn_valid()
    test_spawn_invalid_image()
    test_teardown_single()
    test_teardown_all()
    test_backend_orchestrator_integration()
    test_docker_unavailable()

    sys.exit(_summary())
