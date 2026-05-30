"""
test_container_manager.py — Task 4.3 Verification Suite
========================================================
Tests for backend/deception/container_manager.py.

All Docker SDK interactions are mocked so the suite runs
without a live Docker daemon.

Covers:
  1. Docker unavailable handling (no crash, returns None)
  2. Spawn success (container created, registered)
  3. Spawn failure (exception handled, returns None)
  4. Topology deployment (teardown → spawn all → emit events)
  5. Teardown cleanup (all containers stopped, registry cleared)
  6. active_containers tracking accuracy

Usage:
    python tests/test_container_manager.py
"""

import os
import sys
import asyncio
import importlib
from unittest.mock import patch, MagicMock, AsyncMock

# Ensure project root is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.models import NetworkNode, TopologySnapshot

# Terminal styles
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
_results = []


def _record(test_id: str, passed: bool, detail: str = "") -> None:
    _results.append((test_id, passed, detail))
    status = PASS if passed else FAIL
    print(f"  {status} {test_id}" + (f" — {detail}" if detail else ""))


def _make_node(node_id="node_0_1", node_type="web_server", ip="172.20.0.6"):
    return NetworkNode(
        node_id=node_id,
        ip=ip,
        node_type=node_type,
        ports=[80, 443],
        banner="Apache/2.4.41",
        os="Ubuntu 20.04",
        is_fake=True,
        container_id=None,
    )


def _make_topology(num_nodes=3):
    nodes = []
    types = ["web_server", "db_server", "auth_service"]
    for i in range(num_nodes):
        nodes.append(_make_node(
            node_id=f"node_0_{i}",
            node_type=types[i % len(types)],
            ip=f"172.20.0.{6 + i}",
        ))
    edges = [(f"node_0_{i}", f"node_0_{(i+1) % num_nodes}") for i in range(num_nodes)]
    return TopologySnapshot(nodes=nodes, edges=edges, generation=0)


# ---------------------------------------------------------------------------
# Test 1: Docker unavailable handling
# ---------------------------------------------------------------------------
def test_docker_unavailable():
    """When Docker is not available, spawn_container returns None without crashing."""
    # Re-import with docker unavailable
    import backend.deception.container_manager as cm

    # Force unavailable state
    original_available = cm._docker_available
    original_client = cm._docker_client
    cm._docker_available = False
    cm._docker_client = None

    try:
        node = _make_node()
        result = asyncio.run(cm.spawn_container(node))
        ok = result is None
        _record("1. Docker unavailable returns None (no crash)", ok, f"result={result}")
    except Exception as e:
        _record("1. Docker unavailable returns None (no crash)", False, str(e))
    finally:
        cm._docker_available = original_available
        cm._docker_client = original_client


# ---------------------------------------------------------------------------
# Test 2: Spawn success
# ---------------------------------------------------------------------------
def test_spawn_success():
    """When Docker is available, spawn creates container and registers it."""
    import backend.deception.container_manager as cm

    mock_container = MagicMock()
    mock_container.short_id = "abc123def456"

    mock_client = MagicMock()
    mock_client.containers.run.return_value = mock_container

    original_available = cm._docker_available
    original_client = cm._docker_client
    cm._docker_available = True
    cm._docker_client = mock_client
    cm.active_containers.clear()

    try:
        node = _make_node()
        result = asyncio.run(cm.spawn_container(node))

        ok = result == "abc123def456"
        registered = cm.active_containers.get("node_0_1") == "abc123def456"
        _record("2. Spawn success (container created & registered)", ok and registered,
                f"cid={result} | registered={registered}")
    except Exception as e:
        _record("2. Spawn success (container created & registered)", False, str(e))
    finally:
        cm._docker_available = original_available
        cm._docker_client = original_client
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 3: Spawn failure
# ---------------------------------------------------------------------------
def test_spawn_failure():
    """When Docker run throws, spawn returns None and does not crash."""
    import backend.deception.container_manager as cm

    mock_client = MagicMock()
    mock_client.containers.run.side_effect = Exception("Docker engine error: image not found")

    original_available = cm._docker_available
    original_client = cm._docker_client
    cm._docker_available = True
    cm._docker_client = mock_client
    cm.active_containers.clear()

    try:
        node = _make_node()
        result = asyncio.run(cm.spawn_container(node))

        ok = result is None
        not_registered = "node_0_1" not in cm.active_containers
        _record("3. Spawn failure handled gracefully", ok and not_registered,
                f"result={result} | not_registered={not_registered}")
    except Exception as e:
        _record("3. Spawn failure handled gracefully", False, str(e))
    finally:
        cm._docker_available = original_available
        cm._docker_client = original_client
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 4: Topology deployment
# ---------------------------------------------------------------------------
def test_topology_deployment():
    """spawn_topology tears down, spawns all nodes, emits events."""
    import backend.deception.container_manager as cm

    counter = {"value": 0}

    mock_container = MagicMock()
    def _mock_run(**kwargs):
        counter["value"] += 1
        c = MagicMock()
        c.short_id = f"cid_{counter['value']:03d}"
        return c

    mock_client = MagicMock()
    mock_client.containers.run.side_effect = _mock_run
    mock_client.containers.get.side_effect = Exception("not found")

    original_available = cm._docker_available
    original_client = cm._docker_client
    cm._docker_available = True
    cm._docker_client = mock_client
    cm.active_containers.clear()

    # Mock Socket.IO
    mock_sio = MagicMock()
    mock_sio.emit = AsyncMock()

    try:
        topology = _make_topology(num_nodes=3)
        asyncio.run(cm.spawn_topology(topology, mock_sio))

        # Check all nodes got container IDs
        all_have_cid = all(n.container_id is not None for n in topology.nodes)
        # Check active_containers has all 3
        tracking_ok = len(cm.active_containers) == 3
        # Check sio.emit was called 3 times
        emit_count = mock_sio.emit.call_count
        emit_ok = emit_count == 3

        ok = all_have_cid and tracking_ok and emit_ok
        _record("4. Topology deployment (teardown → spawn → emit)", ok,
                f"cids_assigned={all_have_cid} | tracked={len(cm.active_containers)} | emits={emit_count}")
    except Exception as e:
        _record("4. Topology deployment (teardown → spawn → emit)", False, str(e))
    finally:
        cm._docker_available = original_available
        cm._docker_client = original_client
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 5: Teardown cleanup
# ---------------------------------------------------------------------------
def test_teardown_cleanup():
    """teardown_all stops containers and clears registry."""
    import backend.deception.container_manager as cm

    mock_container_obj = MagicMock()
    mock_container_obj.stop.return_value = None

    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container_obj

    original_available = cm._docker_available
    original_client = cm._docker_client
    cm._docker_available = True
    cm._docker_client = mock_client

    # Pre-populate active containers
    cm.active_containers = {
        "node_0_0": "cid_aaa",
        "node_0_1": "cid_bbb",
        "node_0_2": "cid_ccc",
    }

    try:
        asyncio.run(cm.teardown_all())

        ok = len(cm.active_containers) == 0
        stop_called = mock_container_obj.stop.call_count == 3
        _record("5. Teardown cleanup (all stopped & cleared)", ok and stop_called,
                f"remaining={len(cm.active_containers)} | stops={mock_container_obj.stop.call_count}")
    except Exception as e:
        _record("5. Teardown cleanup (all stopped & cleared)", False, str(e))
    finally:
        cm._docker_available = original_available
        cm._docker_client = original_client
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 6: active_containers tracking accuracy
# ---------------------------------------------------------------------------
def test_active_containers_tracking():
    """active_containers accurately reflects spawn/teardown state."""
    import backend.deception.container_manager as cm

    mock_container = MagicMock()
    mock_container.short_id = "track_001"

    mock_client = MagicMock()
    mock_client.containers.run.return_value = mock_container
    mock_client.containers.get.return_value = mock_container
    mock_container.stop.return_value = None

    original_available = cm._docker_available
    original_client = cm._docker_client
    cm._docker_available = True
    cm._docker_client = mock_client
    cm.active_containers.clear()

    try:
        # Spawn a node
        node = _make_node()
        asyncio.run(cm.spawn_container(node))
        after_spawn = len(cm.active_containers)

        # Teardown
        asyncio.run(cm.teardown_all())
        after_teardown = len(cm.active_containers)

        ok = after_spawn == 1 and after_teardown == 0
        _record("6. active_containers tracking accuracy", ok,
                f"after_spawn={after_spawn} | after_teardown={after_teardown}")
    except Exception as e:
        _record("6. active_containers tracking accuracy", False, str(e))
    finally:
        cm._docker_available = original_available
        cm._docker_client = original_client
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def _print_summary():
    total = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = total - passed
    print("\n" + "=" * 60)
    print(f"Total: {total} | PASS: {passed} | FAIL: {failed}")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("═══ TASK 4.3 — Container Manager Verification Suite ═══")
    print("═" * 60)

    test_docker_unavailable()
    test_spawn_success()
    test_spawn_failure()
    test_topology_deployment()
    test_teardown_cleanup()
    test_active_containers_tracking()

    sys.exit(_print_summary())
