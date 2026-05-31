"""
test_container_manager.py — Container Manager Verification Suite
================================================================
Tests for backend/deception/container_manager.py.

The container_manager now delegates ALL Docker operations to the orchestrator
via HTTP (httpx). Tests mock _orchestrator_request instead of a Docker client.

Covers:
  1. Orchestrator unavailable — spawn returns None without crashing
  2. Spawn success — container registered, returns container_id
  3. Spawn failure — orchestrator error response handled gracefully
  4. Topology deployment — teardown → spawn all → emit events
  5. Teardown cleanup — registry cleared, orchestrator called
  6. active_containers tracking accuracy

Usage:
    python tests/test_container_manager.py
"""

import os
import sys
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.models import NetworkNode, TopologySnapshot

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
# Test 1: Orchestrator unavailable
# ---------------------------------------------------------------------------
def test_docker_unavailable():
    """When orchestrator is unreachable, spawn_container returns None without crashing."""
    import backend.deception.container_manager as cm
    cm.active_containers.clear()

    async def _run():
        with patch.object(cm, '_orchestrator_request', new=AsyncMock(return_value=None)):
            node = _make_node()
            return await cm.spawn_container(node)

    try:
        result = asyncio.run(_run())
        ok = result is None
        _record("1. Orchestrator unavailable returns None (no crash)", ok, f"result={result}")
    except Exception as e:
        _record("1. Orchestrator unavailable returns None (no crash)", False, str(e))
    finally:
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 2: Spawn success
# ---------------------------------------------------------------------------
def test_spawn_success():
    """When orchestrator returns a container_id, spawn registers it and returns it."""
    import backend.deception.container_manager as cm
    cm.active_containers.clear()

    async def _run():
        with patch.object(cm, '_orchestrator_request',
                          new=AsyncMock(return_value={"container_id": "abc123def456"})):
            node = _make_node()
            return await cm.spawn_container(node)

    try:
        result = asyncio.run(_run())
        ok = result == "abc123def456"
        registered = cm.active_containers.get("node_0_1") == "abc123def456"
        _record("2. Spawn success (container created & registered)", ok and registered,
                f"cid={result} | registered={registered}")
    except Exception as e:
        _record("2. Spawn success (container created & registered)", False, str(e))
    finally:
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 3: Spawn failure (orchestrator returns error)
# ---------------------------------------------------------------------------
def test_spawn_failure():
    """When orchestrator returns an error dict, spawn returns None and does not crash."""
    import backend.deception.container_manager as cm
    cm.active_containers.clear()

    async def _run():
        with patch.object(cm, '_orchestrator_request',
                          new=AsyncMock(return_value={"error": "image not found"})):
            node = _make_node()
            return await cm.spawn_container(node)

    try:
        result = asyncio.run(_run())
        ok = result is None
        not_registered = "node_0_1" not in cm.active_containers
        _record("3. Spawn failure handled gracefully", ok and not_registered,
                f"result={result} | not_registered={not_registered}")
    except Exception as e:
        _record("3. Spawn failure handled gracefully", False, str(e))
    finally:
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 4: Topology deployment
# ---------------------------------------------------------------------------
def test_topology_deployment():
    """spawn_topology tears down, spawns all tier-1 nodes, emits events."""
    import backend.deception.container_manager as cm
    cm.active_containers.clear()

    counter = {"value": 0}

    async def _mock_orchestrator(method, path, **kwargs):
        if method == "delete":
            return {"stopped": 0}
        counter["value"] += 1
        return {"container_id": f"cid_{counter['value']:03d}"}

    mock_sio = MagicMock()
    mock_sio.emit = AsyncMock()

    async def _run():
        with patch.object(cm, '_orchestrator_request', side_effect=_mock_orchestrator):
            topology = _make_topology(num_nodes=3)
            await cm.spawn_topology(topology, mock_sio)
            return topology

    try:
        topology = asyncio.run(_run())
        tier1_nodes = [n for n in topology.nodes if n.tier != "tier2"]
        all_have_cid = all(n.container_id is not None for n in tier1_nodes)
        tracking_ok = len(cm.active_containers) == len(tier1_nodes)
        emit_count = mock_sio.emit.call_count
        emit_ok = emit_count >= len(tier1_nodes)

        ok = all_have_cid and tracking_ok and emit_ok
        _record("4. Topology deployment (teardown → spawn → emit)", ok,
                f"cids_assigned={all_have_cid} | tracked={len(cm.active_containers)} | emits={emit_count}")
    except Exception as e:
        _record("4. Topology deployment (teardown → spawn → emit)", False, str(e))
    finally:
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 5: Teardown cleanup
# ---------------------------------------------------------------------------
def test_teardown_cleanup():
    """teardown_all clears registry and calls orchestrator."""
    import backend.deception.container_manager as cm

    cm.active_containers.clear()
    cm.active_containers.update({
        "node_0_0": "cid_aaa",
        "node_0_1": "cid_bbb",
        "node_0_2": "cid_ccc",
    })

    async def _run():
        with patch.object(cm, '_orchestrator_request',
                          new=AsyncMock(return_value={"stopped": 3})):
            await cm.teardown_all()

    try:
        asyncio.run(_run())
        ok = len(cm.active_containers) == 0
        _record("5. Teardown cleanup (registry cleared)", ok,
                f"remaining={len(cm.active_containers)}")
    except Exception as e:
        _record("5. Teardown cleanup (registry cleared)", False, str(e))
    finally:
        cm.active_containers.clear()


# ---------------------------------------------------------------------------
# Test 6: active_containers tracking accuracy
# ---------------------------------------------------------------------------
def test_active_containers_tracking():
    """active_containers accurately reflects spawn/teardown state."""
    import backend.deception.container_manager as cm
    cm.active_containers.clear()

    async def _run():
        with patch.object(cm, '_orchestrator_request',
                          new=AsyncMock(return_value={"container_id": "track_001"})):
            node = _make_node()
            await cm.spawn_container(node)
            after_spawn = len(cm.active_containers)

        with patch.object(cm, '_orchestrator_request',
                          new=AsyncMock(return_value={"stopped": 1})):
            await cm.teardown_all()
            after_teardown = len(cm.active_containers)

        return after_spawn, after_teardown

    try:
        after_spawn, after_teardown = asyncio.run(_run())
        ok = after_spawn == 1 and after_teardown == 0
        _record("6. active_containers tracking accuracy", ok,
                f"after_spawn={after_spawn} | after_teardown={after_teardown}")
    except Exception as e:
        _record("6. active_containers tracking accuracy", False, str(e))
    finally:
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
    print("═══ Container Manager Verification Suite ═══")
    print("═" * 60)

    test_docker_unavailable()
    test_spawn_success()
    test_spawn_failure()
    test_topology_deployment()
    test_teardown_cleanup()
    test_active_containers_tracking()

    sys.exit(_print_summary())
