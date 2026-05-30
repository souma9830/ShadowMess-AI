"""
ShadowMesh - Task 9.5: Container Manager (Orchestrator Edition)
================================================================
The backend NO LONGER touches Docker directly.
All container lifecycle operations are delegated to the orchestrator
service via HTTP (httpx), which is the sole holder of the Docker socket.

Architecture:
  backend  --httpx-->  orchestrator --docker.sock-->  Docker daemon

Environment variables:
  ORCHESTRATOR_URL        URL of the orchestrator service (default: http://localhost:9000)
  HONEYPOT_CALLBACK_URL   Injected into each honeypot container as ATTACKER_CALLBACK_URL
"""

import asyncio
import logging
import os
from typing import Dict, Optional

import httpx

from backend.events import EVENTS
from backend.models import NetworkNode, TopologySnapshot
from backend.deception.credentials import cred_manager
from backend.deception.canary import canary_manager

log = logging.getLogger("container_manager")

ORCHESTRATOR_URL      = os.getenv("ORCHESTRATOR_URL", "http://localhost:9000")
HONEYPOT_CALLBACK_URL = os.getenv("HONEYPOT_CALLBACK_URL", "http://host.docker.internal:8000")

# node_id -> container_id tracking (in-process)
active_containers: Dict[str, str] = {}

# HTTP client timeout: 30 s to allow slow image pulls
_TIMEOUT = httpx.Timeout(30.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _orchestrator_request(method: str, path: str, **kwargs) -> Optional[dict]:
    """
    Fire a single request to the orchestrator and return parsed JSON, or
    None if the orchestrator is unreachable / returns an error.
    Never raises -- always returns None on any failure.

    Fix #18: Returns None for both network errors AND 4xx/5xx responses;
    callers should log context before discarding None.
    """
    url = f"{ORCHESTRATOR_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await getattr(client, method)(url, **kwargs)
        if resp.status_code < 400:
            return resp.json()
        log.error("[orchestrator] %s %s -> %d: %s",
                  method.upper(), url, resp.status_code, resp.text[:200])
        return None
    except httpx.ConnectError:
        log.error("[orchestrator] Unreachable at %s -- is the orchestrator running?", ORCHESTRATOR_URL)
        return None
    except Exception as exc:
        log.error("[orchestrator] Request failed (%s %s): %s", method.upper(), url, exc)
        return None


# ---------------------------------------------------------------------------
# Function 1: spawn_container
# ---------------------------------------------------------------------------

async def spawn_container(node: NetworkNode, canary_url: str = "") -> Optional[str]:
    """
    Ask the orchestrator to spawn a honeypot container for `node`.
    Returns the container short ID on success, or None on any failure.
    """
    result = await _orchestrator_request(
        "post",
        "/spawn",
        json={
            "node_id":      node.node_id,
            "node_type":    node.node_type,
            "callback_url": HONEYPOT_CALLBACK_URL,
            "canary_url":   canary_url,
        },
    )

    if result is None:
        log.warning("[spawn] Orchestrator returned no result for node %s", node.node_id)
        return None

    if "error" in result:
        log.error("[spawn] Orchestrator rejected node %s: %s", node.node_id, result["error"])
        return None

    cid = result.get("container_id")
    if cid:
        active_containers[node.node_id] = cid
        log.info("[spawn] OK %s (%s) -> container %s", node.node_id, node.node_type, cid)
    return cid


# ---------------------------------------------------------------------------
# Function 2: teardown_container
# ---------------------------------------------------------------------------

async def teardown_container(node_id: str) -> bool:
    """
    Ask the orchestrator to stop and remove the container for `node_id`.
    Clears the local registry entry regardless of whether the orchestrator
    call succeeds (container may already be gone).
    Returns True if the orchestrator confirmed the stop.
    """
    # Clean up local state first so callers never see stale entries
    active_containers.pop(node_id, None)
    cred_manager.clear_for_node(node_id)
    canary_manager.clear_for_node(node_id)

    result = await _orchestrator_request("delete", f"/teardown/{node_id}")
    if result is None:
        log.warning("[teardown] Orchestrator did not confirm teardown for %s", node_id)
        return False

    log.info("[teardown] Confirmed: %s", result)
    return True


# ---------------------------------------------------------------------------
# Function 3: teardown_all
# ---------------------------------------------------------------------------

async def teardown_all() -> None:
    """
    Ask the orchestrator to stop ALL containers, then clear local state.
    """
    if not active_containers:
        log.info("[teardown_all] No active containers to tear down.")
        return

    log.info("[teardown_all] Tearing down %d container(s): %s",
             len(active_containers), list(active_containers.keys()))

    # Clear local state -- even if orchestrator fails we don't want stale refs
    for node_id in list(active_containers.keys()):
        cred_manager.clear_for_node(node_id)
        canary_manager.clear_for_node(node_id)
    active_containers.clear()

    result = await _orchestrator_request("delete", "/teardown-all")
    if result:
        log.info("[teardown_all] Orchestrator stopped %d container(s).", result.get("stopped", "?"))
    else:
        log.warning("[teardown_all] Orchestrator did not confirm teardown -- containers may still be running.")


# ---------------------------------------------------------------------------
# Function 4: spawn_topology
# ---------------------------------------------------------------------------

async def spawn_topology(topology: TopologySnapshot, sio) -> None:
    """
    Deploy a full deception topology.

    Steps:
      1. Tear down all previously active containers via orchestrator.
      2. Iterate topology.nodes and spawn a container for each.
      3. Stamp the returned container_id back onto the node.
      4. Emit a CONTAINER_SPAWNED Socket.IO event for each attempt.
      5. Continue even if individual containers fail.

    Fix #3: Credentials and canary tokens are generated AFTER a successful
    spawn and cleaned up immediately on failure.
    """
    log.info("[topology] Deploying generation %d (%d nodes)",
             topology.generation, len(topology.nodes))

    # Step 1 -- clean slate
    await teardown_all()

    # Steps 2, 3, 4
    for node in topology.nodes:
        # Fix #3: Generate credentials and canary tokens before spawn so the
        # canary URL can be injected into the container environment.
        # If spawn fails we clean them up immediately below.
        cred_manager.generate_for_node(node.node_id)
        tokens = canary_manager.generate_for_node(node.node_id)
        wiki_token = next((t for t in tokens if t.token_type == "url"), None)
        canary_url = wiki_token.token_url if wiki_token else ""

        cid = await spawn_container(node, canary_url=canary_url)
        if cid:
            node.container_id = cid
        else:
            # Spawn failed -- clean up orphaned credentials and canary tokens immediately
            cred_manager.clear_for_node(node.node_id)
            canary_manager.clear_for_node(node.node_id)

        # Emit regardless of success so the frontend always gets a node event
        # Fix #16: Use EVENTS constant instead of the bare 'container_spawned' literal
        if sio is not None:
            try:
                await sio.emit(EVENTS['CONTAINER_SPAWNED'], {
                    "node_id":      node.node_id,
                    "node_type":    node.node_type,
                    "container_id": node.container_id,
                })
            except Exception as exc:
                log.warning("[topology] Socket.IO emit failed for %s: %s", node.node_id, exc)

    spawned = sum(1 for n in topology.nodes if n.container_id)
    log.info("[topology] Deployment complete -- %d/%d containers active.",
             spawned, len(topology.nodes))
