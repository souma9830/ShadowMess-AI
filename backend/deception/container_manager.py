"""
ShadowMesh — Task 4.3: Container Manager
=========================================
Production-grade container lifecycle manager for the ShadowMesh deception platform.

Responsibilities:
  - Spawns honeypot Docker containers from topology nodes
  - Maps node_type → pre-built honeypot Docker images
  - Enforces strict resource limits (64 MB RAM, 25% CPU)
  - Drops all Linux capabilities and blocks privilege escalation
  - Tracks active containers via an in-memory registry
  - Tears down all active containers on topology mutation
  - Emits Socket.IO events on container lifecycle changes
  - Handles Docker daemon unavailability gracefully (no crash)

Docker images used (must be pre-built):
  shadowmesh-fake-http   — Task 4.2A
  shadowmesh-fake-db     — Task 4.2B
  shadowmesh-fake-api    — Task 4.2C
  shadowmesh-fake-auth   — Task 4.2D
  shadowmesh-fake-ssh    — Task 4.1
"""

import asyncio
import logging
from typing import Dict, Optional

from backend.models import NetworkNode, TopologySnapshot

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("container_manager")

# ---------------------------------------------------------------------------
# Docker SDK — imported lazily and guarded against absence
# ---------------------------------------------------------------------------
_docker_client = None
_docker_available = False

try:
    import docker
    _docker_client = docker.from_env()
    # Quick connectivity probe — does not raise if the daemon socket exists
    _docker_client.ping()
    _docker_available = True
    log.info("[container_manager] Docker daemon connected successfully.")
except Exception as exc:
    log.warning(
        "[container_manager] Docker is NOT available (%s). "
        "Container operations will be no-ops until Docker is reachable.",
        exc,
    )

# ---------------------------------------------------------------------------
# Image Mapping — node_type → Docker image name
# ---------------------------------------------------------------------------
CONTAINER_IMAGES: Dict[str, str] = {
    "web_server":   "shadowmesh-fake-http",
    "db_server":    "shadowmesh-fake-db",
    "auth_service": "shadowmesh-fake-auth",
    "file_server":  "shadowmesh-fake-http",
    "api_gateway":  "shadowmesh-fake-api",
    "mail_server":  "shadowmesh-fake-http",
    "workstation":  "shadowmesh-fake-http",
}

# Docker network all honeypots will be attached to
DOCKER_NETWORK = "shadowmesh_deception_net"

# ---------------------------------------------------------------------------
# State Tracking — node_id → container_id
# ---------------------------------------------------------------------------
active_containers: Dict[str, str] = {}


# ---------------------------------------------------------------------------
# Function 1: spawn_container
# ---------------------------------------------------------------------------
async def spawn_container(node: NetworkNode) -> Optional[str]:
    """
    Spawn a single honeypot container for the given topology node.

    Steps:
      1. Resolve Docker image from node.node_type via CONTAINER_IMAGES.
      2. Launch container with enforced resource limits, security hardening,
         and the required environment variables (NODE_ID, ATTACKER_CALLBACK_URL).
      3. Register the container in the active_containers registry.
      4. Return the container ID, or None on any failure.
    """
    global _docker_client, _docker_available

    if not _docker_available or _docker_client is None:
        log.warning(
            "[spawn] Docker unavailable — skipping spawn for node %s",
            node.node_id,
        )
        return None

    image = CONTAINER_IMAGES.get(node.node_type)
    if image is None:
        log.error(
            "[spawn] Unknown node_type '%s' for node %s — no image mapping",
            node.node_type,
            node.node_id,
        )
        return None

    # Derive a short suffix from the node_id for the hostname
    suffix = node.node_id.replace("node_", "").replace("_", "")
    hostname = f"fake-{node.node_type.replace('_', '-')}-{suffix}"
    container_name = f"sm_{node.node_id}"

    try:
        container = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: _docker_client.containers.run(
                image=image,
                detach=True,
                remove=True,
                name=container_name,
                hostname=hostname,
                network=DOCKER_NETWORK,
                environment={
                    "NODE_ID": node.node_id,
                    "ATTACKER_CALLBACK_URL": "http://host.docker.internal:8000",
                },
                mem_limit="64m",
                cpu_period=100000,
                cpu_quota=25000,
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
            ),
        )

        cid = container.short_id
        active_containers[node.node_id] = cid
        log.info(
            "[spawn] ✓ %s (%s) → container %s [%s]",
            node.node_id,
            node.node_type,
            cid,
            image,
        )
        return cid

    except Exception as exc:
        log.error(
            "[spawn] ✗ Failed to spawn container for node %s (%s): %s",
            node.node_id,
            node.node_type,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Function 2: teardown_all
# ---------------------------------------------------------------------------
async def teardown_all() -> None:
    """
    Stop and remove every container tracked in active_containers.

    - Uses a 2-second stop timeout.
    - Ignores individual stop failures (container may already be gone).
    - Clears the active_containers registry after sweep.
    """
    global _docker_client, _docker_available

    if not active_containers:
        log.info("[teardown] No active containers to tear down.")
        return

    log.info(
        "[teardown] Tearing down %d active container(s): %s",
        len(active_containers),
        list(active_containers.keys()),
    )

    for node_id, cid in list(active_containers.items()):
        try:
            if _docker_available and _docker_client is not None:
                container = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda cid=cid: _docker_client.containers.get(cid),
                )
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda c=container: c.stop(timeout=2),
                )
            log.info("[teardown] Stopped container %s (node %s)", cid, node_id)
        except Exception as exc:
            log.warning(
                "[teardown] Could not stop container %s (node %s): %s",
                cid,
                node_id,
                exc,
            )

    active_containers.clear()
    log.info("[teardown] All containers cleared.")


# ---------------------------------------------------------------------------
# Function 3: spawn_topology
# ---------------------------------------------------------------------------
async def spawn_topology(topology: TopologySnapshot, sio) -> None:
    """
    Deploy a full deception topology.

    Steps:
      1. Tear down all previously active containers.
      2. Iterate over topology.nodes and spawn a container for each.
      3. Stamp the container_id back onto the topology node.
      4. Emit a 'container_spawned' Socket.IO event for each success.
      5. Continue even if individual containers fail.
    """
    log.info(
        "[topology] Deploying topology generation %d (%d nodes)",
        topology.generation,
        len(topology.nodes),
    )

    # Step 1 — clean slate
    await teardown_all()

    # Step 2 & 3 — spawn each node
    for node in topology.nodes:
        cid = await spawn_container(node)

        if cid:
            node.container_id = cid

        # Step 4 — emit Socket.IO event
        if sio is not None:
            try:
                await sio.emit("container_spawned", {
                    "node_id": node.node_id,
                    "node_type": node.node_type,
                })
            except Exception as exc:
                log.warning(
                    "[topology] Socket.IO emit failed for node %s: %s",
                    node.node_id,
                    exc,
                )

    spawned = sum(1 for n in topology.nodes if n.container_id)
    log.info(
        "[topology] Deployment complete — %d/%d containers active.",
        spawned,
        len(topology.nodes),
    )
