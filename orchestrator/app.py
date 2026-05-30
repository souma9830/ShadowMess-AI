"""
orchestrator/app.py
====================
ShadowMesh Orchestrator — Task 9.5
Docker socket gatekeeper service.

Exposes a minimal Flask API that the backend calls via HTTP (httpx).
This process is the ONLY service with access to /var/run/docker.sock.
The backend never touches Docker directly.

Routes:
  GET  /health                   — liveness check
  POST /spawn                    — spawn a single honeypot container
  DELETE /teardown/<node_id>     — stop and remove one container
  DELETE /teardown-all           — stop and remove all active containers
"""

import os
import re
import logging
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("orchestrator")

# ---------------------------------------------------------------------------
# ALLOWED_IMAGES whitelist — the ONLY images the orchestrator will ever spawn.
# Requests for any other image are rejected with 400.
# ---------------------------------------------------------------------------
ALLOWED_IMAGES = {
    "shadowmesh-fake-http",
    "shadowmesh-fake-db",
    "shadowmesh-fake-api",
    "shadowmesh-fake-auth",
    "shadowmesh-fake-ssh",
}

# node_type -> Docker image (mirrors container_manager.py mapping)
IMAGE_MAP = {
    "web_server":   "shadowmesh-fake-http",
    "db_server":    "shadowmesh-fake-db",
    "auth_service": "shadowmesh-fake-auth",
    "file_server":  "shadowmesh-fake-http",
    "api_gateway":  "shadowmesh-fake-api",
    "mail_server":  "shadowmesh-fake-http",
    "workstation":  "shadowmesh-fake-http",
}

DOCKER_NETWORK = os.getenv("DECEPTION_NETWORK", "shadowmesh_deception_net")
# node_id -> container_id registry (in-process; orchestrator is single-instance)
_active: dict[str, str] = {}

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
_SAFE_ID_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')

def _safe_id(value: str) -> bool:
    """Return True only if value is safe for use as Docker name/hostname."""
    return bool(_SAFE_ID_RE.match(value or ""))

# ---------------------------------------------------------------------------
# Docker client — lazily initialised with graceful fallback
# ---------------------------------------------------------------------------
_docker = None
_docker_ok = False

def _get_docker():
    global _docker, _docker_ok
    if _docker_ok and _docker is not None:
        return _docker
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        client.ping()
        _docker = client
        _docker_ok = True
        log.info("[orchestrator] Docker daemon connected.")
        return _docker
    except Exception as exc:
        log.warning("[orchestrator] Docker unavailable: %s", exc)
        _docker_ok = False
        _docker = None
        return None

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    client = _get_docker()
    return jsonify({
        "status": "ok",
        "docker": "connected" if client else "unavailable",
        "active_containers": len(_active),
    })


@app.post("/spawn")
def spawn():
    """
    Expected JSON body:
      {
        "node_id":      "node_0_1",
        "node_type":    "web_server",
        "callback_url": "http://172.17.0.1:8000",
        "canary_url":   ""
      }
    """
    data = request.get_json(force=True, silent=True) or {}
    node_id      = data.get("node_id", "")
    node_type    = data.get("node_type", "")
    callback_url = data.get("callback_url", "")
    canary_url   = data.get("canary_url", "")

    # -- Validate node_id ---------------------------------------------------
    if not _safe_id(node_id):
        return jsonify({"error": "Invalid node_id — alphanumeric, _ and - only"}), 400

    # -- Resolve image from whitelist ----------------------------------------
    image = IMAGE_MAP.get(node_type)
    if image is None:
        return jsonify({"error": f"node_type '{node_type}' not allowed"}), 400
    if image not in ALLOWED_IMAGES:
        # Defensive double-check — IMAGE_MAP values must always be in ALLOWED_IMAGES
        return jsonify({"error": f"image '{image}' not in ALLOWED_IMAGES whitelist"}), 400

    # -- Duplicate detection (Fix #11) --------------------------------------
    # Verify the cached container is actually still running before returning
    # the stale ID.  If it's dead, clear the registry and spawn fresh.
    if node_id in _active:
        cached_cid = _active[node_id]
        client_check = _get_docker()
        if client_check:
            try:
                existing = client_check.containers.get(cached_cid)
                if existing.status == "running":
                    log.info("[spawn] node_id '%s' reusing live container %s", node_id, cached_cid)
                    return jsonify({"container_id": cached_cid, "reused": True})
                else:
                    log.warning("[spawn] Cached container %s for '%s' is '%s' — evicting and re-spawning",
                                cached_cid, node_id, existing.status)
            except Exception:
                log.warning("[spawn] Cached container %s for '%s' no longer exists — evicting",
                            cached_cid, node_id)
        _active.pop(node_id, None)

    # -- Docker availability ------------------------------------------------
    client = _get_docker()
    if client is None:
        return jsonify({"error": "Docker daemon unavailable"}), 503

    # -- Derive safe hostname -----------------------------------------------
    suffix = re.sub(r'[^a-z0-9]', '', node_id.lower().replace("node_", ""))[:12]
    hostname = f"fake-{node_type.replace('_', '-')}-{suffix}"
    container_name = f"sm_{node_id}"

    try:
        container = client.containers.run(
            image=image,
            detach=True,
            remove=True,
            name=container_name,
            hostname=hostname,
            network=DOCKER_NETWORK,
            environment={
                "NODE_ID":               node_id,
                "ATTACKER_CALLBACK_URL": callback_url,
                "CANARY_WIKI_URL":       canary_url,
            },
            mem_limit="64m",
            cpu_period=100_000,
            cpu_quota=25_000,
            security_opt=["no-new-privileges:true"],
            cap_drop=["ALL"],
            read_only=True,
            tmpfs={"/tmp": "size=16m,mode=1777"},
        )
        cid = container.short_id
        _active[node_id] = cid
        log.info("[spawn] OK %s (%s) -> %s [%s]", node_id, node_type, cid, image)
        return jsonify({"container_id": cid})

    except Exception as exc:
        log.error("[spawn] FAIL %s: %s", node_id, exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/teardown/<node_id>", methods=["DELETE"])
def teardown_one(node_id):
    if not _safe_id(node_id):
        return jsonify({"error": "Invalid node_id"}), 400

    cid = _active.pop(node_id, None)
    if cid is None:
        return jsonify({"status": "not_found", "node_id": node_id}), 404

    client = _get_docker()
    if client:
        try:
            c = client.containers.get(cid)
            c.stop(timeout=2)
            log.info("[teardown] Stopped %s (node %s)", cid, node_id)
        except Exception as exc:
            log.warning("[teardown] Could not stop %s: %s", cid, exc)

    return jsonify({"status": "stopped", "node_id": node_id, "container_id": cid})


@app.route("/teardown-all", methods=["DELETE"])
def teardown_all():
    if not _active:
        return jsonify({"status": "ok", "stopped": 0})

    stopped = 0
    client = _get_docker()
    for node_id, cid in list(_active.items()):
        if client:
            try:
                c = client.containers.get(cid)
                c.stop(timeout=2)
                stopped += 1
            except Exception as exc:
                log.warning("[teardown-all] Could not stop %s: %s", cid, exc)
        _active.pop(node_id, None)

    log.info("[teardown-all] Stopped %d containers.", stopped)
    return jsonify({"status": "ok", "stopped": stopped})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=False)
