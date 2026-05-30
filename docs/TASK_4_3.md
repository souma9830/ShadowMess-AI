# TASK 4.3 — Container Manager

## Overview

Task 4.3 implements the **production-grade Docker container lifecycle manager** for the ShadowMesh deception platform. This module (`backend/deception/container_manager.py`) is the bridge between the AI-generated topology graphs and the actual running honeypot containers.

It replaces the previous mock stub with full Docker SDK integration, enforcing strict resource limits, security hardening, and graceful failure handling.

---

## Files Created / Modified

| File | Purpose |
|---|---|
| `backend/deception/container_manager.py` | **MODIFIED** — Full Docker SDK lifecycle manager |
| `tests/test_container_manager.py` | **NEW** — 6-assertion mock-based test suite |
| `docs/TASK_4_3.md` | **NEW** — This architectural and operational manual |

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│  backend/deception/container_manager.py                │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Docker Client (docker.from_env())               │  │
│  │  • Lazy init, graceful fallback if unavailable   │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  CONTAINER_IMAGES Mapping                        │  │
│  │   web_server   → shadowmesh-fake-http            │  │
│  │   db_server    → shadowmesh-fake-db              │  │
│  │   auth_service → shadowmesh-fake-auth            │  │
│  │   file_server  → shadowmesh-fake-http            │  │
│  │   api_gateway  → shadowmesh-fake-api             │  │
│  │   mail_server  → shadowmesh-fake-http            │  │
│  │   workstation  → shadowmesh-fake-http            │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  active_containers: dict[str, str]               │  │
│  │   node_id → container_id                         │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  Functions:                                            │
│   spawn_container(node)     → create one container     │
│   teardown_all()            → stop all + clear state   │
│   spawn_topology(topo, sio) → full deploy cycle        │
└────────────────────────────────────────────────────────┘
         │                            │
         ▼                            ▼
   Docker Engine               Socket.IO Server
   (containers)                (container_spawned)
```

---

## Container Lifecycle

```
  spawn_topology() called
         │
         ▼
  teardown_all()  ◄── Stop all existing containers (timeout=2s)
         │              Clear active_containers dict
         ▼
  for each node in topology.nodes:
         │
         ├── spawn_container(node)
         │       │
         │       ├── Resolve image from CONTAINER_IMAGES
         │       ├── docker.containers.run(...)
         │       │     detach=True, remove=True
         │       │     mem_limit="64m"
         │       │     cpu_period=100000, cpu_quota=25000
         │       │     security_opt=["no-new-privileges:true"]
         │       │     cap_drop=["ALL"]
         │       │     network=shadowmesh_deception_net
         │       │     env: NODE_ID, ATTACKER_CALLBACK_URL
         │       ├── Register active_containers[node_id] = cid
         │       └── Return container short_id (or None on failure)
         │
         ├── Update node.container_id
         │
         └── sio.emit("container_spawned", {...})
```

---

## Docker Network Requirements

Before deploying containers, create the Docker network:

```bash
docker network create shadowmesh_deception_net
```

All honeypot containers will be attached to this bridge network, allowing inter-container communication and centralized traffic routing.

---

## Environment Variables (Injected Into Each Container)

| Variable | Value | Description |
|---|---|---|
| `NODE_ID` | `node_{gen}_{idx}` | Unique node identifier from the topology graph |
| `ATTACKER_CALLBACK_URL` | `http://host.docker.internal:8000` | Backend telemetry callback URL |

---

## Container Resource Limits

| Resource | Limit | Rationale |
|---|---|---|
| Memory | `64 MB` | Honeypots are lightweight Flask apps; prevents DoS |
| CPU Period | `100000 µs` | Standard Linux CFS scheduling period |
| CPU Quota | `25000 µs` | Limits each container to 25% of one CPU core |
| Capabilities | `ALL dropped` | Zero Linux capabilities for defense in depth |
| Privileges | `no-new-privileges` | Prevents privilege escalation inside container |

---

## How to Build Images

Before the container manager can spawn containers, all honeypot images must be pre-built:

```bash
# Task 4.1 — Fake SSH
docker build -t shadowmesh-fake-ssh ./docker/fake-ssh

# Task 4.2A — Fake HTTP
docker build -t shadowmesh-fake-http ./docker/fake-http

# Task 4.2B — Fake DB
docker build -t shadowmesh-fake-db ./docker/fake-db

# Task 4.2C — Fake API
docker build -t shadowmesh-fake-api ./docker/fake-api

# Task 4.2D — Fake Auth
docker build -t shadowmesh-fake-auth ./docker/fake-auth
```

---

## How to Run Locally

The container manager is imported and used by the FastAPI backend. It initializes automatically:

```python
from backend.deception.container_manager import spawn_topology, teardown_all

# Deploy a topology
await spawn_topology(topology_snapshot, sio_instance)

# Tear down
await teardown_all()
```

If Docker is not running locally, the module will log a warning and continue without crashing. All `spawn_container` calls will return `None`.

---

## How to Run With Docker Compose

A `docker-compose.yml` integrating the backend with all honeypot images would look like:

```yaml
version: "3.9"

networks:
  shadowmesh_deception_net:
    driver: bridge

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - shadowmesh_deception_net
```

> **Important**: The backend container needs access to `/var/run/docker.sock` so the Docker SDK can spawn sibling containers.

---

## Testing Procedure

Execute the automated test suite:
```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python tests\test_container_manager.py
```

All Docker SDK calls are mocked — no live Docker daemon is required to run the tests.

---

## Expected Output

```
════════════════════════════════════════════════════════════
═══ TASK 4.3 — Container Manager Verification Suite ═══
════════════════════════════════════════════════════════════
  [PASS] 1. Docker unavailable returns None (no crash)
  [PASS] 2. Spawn success (container created & registered)
  [PASS] 3. Spawn failure handled gracefully
  [PASS] 4. Topology deployment (teardown → spawn → emit)
  [PASS] 5. Teardown cleanup (all stopped & cleared)
  [PASS] 6. active_containers tracking accuracy

============================================================
Total: 6 | PASS: 6 | FAIL: 0
============================================================
```

---

## Failure Scenarios

| Scenario | Behavior |
|---|---|
| Docker daemon not running | Module initializes, logs warning. All spawns return `None`. No crash. |
| Docker image not found | `spawn_container` catches the exception, logs error, returns `None`. Topology deployment continues with remaining nodes. |
| Container fails to start | Same as image not found — logged and skipped. |
| Container already stopped during teardown | `teardown_all` catches the exception on `.stop()`, logs warning, continues to next container. Registry is still cleared. |
| Socket.IO disconnected | `spawn_topology` catches emit exception, logs warning, continues deployment. |
| Unknown `node_type` | `spawn_container` logs error (no image mapping), returns `None`. |
