# TASK 9.5 — Orchestrator Security Layer

## Overview

Task 9.5 eliminates the most critical security vulnerability in the pre-9.5 architecture: the Docker socket (`/var/run/docker.sock`) was mounted directly into the backend container. Any Remote Code Execution in the backend would have granted an attacker full Docker daemon control.

The solution introduces a dedicated **Orchestrator** microservice as a security boundary. It is the **sole** service with access to the Docker socket. The backend communicates with the orchestrator exclusively via HTTP (httpx), never touching the socket directly.

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Before Task 9.5 (INSECURE)                                  │
  │                                                              │
  │  backend ──docker.sock──► Docker daemon                      │
  │  RCE in backend = full host-level Docker control             │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  After Task 9.5 (SECURE)                                     │
  │                                                              │
  │  backend ──httpx──► orchestrator ──docker.sock──► Docker     │
  │  RCE in backend = only HTTP calls to a tightly               │
  │  controlled whitelist-enforced API                           │
  └──────────────────────────────────────────────────────────────┘
```

---

## Files Created / Modified

| File | Status | Purpose |
|---|---|---|
| `orchestrator/app.py` | **NEW** | Flask API orchestrator with ALLOWED_IMAGES whitelist |
| `orchestrator/Dockerfile` | **NEW** | Minimal Python 3.11-slim image running as non-root |
| `backend/deception/container_manager.py` | **REWRITTEN** | All Docker calls replaced with httpx calls to orchestrator |
| `docker-compose.yml` | **MODIFIED** | Orchestrator service added; Docker socket removed from backend |
| `.env.example` | **MODIFIED** | ORCHESTRATOR_URL documented |
| `tests/test_orchestrator.py` | **NEW** | 9-assertion verification suite |
| `docs/TASK_9_5.md` | **NEW** | This file |

---

## Orchestrator API Reference

### `GET /health`
Returns orchestrator and Docker daemon status.

```json
{
  "status": "ok",
  "docker": "connected",
  "active_containers": 3
}
```

### `POST /spawn`
Spawns a honeypot container. Image must be in the `ALLOWED_IMAGES` whitelist.

**Request:**
```json
{
  "node_id":      "node_0_1",
  "node_type":    "web_server",
  "callback_url": "http://172.17.0.1:8000",
  "canary_url":   "/api/canary/abc-123"
}
```

**Response (200):**
```json
{ "container_id": "a1b2c3d4" }
```

**Response (400 — invalid image):**
```json
{ "error": "node_type 'unknown' not allowed" }
```

**Response (503 — Docker unavailable):**
```json
{ "error": "Docker daemon unavailable" }
```

### `DELETE /teardown/<node_id>`
Stops and removes the container for a specific node.

### `DELETE /teardown-all`
Stops and removes all tracked containers.

```json
{ "status": "ok", "stopped": 5 }
```

---

## Security Controls

| Control | Implementation |
|---|---|
| **ALLOWED_IMAGES whitelist** | `ALLOWED_IMAGES` set — any image not in the set is rejected with 400 |
| **Input sanitization** | `node_id` validated against `^[a-zA-Z0-9_-]{1,64}$` before use as container `name=` or `hostname=` |
| **read_only filesystem** | `read_only=True` passed to `containers.run()` |
| **tmpfs restriction** | `tmpfs={"/tmp": "size=16m,mode=1777"}` — only /tmp is writable |
| **no-new-privileges** | `security_opt=["no-new-privileges:true"]` |
| **cap_drop ALL** | `cap_drop=["ALL"]` |
| **Non-root orchestrator process** | Dockerfile: `USER orchestrator` (UID 1001) |
| **Docker socket isolation** | Socket only in orchestrator container, removed from backend |
| **Resource limits** | 64 MB RAM, 25% CPU per honeypot container |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ORCHESTRATOR_URL` | `http://localhost:9000` | Backend → Orchestrator URL |
| `HONEYPOT_CALLBACK_URL` | `http://host.docker.internal:8000` | Injected into honeypot containers |
| `DECEPTION_NETWORK` | `shadowmesh_deception_net` | Docker network for honeypots |

---

## Running Locally (Development)

### Start the Orchestrator standalone
```bash
cd orchestrator
pip install flask docker gunicorn
python app.py
# Listening on http://localhost:9000
```

### Run with Docker Compose
```bash
docker compose up --build orchestrator backend
```

---

## Testing

```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python tests/test_orchestrator.py
```

### Expected Output
```
════════════════════════════════════════════════════════════
═══ TASK 9.5 — Orchestrator Test Suite ═══
════════════════════════════════════════════════════════════
  [PASS] 1. /health returns status=ok
  [PASS] 2. /spawn (valid) returns container_id
  [PASS] 3. /spawn (invalid) returns 400
  [PASS] 4. /teardown/<node_id> stops container
  [PASS] 5. /teardown-all stops all containers
  [PASS] 6a. container_manager does NOT use docker.from_env()
  [PASS] 6b. container_manager uses httpx
  [PASS] 6c. spawn_container calls orchestrator /spawn via httpx
  [PASS] 7. Orchestrator returns 503 when Docker unavailable
============================================================
Total: 9 | PASS: 9 | FAIL: 0
============================================================
```

---

## Failure Handling

| Scenario | Behavior |
|---|---|
| Orchestrator unreachable | `spawn_container()` returns `None` → topology deploys but container skipped |
| Docker daemon unavailable | Orchestrator returns `503` → backend receives `None` → graceful no-op |
| Invalid image requested | Orchestrator returns `400` → backend logs error, returns `None` |
| Duplicate `node_id` | Orchestrator returns existing `container_id` with `reused: true` |
| Container already gone at teardown | Exception caught, registry entry still cleared |
