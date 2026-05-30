# TASK 4.4 — Neo4j Integration & Health Monitoring

## Overview

Task 4.4 integrates health checking, dynamic status tracking, and automated idempotent seeding into the ShadowMesh enterprise attack graph database (Neo4j) and backend service lifecycle.

It establishes:
1. A robust **Neo4j Health Check** which dynamically updates the application's connection status (`_neo4j_available`).
2. An **Idempotent Seed Pipeline** that automatically populates the graph database on initial startup only, preventing duplicates.
3. A **Graceful Lifespan Startup** sequence in FastAPI that guarantees startup will *never* block or crash even if the Neo4j database is completely offline.
4. An **Exception-Proof Health Endpoint (`GET /health`)** providing complete system telemetry (Neo4j status, MITRE ATT&CK status, active honeypot container counts).

---

## Files Modified / Created

| File | Status | Purpose |
|---|---|---|
| `backend/database/neo4j_client.py` | **MODIFIED** | Added robust health checking and idempotent demo seeding |
| `backend/main.py` | **MODIFIED** | Configured lifespan startup to verify health and run seeding, and updated `/health` endpoint to be exception-proof |
| `tests/test_health.py` | **NEW** | 7-assertion unit verification suite for health check, seeding, and telemetry |
| `docs/TASK_4_4.md` | **NEW** | Architectural and operational documentation (this file) |

---

## Architecture

```
                       ┌────────────────────────┐
                       │  FastAPI Lifespan      │
                       └───────────┬────────────┘
                                   │
                    1. init_schema() (Try/Except)
                                   │
                                   ▼
                    2. health_check() (Try/Except)
                                   │
                  ┌────────────────┴────────────────┐
                  ▼                                 ▼
             [ HEALTHY ]                      [ UNHEALTHY ]
                  │                                 │
         3. seed_demo_data()                        │
         Check Node count = 0                       │
                  │                                 │
         ┌────────┴────────┐                        │
         ▼                 ▼                        │
    [ COUNT = 0 ]    [ COUNT > 0 ]                  │
    Seed 1 Attacker,    Return                      │
     1 Node, 1 Rel    (No-op)                       │
                  │                                 │
                  ▼                                 ▼
         Log: "Neo4j connected"          Log: "Neo4j connection failed"
```

---

## Neo4j Health Check Flow

The `health_check()` function is executed inside `backend/database/neo4j_client.py`.
It runs a minimal Cypher transaction:

```cypher
RETURN 1 AS n
```

- If successful, it sets the module's global state flag `_neo4j_available = True` and returns `True`.
- If any exception is thrown, it catches it, sets `_neo4j_available = False`, and returns `False`.
- It is fully non-blocking and safe to run in active loops or request pipelines.

---

## Seed Data Design

The `seed_demo_data()` function is triggered only if:
1. `health_check()` returned `True`.
2. The current `Node` count in the Neo4j database is strictly `0`.

To prevent any duplicate creation when restarted or run in multi-threaded contexts, the query utilizes Cypher's `MERGE` clause:

```cypher
MERGE (a:Attacker {ip: '192.168.1.100'})
MERGE (n:Node {node_id: 'node_demo', node_type: 'web_server'})
MERGE (a)-[r:PERFORMED {action_type: 'port_scan'}]->(n)
ON CREATE SET r.timestamp = $timestamp
```

This enforces absolute idempotency:
- The node and relationship are only created once.
- The relationship properties (like `timestamp`) are only set on the initial creation.

---

## Health Endpoint Structure

`GET /health` is served by FastAPI. It gathers telemetry from the three core components of ShadowMesh:
1. **Neo4j Status** (via `health_check()`)
2. **MITRE ATT&CK Mapper Status** (via `mitre_mapper._is_initialized`)
3. **Active Honeypot Containers Count** (via `len(active_containers)`)

### Telemetry Payload Schema

```json
{
  "status": "ok",
  "neo4j": true,
  "mitre_loaded": true,
  "active_containers": 0
}
```

### Exception Proofing
Every step is wrapped in isolated `try-except` blocks. If any component is offline or failing, the endpoint will catch the exception, substitute safe fallbacks (e.g. `False` or `0`), and return a valid `HTTP 200` JSON response.

---

## Local and Docker Testing

### 1. Verification Suite (Local Mode)
To run the mock-based unit tests verify that all health checking and seeding flows behave exactly as specified:

```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python tests\test_health.py
```

### Expected Output
```
════════════════════════════════════════════════════════════
═══ TASK 4.4 — Neo4j & API Health Verification Suite ═══
════════════════════════════════════════════════════════════
  [PASS] 1. Neo4j healthy check returns True — result=True
  [PASS] 2. Neo4j unavailable check returns False — result=False
  [PASS] 3. Seed data insertion executed — calls=2
  [PASS] 4. Seed data duplicate prevention (skips insert) — calls=1
  [PASS] 5. Health endpoint response status & neo4j matches — response={'status': 'ok', 'neo4j': True, 'mitre_loaded': True, 'active_containers': 1}
  [PASS] 6. MITRE status included in health check — loaded_true=True | loaded_false=False
  [PASS] 7. Active container count included in health check — count_0=0 | count_3=3

============================================================
Total: 7 | PASS: 7 | FAIL: 0
============================================================
```

### 2. Integration / Docker Testing
If running with a real live Neo4j service (via `docker compose`):
1. Start the services:
   ```bash
   docker compose up -d neo4j backend
   ```
2. Verify application logs:
   - If Neo4j is online, logs will output: `INFO:backend:Neo4j connected`.
   - If Neo4j is offline or still booting up, logs will output: `ERROR:backend:Neo4j connection failed`.
3. Check the HTTP telemetry:
   ```bash
   curl http://localhost:8000/health
   ```
   If Neo4j is ready and healthy, `neo4j` will be `true`. If not, it will gracefully be `false`.
