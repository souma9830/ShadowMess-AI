# TASK 4.6 — Canary Token System

## Overview

Task 4.6 implements the **Canary Token Management System** for the ShadowMesh deception platform. Canary tokens are fake URLs planted inside honeypot service responses. When an attacker visits one, a silent alert fires — the attacker receives a convincing 403 page and never knows they triggered detection.

---

## Files Created / Modified

| File | Status | Purpose |
|---|---|---|
| `backend/deception/canary.py` | **NEW** | `CanaryManager` class + `canary_manager` singleton |
| `backend/api/routes.py` | **MODIFIED** | Added `GET /api/canary/{token_id}` route |
| `backend/deception/container_manager.py` | **MODIFIED** | Pre-generates tokens before container spawn; injects `CANARY_WIKI_URL` env var |
| `docker/fake-http/server.py` | **MODIFIED** | `GET /api/users` appends `internal_wiki_url` from env |
| `docker/fake-api/server.py` | **MODIFIED** | `GET /v1/employees` appends `note_url` from env |
| `tests/test_canary.py` | **NEW** | 18-assertion verification suite |
| `docs/TASK_4_6.md` | **NEW** | This document |

---

## Architecture

```
  ┌──────────────────────────────────────────────────────┐
  │  backend/deception/canary.py                         │
  │                                                      │
  │  CanaryManager                                       │
  │   generate_for_node(node_id, count=2)                │
  │     → picks 'document' + 'url' token types           │
  │     → stores token_id → CanaryToken                  │
  │     → returns list[CanaryToken]                      │
  │                                                      │
  │   get_token(token_id)   → CanaryToken | None         │
  │   mark_triggered(id, ip) → sets triggered/time/ip    │
  │   get_all_for_node(id)  → list[CanaryToken]          │
  └──────────────────────────────────────────────────────┘
           │ token_url = /api/canary/{token_id}
           ▼
  ┌──────────────────────────────────────────────────────┐
  │  GET /api/canary/{token_id}  (routes.py)             │
  │                                                      │
  │  1. Lookup token → 404 if missing                    │
  │  2. Resolve attacker IP (X-Forwarded-For / client)   │
  │  3. mark_triggered()                                 │
  │  4. Emit CANARY_TRIGGERED via Socket.IO              │
  │  5. Log AttackerAction (canary_trigger)              │
  │  6. Fire Slack alert (background, try/except)        │
  │  7. Return HTTP 403 fake HTML                        │
  └──────────────────────────────────────────────────────┘
           │ planted via CANARY_WIKI_URL env var
           ▼
  ┌──────────────────────────────────────────────────────┐
  │  docker/fake-http  GET /api/users                    │
  │   → each employee record includes internal_wiki_url  │
  │                                                      │
  │  docker/fake-api   GET /v1/employees                 │
  │   → each employee record includes note_url           │
  └──────────────────────────────────────────────────────┘
```

---

## Token Lifecycle

1. **Generation**: `spawn_topology()` calls `canary_manager.generate_for_node(node_id)` before spawning each container. The `url`-type token URL is passed as `CANARY_WIKI_URL` env var to the container.
2. **Planting**: Fake HTTP and API honeypots read `CANARY_WIKI_URL` and embed it in employee/user listings.
3. **Triggering**: Attacker visits the URL. FastAPI route fires.
4. **Alerting**: Socket.IO `CANARY_TRIGGERED` event + Slack alert + `AttackerAction` log.
5. **Response**: Attacker receives HTTP 403 HTML — no indication an alert fired.
6. **Deduplication**: `mark_triggered` is a no-op if `token.triggered` is already `True`.

---

## Token Types

| Type | Label | Planted In |
|---|---|---|
| `document` | `Q3_Financial_Report.pdf` | fake file server (future) |
| `url` | `Internal Wiki — Credentials Page` | fake-http `/api/users`, fake-api `/v1/employees` |

---

## Route Behavior

### `GET /api/canary/{token_id}`

| Condition | Response |
|---|---|
| Unknown `token_id` | HTTP 404 |
| Valid token | HTTP 403 `<html><body>403 Forbidden — Access Denied</body></html>` |

Alert pipeline runs regardless of whether the token was previously triggered (idempotent response, but `mark_triggered` only records the first access).

---

## Alert Flow

```
Attacker hits /api/canary/{token_id}
  → mark_triggered(token_id, attacker_ip)
  → sio.emit('canary_triggered', { token_id, label, node_id, triggered_by_ip })
  → asyncio.create_task(attacker_action(...))   # MITRE tagging + profiling pipeline
  → asyncio.create_task(slack.alert_canary_triggered(...))
  → return HTTP 403
```

All background tasks are fire-and-forget. The attacker's HTTP response is never delayed.

---

## Container Integration

`spawn_topology()` in `container_manager.py`:

```python
cred_manager.generate_for_node(node.node_id)
tokens = canary_manager.generate_for_node(node.node_id)
wiki_token = next((t for t in tokens if t.token_type == "url"), None)
canary_url = wiki_token.token_url if wiki_token else ""
cid = await spawn_container(node, canary_url=canary_url)
```

The `CANARY_WIKI_URL` env var is injected into the container at spawn time so the honeypot services can embed it in their responses without any runtime API calls.

---

## Testing

```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python tests\test_canary.py
```

### Expected Output

```
  [PASS] 1. generate_for_node returns 2 tokens
  [PASS] 2. Token IDs are unique
  [PASS] 3. token_url format correct (url)
  [PASS] 3. token_url format correct (document)
  [PASS] 4. get_token returns correct token
  [PASS] 4b. get_token returns None for unknown id
  [PASS] 5. mark_triggered sets triggered=True
  [PASS] 5b. triggered_by_ip stored
  [PASS] 5c. triggered_at is a float
  [PASS] 6. Duplicate trigger does not overwrite triggered_by_ip
  [PASS] 6b. Duplicate trigger does not overwrite triggered_at
  [PASS] 7. get_all_for_node returns only matching node tokens
  [PASS] 7b. All returned tokens belong to node_A
  [PASS] 8. Route returns 404 for unknown token
  [PASS] 9. Route returns 403 for valid token
  [PASS] 9b. Response body contains 'Forbidden'
  [PASS] 10. CANARY_TRIGGERED event emitted
  [PASS] 11. Route still returns 403 when Slack alert fails

============================================================
Total: 18 | PASS: 18 | FAIL: 0
============================================================
```

---

## Failure Scenarios

| Scenario | Behavior |
|---|---|
| Unknown `token_id` | HTTP 404 — no alert fired |
| Socket.IO disconnected | `try/except` swallows error; route completes normally |
| Slack webhook down | Background task fails silently; route unaffected |
| Token triggered twice | Second `mark_triggered` is a no-op; first IP/time preserved |
| `CANARY_WIKI_URL` not set | Honeypot omits the field from responses; no crash |
