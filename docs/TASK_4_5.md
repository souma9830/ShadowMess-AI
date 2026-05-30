# TASK 4.5 — Credential Management System

## Overview

Task 4.5 implements the **Fake Credential Management System** (`backend/deception/credentials.py`) and its associated API integration. This system dynamically generates highly realistic decoy credentials (AWS keys, database passwords, SSH keys, `.env` files) and binds them to specific deception nodes. 

When an attacker discovers and attempts to download or use one of these credentials, the system immediately flags the access, correlates the attacker's IP, and broadcasts a high-fidelity `CREDENTIAL_STOLEN` event.

---

## Files Modified / Created

| File | Status | Purpose |
|---|---|---|
| `backend/deception/credentials.py` | **NEW** | Contains credential templates and the `CredentialManager` |
| `backend/api/routes.py` | **MODIFIED** | Added `GET /api/creds/{node_id}/{cred_id}` endpoint and pipeline integration |
| `tests/test_credentials.py` | **NEW** | Automated pytest suite for generation, tracking, and API download |
| `docs/TASK_4_5.md` | **NEW** | Architectural documentation and workflow (this file) |

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │  backend/deception/credentials.py                       │
  │                                                         │
  │  ┌──────────────────────┐   ┌────────────────────────┐  │
  │  │ CREDENTIAL_TEMPLATES │   │ CredentialManager      │  │
  │  │ - env_file           │   │ - generate_for_node()  │  │
  │  │ - aws_key            │◄──┤ - get_credential()     │  │
  │  │ - ssh_key            │   │ - mark_accessed()      │  │
  │  │ - db_password        │   │ - get_all_for_node()   │  │
  │  └──────────────────────┘   └────────────────────────┘  │
  └────────────────────────┬────────────────────────────────┘
                           │
                           ▼
  ┌─────────────────────────────────────────────────────────┐
  │  backend/api/routes.py                                  │
  │                                                         │
  │  GET /api/creds/{node_id}/{cred_id}                     │
  │  1. Lookup credential in CredentialManager              │
  │  2. Mark as accessed                                    │
  │  3. Emit CREDENTIAL_STOLEN to Socket.IO                 │
  │  4. Log 'credential_theft' via AttackerAction           │
  │  5. Trigger Slack alert (if available)                  │
  │  6. Return application/octet-stream payload             │
  └─────────────────────────────────────────────────────────┘
```

---

## Credential Lifecycle

1. **Generation**: When a topology node (e.g. `web_server`) is instantiated or a lure is spawned, `cred_manager.generate_for_node(node_id)` is called.
2. **Selection**: The manager randomly selects exactly 2 distinct credential types from the templates.
3. **Tracking**: Each credential is given a unique `uuid4` and stored in the manager's internal dictionary mapping `cred_id -> FakeCredential`.
4. **Planting**: (Future tasks) Decoy services like the fake HTTP server or SSH honeypot will read `get_all_for_node()` to list these credential URLs inside their mock filesystems or directory listings.
5. **Theft**: The attacker accesses `GET /api/creds/{node_id}/{cred_id}`.
6. **Alerting**: The system records the timestamp (`accessed_at`), updates the internal state (`accessed=True`), and fires background telemetry into Neo4j and Socket.IO.

---

## API Route

### `GET /api/creds/{node_id}/{cred_id}`

**Behavior**:
- Verifies that the `cred_id` exists and belongs to the given `node_id`.
- If invalid, returns `HTTP 404 Credential not found`.
- Marks the credential accessed and logs an `AttackerAction` (`action_type="credential_theft"`).
- Emits a Socket.IO `CREDENTIAL_STOLEN` payload.
- Returns the fake credential content natively as an `application/octet-stream` download.

---

## Socket.IO Events

When a credential is stolen, the backend emits:

```json
{
  "event": "CREDENTIAL_STOLEN",
  "payload": {
    "cred_id": "c62b9...-...",
    "filename": "credentials.csv",
    "cred_type": "aws_key",
    "attacker_ip": "192.168.1.100"
  }
}
```

---

## Testing Steps

Run the automated `pytest` suite locally to verify the generation, tracking, and API download lifecycle:

```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python -m pytest tests\test_credentials.py
```

### Expected Outputs

```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.3, pluggy-1.6.0
rootdir: C:\Users\SOUMADEEP\OneDrive\Desktop\shadowmess\ShadowMess-AI
plugins: anyio-4.13.0
collected 3 items

tests\test_credentials.py ...                                            [100%]
======================== 3 passed, 1 warning in 14.47s ========================
```

The 3 passed test suites cover:
1. `test_credential_generation`: Random selection, exact length requirements, type verification.
2. `test_access_marking`: Correct timestamp updates on `mark_accessed()`.
3. `test_download_route`: Simulates the `GET` endpoint, HTTP 200 payload verification, and `action_type="credential_theft"` logging.

---

## Failure Handling

- **Invalid Credential Request**: If an attacker attempts to download a credential using an invalid `node_id` or `cred_id`, the endpoint immediately terminates with an `HTTP 404` to prevent information disclosure.
- **Alert Service Downtime**: If Socket.IO or Slack is unavailable, the `try/except` wrappers ensure the attacker still receives the payload instantly, so the honeypot never drops character or breaks the illusion.
- **Telemetry Offloading**: The heavy processing required for MITRE mapping, profiling, and Neo4j injection runs in a decoupled background `asyncio.create_task()` pipeline. The attacker's HTTP request completes immediately.
