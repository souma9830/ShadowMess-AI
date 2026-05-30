# TASK 4.2B — Fake Database Honeypot

## Overview

Task 4.2B implements a production-grade **Flask-based Database honeypot** container
for the ShadowMesh deception platform. Running on port `3306` inside the container,
it simulates a standard web-accessible administrative panel (e.g. phpMyAdmin) managing
an internal MySQL server. It simulates LDAP/AD validation latency (400ms) on `/login`,
provides realistic database schemas and custom payroll dumps, overrides response headers to
expose standard custom software signatures, and asynchronously logs attacker metrics in
background threads.

---

## Files Created

| File | Purpose |
|---|---|
| `docker/fake-db/server.py` | Full Database honeypot implementation (Flask) |
| `docker/fake-db/Dockerfile` | Container build definition |
| `scripts/test_fake_db.py` | Automated testing and verification suite |
| `docs/TASK_4_2B.md` | This architectural and operational manual |

---

## Architecture

```
Attacker Client
       │
       │  TCP :3306
       ▼
┌──────────────────────────────────────────────┐
│  docker/fake-db/server.py                    │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Flask App Engine (Port 3306)           │  │
│  │  Interceptors:                         │  │
│  │   - Server: nginx/1.14.0               │  │
│  │   - X-Database-Engine: MySQL/8.0.28    │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Routes & Simulators                    │  │
│  │  /           ➔ phpMyAdmin Login page   │  │
│  │  /login      ➔ Simulate auth delay     │  │
│  │                (400ms) ➔ HTTP 401      │  │
│  │  /tables     ➔ 5 Database tables list  │  │
│  │  /dump       ➔ 10 payroll records      │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  _fire_callback_async()                      │──► POST /api/attacker/action
│   (Daemon thread, non-blocking telemetry)    │    (every request / login / dump)
└──────────────────────────────────────────────┘
```

### Key Architectural Standards

1. **phpMyAdmin Visual Masking (`GET /`)**: Serves an authentic-looking, premium-style CSS-rendered phpMyAdmin login dashboard. The input fields are fully active and dispatch JSON payloads asynchronously using a modern Javascript `fetch()` API block.
2. **Standard Authentication Latency simulation (`POST /login`)**: On credential submission, the honeypot pauses for exactly `400ms` prior to returning an `HTTP 401 Access denied` payload. This mocks active credential hash checks or AD server delays to keep scanners engaged.
3. **Decoupled Telemetry Pipeline**: Communication to the core backend FastAPI logging engine (`POST /api/attacker/action`) is run asynchronously using independent daemon threads. Attacker UI response times are completely unaffected by core system loads.
4. **Werkzeug Header Cleanup**: Patches Werkzeug's internal `WSGIRequestHandler.send_header` during development runtimes to discard redundant empty header elements, keeping response outputs exactly formatted to spec.

---

## API Routes

### 1. `GET /`
Serves a realistic phpMyAdmin Administration dashboard login page containing visual elements, language boxes, server descriptions, and form integrations.

### 2. `POST /login`
Accepts a JSON username/password credential load, blocks execution for `400ms`, and always rejects with:
- **HTTP Code**: `401 Unauthorized`
- **Response**:
```json
{
  "error": "Access denied"
}
```

### 3. `GET /tables`
Exposes fake target tables schema to attackers scan sweeps:
```json
[
  "users",
  "transactions",
  "employee_payroll",
  "audit_log",
  "customer_pii"
]
```

### 4. `GET /dump`
Returns 10 detailed payroll rows mimicking stolen company details:
```json
[
  {
    "employee_id": "EMP-9401",
    "name": "Alice Smith",
    "department": "Executive",
    "salary": 185000
  },
  ...
]
```

---

## Response Headers

To present a convincing decoy web layer, all outgoing traffic includes:
- `Server: nginx/1.14.0`
- `X-Database-Engine: MySQL/8.0.28`

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `fake-db-node` | Injected by orchestrator — identifies this node |
| `ATTACKER_CALLBACK_URL` | `http://backend:8000` | Target backend webhook base url |
| `DB_PORT` | `3306` | Internal port bound inside the honeypot container |

---

## Telemetry Callback Schema

Fires a `POST` request to `{ATTACKER_CALLBACK_URL}/api/attacker/action` with:
```json
{
  "attacker_ip": "172.20.0.1",
  "action_type": "data_access",
  "target_node_id": "fake-db-node",
  "detail": "Database access — GET /tables",
  "timestamp": 1717064234.812
}
```
*Note: `action_type` defaults to `login_attempt` for all incoming traffic to `/login`.*

---

## How to Run Locally (without Docker)

Install dependencies in your active environment:
```powershell
pip install flask requests
```

Launch the mock database interface on a local port (e.g. `8081`):
```powershell
$env:DB_PORT = "8081"
$env:NODE_ID = "local-db-test"
$env:ATTACKER_CALLBACK_URL = "http://localhost:8000"
python docker/fake-db/server.py
```

Access using `curl`:
- `curl -I http://localhost:8081/tables` (to verify headers)
- `curl http://localhost:8081/dump` (to retrieve payroll records)

---

## How to Run with Docker

### Build the Image
```bash
docker build -t shadowmesh-fake-db ./docker/fake-db
```

### Run Container Standalone
```bash
docker run --rm -it \
  -p 3306:3306 \
  -e NODE_ID=prod-mysql-panel \
  -e ATTACKER_CALLBACK_URL=http://host.docker.internal:8000 \
  shadowmesh-fake-db
```

---

## Test Procedure

Execute the automated test suite locally to verify full compliance:
```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python scripts/test_fake_db.py
```

---

## Expected Output

```
════════════════════════════════════════════════════════════
═══ TASK 4.2B — Fake Database Honeypot Verification Suite ═══
════════════════════════════════════════════════════════════
  [PASS] T4.2B.1 GET / matches phpMyAdmin specifications
  [PASS] T4.2B.2 POST /login returns 401 with 400ms delay
  [PASS] T4.2B.3 GET /tables returns correct database schemas
  [PASS] T4.2B.4 GET /dump returns 10 detailed payroll rows
  [PASS] T4.2B.5 Header banners correctly mimic custom server
  [PASS] T4.2B.6 Callback dispatches telemetry successfully

============================================================
Total: 6 | PASS: 6 | FAIL: 0
============================================================
```
