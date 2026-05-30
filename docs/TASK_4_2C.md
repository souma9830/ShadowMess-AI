# TASK 4.2C — Fake API Honeypot

## Overview

Task 4.2C implements a production-grade **Flask-based API honeypot** container for the ShadowMesh deception platform. Running on port `8443` inside the container, it simulates an internal enterprise API gateway exposing multiple microservices. 

It provides endpoints that simulate internal organizational infrastructure, such as employee payroll data and service directories. It also exposes a simulated API token endpoint to detect credential theft attempts. All requests are logged asynchronously, with specific actions tagged as `credential_theft` to provide high-fidelity threat intelligence.

---

## Files Created

| File | Purpose |
|---|---|
| `docker/fake-api/server.py` | Full API honeypot implementation (Flask) |
| `docker/fake-api/Dockerfile` | Container build definition |
| `scripts/test_fake_api.py` | Automated testing and verification suite |
| `docs/TASK_4_2C.md` | This architectural and operational manual |

---

## Architecture

```
Attacker Client
       │
       │  TCP :8443
       ▼
┌──────────────────────────────────────────────┐
│  docker/fake-api/server.py                   │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Flask App Engine (Port 8443)           │  │
│  │  Interceptors:                         │  │
│  │   - Server: nginx/1.18.0               │  │
│  │   - X-API-Version: 3.1.4               │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Routes & Simulators                    │  │
│  │  /v1/health      ➔ API Status JSON     │  │
│  │  /v1/services    ➔ 6 Mock Microservices│  │
│  │  /v1/tokens      ➔ Fake API Key        │  │
│  │  /v1/employees   ➔ 15 Employee Records │  │
│  │  /v1/auth/token  ➔ Simulate auth delay │  │
│  │                    (300ms) ➔ HTTP 401  │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  _fire_callback_async()                      │──► POST /api/attacker/action
│   (Daemon thread, non-blocking telemetry)    │    (every request)
└──────────────────────────────────────────────┘
```

### Key Architectural Standards

1. **Simulated Microservice Gateway**: Mimics a standard API gateway by providing a directory of internal services (`/v1/services`) and exposing data endpoints (`/v1/employees`).
2. **High-Value Decoys (Canaries)**: Exposes `/v1/tokens` which provides a seemingly valid production API key (`sk-prod-...`). Accessing this endpoint triggers a critical `credential_theft` alert.
3. **Authentication Latency Simulation (`POST /v1/auth/token`)**: Blocks execution for exactly `300ms` prior to returning an `HTTP 401 unauthorized` payload. This mocks backend authentication provider delays.
4. **Decoupled Telemetry Pipeline**: Communication to the core backend FastAPI logging engine (`POST /api/attacker/action`) is run asynchronously using independent daemon threads. Attacker UI response times are completely unaffected by core system loads.
5. **Custom Header Injection**: Overrides default WSGI server headers to present an authentic proxy layer signature (`nginx/1.18.0`).

---

## API Routes

### 1. `GET /v1/health`
Returns gateway health status.
```json
{
  "status": "ok",
  "version": "3.1.4",
  "env": "production"
}
```

### 2. `GET /v1/services`
Exposes the internal service registry.
```json
[
  {"name": "employee-service", "endpoint": "/v1/employees"},
  {"name": "payroll-service", "endpoint": "/v1/payroll"},
  {"name": "billing-service", "endpoint": "/v1/billing"},
  {"name": "auth-service", "endpoint": "/v1/auth"},
  {"name": "reporting-service", "endpoint": "/v1/reports"},
  {"name": "customer-pii-service", "endpoint": "/v1/customers"}
]
```

### 3. `GET /v1/tokens`
**CRITICAL**: Triggers `credential_theft` telemetry event. Returns a mock production API key.
```json
{
  "api_key": "sk-prod-a7f3e829b4c5d6e7f8a9b0c1d2e3f4a5REDACTED",
  "expires": "2025-12-31"
}
```

### 4. `GET /v1/employees`
Returns 15 detailed employee records containing PII (SSNs).
```json
[
  {
    "employee_id": "EMP-9401",
    "name": "Alice Smith",
    "department": "Executive",
    "salary": 185000,
    "ssn": "XXX-XX-1234"
  },
  ...
]
```

### 5. `POST /v1/auth/token`
Accepts authentication payloads, blocks execution for `300ms`, and always rejects with:
- **HTTP Code**: `401 Unauthorized`
- **Response**:
```json
{
  "error": "unauthorized"
}
```

---

## Response Headers

To present a convincing proxy layer, all outgoing traffic includes:
- `Server: nginx/1.18.0`
- `X-API-Version: 3.1.4`

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `fake-api-node` | Injected by orchestrator — identifies this node |
| `ATTACKER_CALLBACK_URL` | `http://backend:8000` | Target backend webhook base url |
| `API_PORT` | `8443` | Internal port bound inside the honeypot container |

---

## Telemetry Callback Schema

Fires a `POST` request to `{ATTACKER_CALLBACK_URL}/api/attacker/action` with:
```json
{
  "attacker_ip": "172.20.0.1",
  "action_type": "data_access",
  "target_node_id": "fake-api-node",
  "detail": "API access — GET /v1/employees",
  "timestamp": 1717064234.812
}
```
*Note: `action_type` defaults to `data_access`, except for `/v1/tokens` which sends `credential_theft`, and `/v1/auth/token` which sends `login_attempt`.*

---

## How to Run Locally (without Docker)

Install dependencies in your active environment:
```powershell
pip install flask requests
```

Launch the mock API interface on a local port (e.g. `8443`):
```powershell
$env:API_PORT = "8443"
$env:NODE_ID = "local-api-test"
$env:ATTACKER_CALLBACK_URL = "http://localhost:8000"
python docker/fake-api/server.py
```

Access using `curl`:
- `curl -I http://localhost:8443/v1/health` (to verify headers)
- `curl http://localhost:8443/v1/employees` (to retrieve employee data)

---

## How to Run with Docker

### Build the Image
```bash
docker build -t shadowmesh-fake-api ./docker/fake-api
```

### Run Container Standalone
```bash
docker run --rm -it \
  -p 8443:8443 \
  -e NODE_ID=prod-api-gateway \
  -e ATTACKER_CALLBACK_URL=http://host.docker.internal:8000 \
  shadowmesh-fake-api
```

---

## Test Procedure

Execute the automated test suite locally to verify full compliance:
```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python scripts/test_fake_api.py
```

---

## Expected Output

```
════════════════════════════════════════════════════════════
═══ TASK 4.2C — Fake API Honeypot Verification Suite ═══
════════════════════════════════════════════════════════════
  [PASS] 1. GET /v1/health returns expected JSON
  [PASS] 2. GET /v1/services returns 6 fake services
  [PASS] 3. GET /v1/tokens returns expected JSON
  [PASS] 4. GET /v1/employees returns 15 fake employees
  [PASS] 5. POST /v1/auth/token returns 401 with 300ms delay
  [PASS] 6. Headers present (nginx/1.18.0 and 3.1.4)
  [PASS] 7. credential_theft callback fires on /v1/tokens
  [PASS] 8. data_access callback fires on normal endpoints

============================================================
Total: 8 | PASS: 8 | FAIL: 0
============================================================
```
