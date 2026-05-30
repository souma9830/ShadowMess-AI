# TASK 4.2D — Fake LDAP / SSO / Active Directory Honeypot

## Overview

Task 4.2D implements a production-grade **Flask-based LDAP & SSO honeypot** container for the ShadowMesh deception platform. Running on port `389` inside the container (simulating HTTP-based LDAP services or web-based SSO portals), it mimics a corporate Active Directory infrastructure.

It provides endpoints that simulate user directory searches (returning XML formatted user data, groups, and fake password hashes) and SAML-based SSO metadata. It enforces authentication failures and deliberate latencies to maximize attacker engagement time while reliably logging all interactions as `login_attempt` telemetry events.

---

## Files Created

| File | Purpose |
|---|---|
| `docker/fake-auth/server.py` | Full LDAP / SSO honeypot implementation (Flask) |
| `docker/fake-auth/Dockerfile` | Container build definition |
| `scripts/test_fake_auth.py` | Automated testing and verification suite |
| `docs/TASK_4_2D.md` | This architectural and operational manual |

---

## Architecture

```
Attacker Client
       │
       │  TCP :389
       ▼
┌──────────────────────────────────────────────┐
│  docker/fake-auth/server.py                  │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Flask App Engine (Port 389)            │  │
│  │  Interceptors:                         │  │
│  │   - Server: Microsoft-IIS/10.0         │  │
│  │   - X-Powered-By: ASP.NET              │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Routes & Simulators                    │  │
│  │  /ldap/search    ➔ XML 20 Fake Users   │  │
│  │  /ldap/bind      ➔ HTTP 401 Code 49    │  │
│  │  /sso/metadata   ➔ Fake SAML XML       │  │
│  │  /sso/login      ➔ Simulate auth delay │  │
│  │                    (500ms) ➔ HTTP 401  │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  _fire_callback_async()                      │──► POST /api/attacker/action
│   (Daemon thread, non-blocking telemetry)    │    (every request = login_attempt)
└──────────────────────────────────────────────┘
```

### Key Architectural Standards

1. **Microsoft IIS Simulation**: Overrides default WSGI server headers to present an authentic Windows Server signature (`Microsoft-IIS/10.0` and `ASP.NET`), which pairs logically with Active Directory implementations.
2. **XML Payload Generation**: Generates valid XML payloads for both LDAP search results (users, groups, hashes) and SAML SSO metadata (`EntityDescriptor`), providing rich, parseable data to automated enumeration tools.
3. **Authentication Latency Simulation (`POST /sso/login`)**: Blocks execution for exactly `500ms` prior to returning an `HTTP 401` payload.
4. **LDAP Failure Simulation (`POST /ldap/bind`)**: Returns a standardized LDAP `invalidCredentials` payload with error code `49`.
5. **Decoupled Telemetry Pipeline**: Communication to the core backend FastAPI logging engine (`POST /api/attacker/action`) is run asynchronously using independent daemon threads.

---

## API Routes

### 1. `GET /ldap/search`
Returns a valid XML document containing 20 fake users, including their Common Name (`cn`), department, group, and a fake bcrypt password hash.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<users>
  <user>
    <cn>john.smith</cn>
    <department>Finance</department>
    <group>Domain Users</group>
    <hash>$2b$12$R1qK...ZzF</hash>
  </user>
  <!-- ... 19 more users ... -->
</users>
```

### 2. `POST /ldap/bind`
Simulates a failed LDAP bind attempt.
- **HTTP Code**: `401 Unauthorized`
- **Response**:
```json
{
  "result": "invalidCredentials",
  "code": 49
}
```

### 3. `GET /sso/metadata`
Returns fake SAML metadata XML.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://sso.corp.internal/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <!-- ... SAML metadata ... -->
</EntityDescriptor>
```

### 4. `POST /sso/login`
Accepts authentication payloads, blocks execution for `500ms`, and always rejects with:
- **HTTP Code**: `401 Unauthorized`
- **Response**: `Login Failure: Invalid Token or Credentials`

---

## Response Headers

To present a convincing Windows proxy layer, all outgoing traffic includes:
- `Server: Microsoft-IIS/10.0`
- `X-Powered-By: ASP.NET`

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `fake-auth-node` | Injected by orchestrator — identifies this node |
| `ATTACKER_CALLBACK_URL` | `http://backend:8000` | Target backend webhook base url |
| `AUTH_PORT` | `389` | Internal port bound inside the honeypot container |

---

## Telemetry Callback Schema

Fires a `POST` request to `{ATTACKER_CALLBACK_URL}/api/attacker/action` with:
```json
{
  "attacker_ip": "172.20.0.1",
  "action_type": "login_attempt",
  "target_node_id": "fake-auth-node",
  "detail": "LDAP/SSO access — GET /ldap/search",
  "timestamp": 1717064234.812
}
```
*Note: `action_type` is strictly set to `login_attempt` for all routes in the Fake Auth service.*

---

## How to Run Locally (without Docker)

Install dependencies in your active environment:
```powershell
pip install flask requests
```

Launch the mock LDAP/SSO interface on a local port (e.g. `3890` to avoid requiring admin privileges on standard port 389):
```powershell
$env:AUTH_PORT = "3890"
$env:NODE_ID = "local-auth-test"
$env:ATTACKER_CALLBACK_URL = "http://localhost:8000"
python docker/fake-auth/server.py
```

Access using `curl`:
- `curl -I http://localhost:3890/ldap/search` (to verify headers)
- `curl http://localhost:3890/sso/metadata` (to retrieve SAML XML)

---

## How to Run with Docker

### Build the Image
```bash
docker build -t shadowmesh-fake-auth ./docker/fake-auth
```

### Run Container Standalone
```bash
docker run --rm -it \
  -p 389:389 \
  -e NODE_ID=prod-ad-controller \
  -e ATTACKER_CALLBACK_URL=http://host.docker.internal:8000 \
  shadowmesh-fake-auth
```

---

## Test Procedure

Execute the automated test suite locally to verify full compliance:
```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python scripts/test_fake_auth.py
```

---

## Expected Output

```
════════════════════════════════════════════════════════════
═══ TASK 4.2D — Fake Auth Honeypot Verification Suite ═══
════════════════════════════════════════════════════════════
  [PASS] 1 & 7. GET /ldap/search returns valid XML with 20 users
  [PASS] 2. POST /ldap/bind always returns invalidCredentials/49
  [PASS] 3 & 7. GET /sso/metadata returns valid SAML XML
  [PASS] 4. POST /sso/login fails with 500ms delay
  [PASS] 5. Headers present (Microsoft-IIS/10.0 and ASP.NET)
  [PASS] 6. Callback firing (login_attempt)

============================================================
Total: 6 | PASS: 6 | FAIL: 0
============================================================
```
