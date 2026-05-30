# TASK 4.2A — Fake HTTP Honeypot

## Overview

Task 4.2A implements a production-grade **Flask-based HTTP honeypot** container
for the ShadowMesh deception platform. The honeypot presents a premium look
Internal Employee Portal for the `/` route, simulates login verification delay (600ms),
provides high-fidelity API configurations and mock user lists, handles non-existent endpoints
with an Nginx-style 404, masks itself with Apache and PHP headers, and logs
all attacker requests back to the ShadowMesh core system asynchronously.

---

## Files Created

| File | Purpose |
|---|---|
| `docker/fake-http/server.py` | Full HTTP honeypot implementation (Flask) |
| `docker/fake-http/Dockerfile` | Container build definition |
| `scripts/test_fake_http.py` | Complete automated verification suite |
| `docs/TASK_4_2A.md` | This architecture and implementation documentation |

---

## Architecture

```
Attacker Browser / HTTP Client
             │
             │  TCP :80
             ▼
┌──────────────────────────────────────────────┐
│  docker/fake-http/server.py                  │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Flask App Configuration                │  │
│  │  Custom After-Request Interceptor      │  │
│  │   - Appends Server Banners             │  │
│  │   - Server: Apache/2.4.41 (Ubuntu)     │  │
│  │   - X-Powered-By: PHP/7.4.33           │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ Endpoint Mappings                      │  │
│  │  /               ➔ Portal HTML         │  │
│  │  /api/           ➔ Version JSON        │  │
│  │  /api/users      ➔ 8 Employee Profiles │  │
│  │  /api/config     ➔ DB Configuration    │  │
│  │  /api/login      ➔ Simulated latency   │  │
│  │                    (600ms)             │  │
│  │  404 Handler     ➔ Nginx-style HTML    │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  _fire_callback_async()                      │──► POST /api/attacker/action
│   (Daemon thread, non-blocking telemetry)    │    (every request / status)
└──────────────────────────────────────────────┘
```

### Key Design and Security Decisions

1. **Custom Middleware Hook (`@app.after_request`)**: Standardizes response manipulation. Automatically appends Server headers and processes background telemetries for all successful requests, failed authentication attempts, and 404 route scans.
2. **Delayed Authentication Pipeline (`time.sleep(0.6)`)**: The `POST /api/login` endpoint blocks for exactly `600ms` prior to returning an invalid credential error. This emulates an active backend lookup (e.g. Active Directory or LDAP database query) to keep attackers engaged.
3. **Decoupled Telemetry Transmission (`threading.Thread`)**: Logging callback execution is handled asynchronously via a daemon thread, protecting the attacker session from lagging in case the FastAPI backend is running under high load or network delays.
4. **Authentic nginx-style 404 Pages**: Scans for standard admin pathways return an authentic, minimal nginx 404 HTML structure to trick attackers into believing they hit standard proxy gateways.

---

## API Endpoints

### 1. `GET /`
Returns a highly premium, glassmorphism corporate sign-in portal titled **Internal Employee Portal — Login Required**. Includes a responsive interactive JavaScript form that dispatches async requests to `/api/login`.

### 2. `GET /api/`
Returns:
```json
{
  "version": "2.3.1",
  "endpoints": [
    "/api/users",
    "/api/reports",
    "/api/config"
  ]
}
```

### 3. `GET /api/users`
Returns a list of 8 realistic mock employee roles and email structures:
```json
[
  {"name": "Alice Smith", "role": "Network Administrator", "email": "alice.smith@corp.internal"},
  {"name": "Bob Jones", "role": "Database Administrator", "email": "bob.jones@corp.internal"},
  ...
]
```

### 4. `GET /api/config`
Returns corporate database host credentials pointing to internal targets:
```json
{
  "db_host": "172.20.0.12",
  "db_port": 3306,
  "environment": "production",
  "debug": false
}
```

### 5. `POST /api/login`
Blocks for `600ms` and returns:
```json
{
  "success": false,
  "error": "Invalid credentials"
}
```

---

## Response Headers
To mimic a legacy LAMP server stack under Ubuntu, every request is customized with:
- `Server: Apache/2.4.41 (Ubuntu)`
- `X-Powered-By: PHP/7.4.33`

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `fake-http-node` | Injected dynamically — identifies this deception container |
| `ATTACKER_CALLBACK_URL` | `http://backend:8000` | Target URL pointing to ShadowMesh Core API |
| `HTTP_PORT` | `80` | Internal port bound inside the virtual node container |

---

## Telemetry Payload
Fires a non-blocking `POST` on every interaction to `{ATTACKER_CALLBACK_URL}/api/attacker/action` with:
```json
{
  "attacker_ip": "172.20.0.1",
  "action_type": "data_access",
  "target_node_id": "fake-http-node",
  "detail": "HTTP access — GET /api/users",
  "timestamp": 1717064234.812
}
```
*Note: The `action_type` resolves to `login_attempt` when processing credential validations on `/api/login`.*

---

## How to Run Locally (without Docker)

Ensure Flask and Requests dependencies are installed in your active virtual environment:
```powershell
pip install flask requests
```

Run the server on a local high-port (e.g. port `8080`):
```powershell
$env:HTTP_PORT = "8080"
$env:NODE_ID = "local-http-test"
$env:ATTACKER_CALLBACK_URL = "http://localhost:8000"
python docker/fake-http/server.py
```

Access via browser or curl:
- Open `http://localhost:8080/` to view the Employee Portal.
- Run `curl -I http://localhost:8080/api/users` to verify custom HTTP banners.

---

## How to Run with Docker

### Build the Image
```bash
docker build -t shadowmesh-fake-http ./docker/fake-http
```

### Run Container Standalone
```bash
docker run --rm -it \
  -p 8080:80 \
  -e NODE_ID=prod-employee-portal \
  -e ATTACKER_CALLBACK_URL=http://host.docker.internal:8000 \
  shadowmesh-fake-http
```

---

## Test Procedure

Run the automated test suite locally to verify absolute compliance:
```powershell
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts:python scripts/test_fake_http.py
```

---

## Expected Output

```
════════════════════════════════════════════════════════════
═══ TASK 4.2A — Fake HTTP Honeypot Verification Suite ═══
════════════════════════════════════════════════════════════
  [PASS] T4.2A.1 GET / matches Portal HTML specifications
  [PASS] T4.2A.2 GET /api/ returns version metadata
  [PASS] T4.2A.3 GET /api/users returns 8 employee profiles
  [PASS] T4.2A.4 GET /api/config returns fake credentials configuration
  [PASS] T4.2A.5 POST /api/login rejects credentials with 600ms delay
  [PASS] T4.2A.6 GET unknown route returns Nginx-style 404 page
  [PASS] T4.2A.7 Banners match requirements (Apache/Ubuntu + PHP)
  [PASS] T4.2A.8 Telemetry callback dispatches successfully — Payload structure verified: node_id=test-http-node-402

============================================================
Total: 8 | PASS: 8 | FAIL: 0
============================================================
```
