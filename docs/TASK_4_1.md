# TASK 4.1 — Fake SSH Honeypot

## Overview

Task 4.1 implements a production-grade **Paramiko-based SSH honeypot** container
for the ShadowMesh deception platform. The honeypot presents a fully interactive
fake bash shell to any attacker who connects, logging every credential attempt and
command back to the ShadowMesh backend in real-time. No real commands are ever
executed.

---

## Files Created

| File | Purpose |
|---|---|
| `docker/fake-ssh/server.py` | Full honeypot implementation |
| `docker/fake-ssh/Dockerfile` | Container build definition |
| `scripts/test_fake_ssh.py` | 20-assertion automated test suite |
| `docs/TASK_4_1.md` | This document |

---

## Architecture

```
Attacker SSH Client
       │
       │  TCP :22
       ▼
┌──────────────────────────────────────┐
│  docker/fake-ssh/server.py           │
│                                      │
│  ┌──────────────────────────────┐    │
│  │ _HoneypotServerInterface     │    │
│  │  check_auth_password()       │    │  800ms delay
│  │   → AUTH_SUCCESSFUL always   │    │  any user/pass
│  └──────────────────────────────┘    │
│                                      │
│  ┌──────────────────────────────┐    │
│  │ _run_fake_shell()            │    │
│  │  _resolve_command(cmd)       │    │  hardcoded dispatch table
│  │   → COMMAND_RESPONSES[cmd]  │    │  "command not found" fallback
│  └──────────────────────────────┘    │
│                                      │
│  _fire_callback_async()              │──► POST /api/attacker/action
│   (daemon thread, non-blocking)      │    (every login + every command)
└──────────────────────────────────────┘
```

### Key design decisions

| Decision | Rationale |
|---|---|
| Paramiko `ServerInterface` | Pure Python SSH — no host `sshd` inside container |
| Ephemeral RSA host key (2048-bit) | Generated fresh at startup; never stored in image |
| 800ms `time.sleep` in `check_auth_password` | Matches spec; realistic login latency |
| `COMMAND_RESPONSES` dict (module constant) | O(1) lookup; zero subprocess execution |
| Daemon thread for callbacks | Callback latency never blocks the attacker's shell |
| `recv` byte-by-byte echo | Correct interactive terminal behaviour (backspace support) |

---

## Supported Commands

| Command | Response |
|---|---|
| `ls` | `Documents  Downloads  .ssh  .bash_history  financial_reports  employee_data` |
| `pwd` | `/home/admin` |
| `whoami` | `admin` |
| `id` | `uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),27(sudo)` |
| `cat /etc/passwd` | 20-line realistic fake passwd file |
| `uname -a` | `Linux db-prod-01 5.15.0-105-generic ...` |
| `ps aux` | Realistic-looking process table (root, mysql, postgres, admin) |
| `netstat -an` | Listening ports 22/3306/5432/80/443 + established SSH session |
| `history` | 9-entry fake shell history |
| `exit` / `logout` / `quit` | Closes session cleanly |
| _Any other command_ | `bash: <command>: command not found` |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NODE_ID` | `fake-ssh-node` | Injected by `container_manager` — identifies this honeypot node |
| `ATTACKER_CALLBACK_URL` | `http://backend:8000` | Base URL of the ShadowMesh FastAPI backend |
| `SSH_PORT` | `22` | Listening port inside the container (mapped dynamically on the host) |

---

## Callback Payload

Every login and command POSTs the following JSON to `{ATTACKER_CALLBACK_URL}/api/attacker/action`:

```json
{
  "attacker_ip":     "203.0.113.42",
  "action_type":     "login_attempt",
  "target_node_id":  "fake-ssh-node",
  "detail":          "SSH login accepted — username='root' password='toor'",
  "timestamp":       1717064234.812
}
```

`action_type` is one of:
- `login_attempt` — on every authentication attempt
- `command_exec` — on every command submitted in the shell

---

## How to Run Locally (without Docker)

> [!IMPORTANT]
> Requires `paramiko` and `requests`. Install them inside your virtual environment first.

```powershell
# From project root with venv active:
pip install paramiko requests

# Start the honeypot on port 2222 (no root needed on high ports)
$env:SSH_PORT = "2222"
$env:NODE_ID = "local-test-node"
$env:ATTACKER_CALLBACK_URL = "http://localhost:8000"
python docker/fake-ssh/server.py
```

Connect from another terminal:
```bash
ssh -p 2222 -o StrictHostKeyChecking=no attacker@127.0.0.1
# Enter any password when prompted
```

---

## How to Run with Docker

### Build the image
```bash
docker build -t shadowmesh-fake-ssh ./docker/fake-ssh
```

### Run standalone (for testing)
```bash
docker run --rm -it \
  -p 2222:22 \
  -e NODE_ID=test-db-node \
  -e ATTACKER_CALLBACK_URL=http://host.docker.internal:8000 \
  shadowmesh-fake-ssh
```

### Connect to the running container
```bash
ssh -p 2222 -o StrictHostKeyChecking=no attacker@127.0.0.1
# Any password accepted
```

---

## Test Procedure

Run the automated test suite (no Docker, no network required):

```powershell
# From project root, with venv active:
$env:PYTHONIOENCODING = "utf-8"
.\venv\Scripts\python scripts\test_fake_ssh.py
```

### Test coverage

| Test ID | Description |
|---|---|
| T4.1.1 | Login succeeds with any username/password |
| T4.1.2 | Login delay is ≥ 800ms |
| T4.1.3 (×9) | Each of the 9 spec'd commands returns correct content |
| T4.1.4 (×2) | Invalid commands return "command not found" |
| T4.1.5 | Callback fires with `login_attempt` on auth |
| T4.1.6 | Callback fires with `command_exec` per command |
| T4.1.7 | Callback payload contains all 5 required fields |
| T4.1.7b | `target_node_id` matches `NODE_ID` env var |
| T4.1.8 | `exit` closes session without exception |
| T4.1.9 | `uname -a` returns hardcoded fake string (not real host) |
| T4.1.9b (×11) | Unit-tests for `_resolve_command()` covering all branches |
| T4.1.10 | 3 concurrent connections handled without errors |

---

## Expected Output

```
═══ TASK 4.1 — Fake SSH Honeypot Verification Suite ═══
  [PASS] T4.1.1 Login with any credentials succeeds
  [PASS] T4.1.2 Login delay >= 800ms — elapsed=812ms
  [PASS] T4.1.3 Command 'ls' contains 'financial_reports'
  [PASS] T4.1.3 Command 'pwd' contains '/home/admin'
  [PASS] T4.1.3 Command 'whoami' contains 'admin'
  [PASS] T4.1.3 Command 'id' contains 'uid=1000(admin)'
  [PASS] T4.1.3 Command 'cat /etc/passwd' contains 'root:x:0:0'
  [PASS] T4.1.3 Command 'uname -a' contains 'Linux db-prod-01'
  [PASS] T4.1.3 Command 'ps aux' contains 'mysql'
  [PASS] T4.1.3 Command 'netstat -an' contains 'LISTEN'
  [PASS] T4.1.3 Command 'history' contains 'apt-get update'
  [PASS] T4.1.4 Invalid command → 'command not found'
  [PASS] T4.1.4 Unknown 'curl' → 'command not found'
  [PASS] T4.1.5 Callback fires on login — login callbacks captured=1
  [PASS] T4.1.6 Callback fires on command exec — command_exec callbacks captured=2
  [PASS] T4.1.7 Callback payload has required fields
  [PASS] T4.1.7b target_node_id == NODE_ID env var
  [PASS] T4.1.8 'exit' closes the session gracefully
  [PASS] T4.1.9 'uname -a' returns hardcoded (not real) output
  ... (unit tests and concurrency)
──────────────────────────────────────────────────────────────
  Total: 26 | PASS: 26 | FAIL: 0
──────────────────────────────────────────────────────────────
```

---

## Security Notes

> [!WARNING]
> This is a **deception-only** container. It must **never** be deployed with real credentials,
> real file access, or real network adjacency to production systems. It is a honeypot,
> not a bastion host.

- No real shell is spawned — ever.
- No subprocesses are launched by `server.py`.
- The RSA host key is generated fresh on every container start and is never persisted.
- All credential data captured is fake and purely for threat intelligence logging.
