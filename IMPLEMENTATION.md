# ShadowMesh — Implementation Guide

> 24 hours. 4 people. All in.
> Every task is scoped to 1–2 hours of AI-assisted coding.
> Commit after every task. The demo must be flawless — parallel tracks merge at Hour 10.
> Hour estimates are per-track, not wall-clock sequential.

---

## Team Assignments

| Person | Track | Phases |
|---|---|---|
| **Dealer** | Frontend — React dashboard, graph, heatmap | Phase 0 → 2 → 7 → 8 |
| **T2** | Detection — Scapy, FastAPI, Socket.IO events | Phase 0 → 1 → 5 → 6 |
| **T3** | AI — Groq profiling, NetworkX topology, MITRE mapping | Phase 0 → 3 → 6 |
| **T4** | Infrastructure — Docker fake services, Neo4j, Compose | Phase 0 → 4 → 6 |

---

## Project Structure

```
shadowmesh/
├── backend/
│   ├── main.py                  # FastAPI app entry + Socket.IO mount
│   ├── api/
│   │   └── routes.py            # REST endpoints
│   ├── detection/
│   │   └── scanner.py           # Scapy recon detector (runs as thread)
│   ├── deception/
│   │   └── container_manager.py # Docker fake asset spin-up/teardown
│   ├── ai/
│   │   ├── topology.py          # NetworkX Barabási–Albert generator
│   │   ├── profiler.py          # Groq attacker behavioral profiler
│   │   └── mutator.py           # Topology reshuffle engine
│   ├── mitre/
│   │   └── mapper.py            # mitreattack-python TTP tagger
│   ├── database/
│   │   └── neo4j_client.py      # Neo4j driver + attack graph queries
│   └── models.py                # Pydantic models (shared types)
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── NetworkGraph.jsx     # react-force-graph-2d live topology
│   │   │   ├── MitreHeatmap.jsx     # D3.js ATT&CK heatmap
│   │   │   ├── AttackerProfile.jsx  # Groq output panel
│   │   │   ├── AlertFeed.jsx        # Socket.IO live event log
│   │   │   └── StatsBar.jsx         # Session stats (dwell time, nodes hit)
│   │   ├── store/
│   │   │   └── useShadowStore.js    # Zustand global state
│   │   └── services/
│   │       └── socket.js            # Socket.IO client singleton
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
│   ├── alerting/
│   │   └── slack.py             # Slack webhook dispatcher
│   ├── deception/
│   │   ├── container_manager.py # Calls orchestrator sidecar over HTTP (no socket mount)
│   │   ├── credentials.py       # Fake credential file generator
│   │   └── canary.py            # Canary token tracker + alert
│   ├── detection/
│   │   ├── scanner.py           # Scapy recon detector (runs as thread)
│   │   └── dns_honeypot.py      # DNS responder — logs all queries, fires canary on planted names
├── orchestrator/
│   ├── app.py                   # Flask sidecar — only service with Docker socket access
│   └── Dockerfile
├── docker/
│   ├── fake-ssh/
│   │   └── Dockerfile
│   ├── fake-http/
│   │   └── Dockerfile
│   ├── fake-db/
│   │   └── Dockerfile
│   ├── fake-api/
│   │   └── Dockerfile           # Dedicated REST API honeypot
│   └── fake-auth/
│       └── Dockerfile           # LDAP/OAuth fake auth service
├── scripts/
│   ├── download_mitre.py        # One-time MITRE JSON download
│   └── simulate_attacker.py     # Demo attacker script (nmap + ssh + curl)
├── configs/
│   └── node_templates.json      # Fake server fingerprint templates
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## Phase 0 — Scaffold & Setup
> **ALL 4 PEOPLE — Hour 0 to 2**
> Goal: One `docker-compose up` spins everything. Zero broken imports before parallel work starts.

### Task 0.1 — Repo init + Python backend scaffold
```
Prompt to AI:
"Create a Python backend project structure for ShadowMesh.
Root files: requirements.txt, .env.example, .gitignore.

requirements.txt must include:
  fastapi==0.111.0
  uvicorn[standard]==0.29.0
  python-socketio==5.11.2
  python-dotenv==1.0.1
  scapy==2.5.0
  docker==7.0.0
  networkx==3.3
  neo4j==5.20.0
  mitreattack-python==3.0.4
  groq==0.9.0
  pydantic==2.7.1
  aiofiles==23.2.1
  httpx==0.27.0
  requests==2.31.0
  redis==5.0.4
  scikit-learn==1.4.2
  numpy==1.26.4
  dnslib==0.9.24

.env.example:
  NEO4J_URI=bolt://localhost:7687
  NEO4J_USER=neo4j
  NEO4J_PASSWORD=shadowmesh
  GROQ_API_KEY=
  SLACK_WEBHOOK_URL=
  NETWORK_INTERFACE=eth0
  FAKE_NETWORK_SUBNET=172.20.0.0/24
  BACKEND_PORT=8000

backend/models.py — Pydantic models:
  class ScanEvent(BaseModel):
    source_ip: str
    scan_type: str  # 'port_scan' | 'service_probe' | 'fingerprint_attempt'
    ports_hit: list[int]
    timestamp: float

  class NetworkNode(BaseModel):
    node_id: str
    ip: str
    node_type: str  # 'web_server' | 'db_server' | 'auth_service' | 'file_server' | 'api_gateway' | 'mail_server' | 'workstation'
    ports: list[int]
    banner: str
    os: str
    is_fake: bool = True
    container_id: str | None = None

  class AttackerAction(BaseModel):
    attacker_ip: str
    action_type: str  # 'port_scan' | 'login_attempt' | 'command_exec' | 'data_access' | 'lateral_move' | 'credential_theft' | 'canary_trigger'
    target_node_id: str
    detail: str
    timestamp: float
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None

  class AttackerProfile(BaseModel):
    attacker_ip: str
    skill_level: str   # 'Script Kiddie' | 'Intermediate' | 'Advanced' | 'Nation-State APT'
    objective: str
    apt_resemblance: str
    tools_detected: list[str]
    confidence: float
    summary: str

  class TopologySnapshot(BaseModel):
    nodes: list[NetworkNode]
    edges: list[tuple[str, str]]
    generation: int

  class FakeCredential(BaseModel):
    cred_id: str           # e.g. 'cred_node_0_3_env'
    node_id: str           # which fake container it lives in
    cred_type: str         # 'env_file' | 'aws_key' | 'ssh_key' | 'db_password'
    filename: str          # e.g. '.env', 'credentials.csv', 'id_rsa'
    content: str           # the fake credential content served to the attacker
    accessed: bool = False
    accessed_at: float | None = None

  class CanaryToken(BaseModel):
    token_id: str          # unique UUID
    node_id: str           # which fake container it's planted in
    token_url: str         # the fake URL that triggers on access
    token_type: str        # 'document' | 'url' | 'email'
    label: str             # e.g. 'Q3_Financial_Report.pdf'
    triggered: bool = False
    triggered_at: float | None = None
    triggered_by_ip: str | None = None"
```
**Commit:** `chore: init project structure, requirements, pydantic models`

---

### Task 0.2 — Docker Compose: Neo4j + fake network bridge
```
Prompt to AI:
"Create docker-compose.yml for ShadowMesh.

Services:
1. neo4j:
   image: neo4j:5.19
   ports: 7474:7474, 7687:7687
   environment:
     NEO4J_AUTH: neo4j/shadowmesh
     NEO4J_PLUGINS: '["apoc"]'
   volumes: neo4j_data:/data, neo4j_logs:/logs
   healthcheck: wget -q --spider http://localhost:7474 || exit 1

2. redis:
   image: redis:7-alpine
   ports: 6379:6379
   command: redis-server --save 60 1 --loglevel warning
   volumes: redis_data:/data
   healthcheck: redis-cli ping || exit 1

3. orchestrator:
   build: ./orchestrator (Flask sidecar — see Phase 9 Task 9.5)
   ports: 9000:9000
   volumes: /var/run/docker.sock:/var/run/docker.sock (ONLY this service gets the socket)
   environment:
     DECEPTION_NETWORK: shadowmesh_deception_net
   networks: [default, deception_net]
   healthcheck: wget -q --spider http://localhost:9000/health || exit 1

4. backend:
   build: ./backend (Dockerfile: python:3.11-slim, pip install -r requirements.txt,
     CMD uvicorn main:socket_app --host 0.0.0.0 --port 8000 --reload)
   ports: 8000:8000
   env_file: .env
   depends_on: [neo4j, redis, orchestrator]
   volumes: [] (NO Docker socket mount — communicates via orchestrator instead)
   network_mode: host (needed for Scapy raw socket access on Linux)
   cap_add: NET_RAW, NET_ADMIN (required for Scapy + DNS port 53)

5. frontend:
   build: ./frontend (Dockerfile: node:20-alpine, npm install, npm run dev)
   ports: 5173:5173
   depends_on: backend

Networks:
  deception_net:
    driver: bridge
    ipam:
      config: [{subnet: 172.20.0.0/24}]

Volumes: neo4j_data, neo4j_logs, redis_data"
```
**Commit:** `chore: docker-compose with neo4j, backend, frontend, deception network`

---

### Task 0.3 — MITRE ATT&CK dataset download script
```
Prompt to AI:
"Create scripts/download_mitre.py.
Downloads the MITRE ATT&CK Enterprise STIX JSON from the official MITRE CTI GitHub.
URL: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
Saves to backend/mitre/enterprise-attack.json
Shows download progress with a simple byte counter.
Also prints total technique count after download.
Run as: python scripts/download_mitre.py"
```
**Commit:** `chore: mitre att&ck dataset download script`

---

### Task 0.4 — Frontend scaffold: React + Vite
```
Prompt to AI:
"Scaffold a React 18 + Vite frontend in the frontend/ directory.
Install:
  react-force-graph-2d@1.25.4
  socket.io-client@4.7.5
  zustand@4.5.2
  d3@7.9.0
  framer-motion@11.2.10
  tailwindcss@3.4.3 (with postcss, autoprefixer)
  lucide-react@0.383.0

tailwind.config.js — dark theme base, custom colors:
  shadowRed: '#E24B4A'
  shadowAmber: '#EF9F27'
  shadowGreen: '#1D9E75'
  shadowPurple: '#7F77DD'
  shadowGray: '#1a1a1a'

vite.config.js: server proxy /api and /socket.io to http://localhost:8000

src/index.css: @tailwind base/components/utilities. Dark background (#0d0d0d) on body.

src/App.jsx: basic layout — top nav with 'ShadowMesh' title + live status dot,
  left sidebar (placeholder), main content area (placeholder).
  Import and render useShadowStore to confirm Zustand loads."
```
**Commit:** `feat(frontend): react + vite scaffold with tailwind dark theme`

---

## Phase 1 — FastAPI Core + Socket.IO
> **T2 — Hour 2 to 6** (runs parallel to Phase 2, 3, 4)
> Goal: Backend API running, Socket.IO emitting events, all endpoints reachable.

### Task 1.1 — FastAPI main app + Socket.IO server mount
```
Prompt to AI:
"Create backend/main.py.
Use python-socketio with FastAPI (ASGI combined app).

Setup:
  import socketio
  import fastapi
  sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
  app = FastAPI(title='ShadowMesh API')
  socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

Socket.IO namespaces — default namespace '/':
  @sio.event
  async def connect(sid, environ):
    print(f'Client connected: {sid}')
    await sio.emit('status', {'message': 'ShadowMesh active', 'deception': False}, to=sid)

  @sio.event
  async def disconnect(sid):
    print(f'Client disconnected: {sid}')

  @sio.event
  async def ping(sid, data):
    await sio.emit('pong', data, to=sid)

FastAPI lifespan:
  On startup: initialize Neo4j connection, load MITRE data, print 'ShadowMesh backend online'
  On shutdown: close Neo4j driver

GET /health → returns { status: 'ok', neo4j: bool, mitre_loaded: bool }

Include routers: api/routes.py (prefix /api)

Run with: uvicorn main:socket_app --host 0.0.0.0 --port 8000 --reload"
```
**Commit:** `feat(backend): fastapi + socket.io asgi app with lifespan`

---

### Task 1.2 — REST API routes
```
Prompt to AI:
"Create backend/api/routes.py with FastAPI APIRouter.

Endpoints:

POST /api/detect/scan
  Body: ScanEvent (from models.py)
  Action: Emit Socket.IO event 'recon_detected' with the scan data to all clients.
    Then call topology.generate_topology() (stub for now, returns empty TopologySnapshot).
    Emit 'topology_update' with the snapshot.
  Response: { status: 'deception_activated', node_count: int }

POST /api/attacker/action
  Body: AttackerAction
  Action: Save to Neo4j (stub), emit 'attacker_action' to all clients.
  Response: { status: 'logged' }

GET /api/topology/current
  Response: current TopologySnapshot from in-memory state (module-level variable,
    initialized as empty TopologySnapshot on startup)

GET /api/attacker/profile/{attacker_ip}
  Response: AttackerProfile from in-memory dict (keyed by IP), or 404 if not profiled yet

GET /api/neo4j/attack-path/{attacker_ip}
  Response: list of Neo4j nodes/relationships for the attacker's path (stub, returns [])

POST /api/topology/mutate
  Action: trigger topology mutation (stub — emit 'topology_mutating' then 'topology_update')
  Response: { status: 'mutated', generation: int }

Store current_topology: TopologySnapshot and attacker_profiles: dict as module-level
  state in routes.py. Import and update from other modules as they are built."
```
**Commit:** `feat(backend): rest api routes with socket.io emission stubs`

---

### Task 1.3 — Neo4j client + attack graph schema
```
Prompt to AI:
"Create backend/database/neo4j_client.py.

Class Neo4jClient:
  __init__(uri, user, password): create AsyncGraphDatabase.driver
  close(): await driver.close()

  async def init_schema():
    Run Cypher to create constraints:
      CREATE CONSTRAINT IF NOT EXISTS FOR (a:Attacker) REQUIRE a.ip IS UNIQUE
      CREATE CONSTRAINT IF NOT EXISTS FOR (n:Node) REQUIRE n.node_id IS UNIQUE
      CREATE CONSTRAINT IF NOT EXISTS FOR (c:Credential) REQUIRE c.credential_id IS UNIQUE
    Also create indexes on :AttackerAction(timestamp)

  async def create_attacker(ip: str) → None:
    MERGE (a:Attacker {ip: $ip})
    ON CREATE SET a.first_seen = datetime(), a.action_count = 0
    ON MATCH SET a.action_count = a.action_count + 1

  async def log_action(action: AttackerAction) → None:
    MERGE (a:Attacker {ip: $attacker_ip})
    MERGE (n:Node {node_id: $target_node_id})
    CREATE (a)-[:PERFORMED {
      action_type: $action_type,
      detail: $detail,
      timestamp: $timestamp,
      mitre_id: $mitre_id,
      mitre_name: $mitre_name
    }]->(n)

  async def get_attack_path(attacker_ip: str) → list[dict]:
    MATCH p = (a:Attacker {ip: $ip})-[:PERFORMED*]->(n:Node)
    RETURN [node in nodes(p) | {
      id: node.node_id, ip: node.ip, labels: labels(node)
    }] AS path_nodes,
    [rel in relationships(p) | {
      type: type(rel), action: rel.action_type,
      timestamp: rel.timestamp, mitre_id: rel.mitre_id
    }] AS path_rels
    LIMIT 1

  async def get_all_actions(attacker_ip: str) → list[dict]:
    MATCH (a:Attacker {ip: $ip})-[r:PERFORMED]->(n:Node)
    RETURN r, n ORDER BY r.timestamp

Instantiate as a singleton: neo4j_client = Neo4jClient(...) using env vars.
Import and call init_schema() from FastAPI lifespan startup."
```
**Commit:** `feat(backend): neo4j client with attack graph schema and cypher queries`

---

### Task 1.4 — Socket.IO event reference (shared constants)
```
Prompt to AI:
"Create backend/events.py — a single source of truth for all Socket.IO event names.
These must match exactly between backend and frontend.

EVENTS = {
  # Backend → Frontend
  'RECON_DETECTED':     'recon_detected',       # Attacker port scan detected
  'TOPOLOGY_UPDATE':    'topology_update',       # New fake topology generated
  'TOPOLOGY_MUTATING':  'topology_mutating',     # Topology about to reshuffle (animate fog)
  'ATTACKER_ACTION':    'attacker_action',       # Attacker interacted with a fake node
  'PROFILE_UPDATE':     'profile_update',        # Groq attacker profile updated
  'MITRE_TAG':          'mitre_tag',             # New MITRE technique detected
  'ALERT':              'alert',                 # High-priority alert
  'CONTAINER_SPAWNED':  'container_spawned',     # New fake Docker container online
  'CONTAINER_KILLED':   'container_killed',      # Fake container torn down
  'STATUS':             'status',                # General status update
  'CANARY_TRIGGERED':   'canary_triggered',      # Attacker accessed a canary token URL
  'CREDENTIAL_STOLEN':  'credential_stolen',     # Attacker accessed fake credential file
  'LURE_SPAWNED':       'lure_spawned',          # Adaptive lure: new targeted fake service spun up

  # Frontend → Backend (for demo trigger)
  'TRIGGER_SCAN':       'trigger_scan',          # Manual scan simulation for demo
  'TRIGGER_LOGIN':      'trigger_login',         # Manual login attempt simulation
  'TRIGGER_MUTATE':     'trigger_mutate',        # Manual topology mutation
}

Also create frontend/src/services/events.js with the identical mapping as a JS const object.
These are the only strings allowed for emit/on calls — no magic strings anywhere."
```
**Commit:** `feat: socket.io event constants — single source of truth`

---

### Task 1.5 — Slack webhook alert router
```
Prompt to AI:
"Create backend/alerting/slack.py.

Import: httpx, os, asyncio

SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')

SEVERITY_EMOJI = {
  'critical': '🚨',
  'warning':  '⚠️',
  'info':     '✅',
  'canary':   '🐦',
  'mitre':    '🎯',
}

async def send_slack_alert(message: str, severity: str = 'info', fields: dict = None) → None:
  If SLACK_WEBHOOK_URL is empty, log to console and return (graceful no-op — don't crash).

  Build Slack Block Kit payload:
  {
    blocks: [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: f'{emoji} *ShadowMesh Alert*\n{message}' }
      },
      # If fields dict provided (e.g. { 'Attacker IP': '192.168.1.100', 'Technique': 'T1046' }),
      # add a fields block with two columns
      {
        type: 'context',
        elements: [{ type: 'plain_text', text: f'Severity: {severity.upper()} | {datetime now ISO}' }]
      }
    ]
  }

  Use httpx.AsyncClient to POST to SLACK_WEBHOOK_URL.
  Timeout: 3 seconds. Wrap in try/except — Slack failure must NEVER crash the main app.
  Log success: '📨 Slack alert sent: {message[:60]}' or '⚠️ Slack alert failed: {error}'

async def alert_recon_detected(attacker_ip: str, scan_type: str) → None:
  await send_slack_alert(
    message=f'Recon detected — attacker `{attacker_ip}` running `{scan_type}`\nDeception fabric activated.',
    severity='critical',
    fields={ 'Attacker IP': attacker_ip, 'Scan Type': scan_type }
  )

async def alert_canary_triggered(attacker_ip: str, label: str, node_id: str) → None:
  await send_slack_alert(
    message=f'🐦 Canary triggered — attacker `{attacker_ip}` accessed `{label}` on node `{node_id}`',
    severity='canary',
    fields={ 'Attacker IP': attacker_ip, 'Canary': label, 'Node': node_id }
  )

async def alert_credential_stolen(attacker_ip: str, filename: str, cred_type: str) → None:
  await send_slack_alert(
    message=f'Fake credential accessed — attacker `{attacker_ip}` downloaded `{filename}` ({cred_type})',
    severity='warning',
    fields={ 'Attacker IP': attacker_ip, 'File': filename, 'Type': cred_type }
  )

async def alert_topology_mutated(generation: int) → None:
  await send_slack_alert(
    message=f'Topology reshuffled (generation {generation}) — fingerprinting attempt neutralized.',
    severity='info'
  )"
```
**Commit:** `feat(alerting): slack webhook router with block kit payload and severity routing`

---
> **Dealer — Hour 2 to 6**
> Goal: Dashboard layout, Zustand store, Socket.IO live connection, all panels rendering (even if with mock data).

### Task 2.1 — Zustand global store
```
Prompt to AI:
"Create frontend/src/store/useShadowStore.js using Zustand.

State shape:
  isDeceptionActive: false,
  attackerIp: null,
  topologyGeneration: 0,
  nodes: [],         // NetworkNode[]
  edges: [],         // [string, string][]
  actions: [],       // AttackerAction[] — last 50, newest first
  alerts: [],        // { id, message, severity, timestamp }[] — last 20
  attackerProfile: null,   // AttackerProfile | null
  mitreTechniques: {},     // { [technique_id]: { name, count, tactic } }
  sessionStats: {
    dwellTimeSeconds: 0,
    nodesExplored: 0,
    loginAttempts: 0,
    commandsRun: 0,
  },
  isMutating: false,       // true during topology reshuffle animation
  canaryTokens: [],        // CanaryToken[] — tracks all planted canaries
  stolenCredentials: [],   // FakeCredential[] — credentials the attacker has accessed

Actions:
  activateDeception(attackerIp)
  updateTopology(nodes, edges, generation)
  addAction(action)                     // prepend, keep last 50
  addAlert(message, severity)           // prepend, keep last 20, auto-generate id
  setAttackerProfile(profile)
  tagMitreTechnique(technique_id, name, tactic)
  incrementStat(stat: keyof sessionStats, by?: number)
  setMutating(bool)
  markCanaryTriggered(token_id, triggered_by_ip)
  markCredentialStolen(cred_id, accessed_at)
  reset()

Export both the hook (useShadowStore) and the raw store for use outside React."
```
**Commit:** `feat(frontend): zustand store with full shadow state shape`

---

### Task 2.2 — Socket.IO client + event wiring
```
Prompt to AI:
"Create frontend/src/services/socket.js.

Singleton Socket.IO client:
  import { io } from 'socket.io-client'
  const socket = io('http://localhost:8000', { transports: ['websocket'], autoConnect: true })
  export default socket

Create frontend/src/hooks/useSocketEvents.js — a React hook that:
  Imports socket, useShadowStore actions, and EVENTS constants from events.js.
  On mount, registers these Socket.IO listeners:
    EVENTS.RECON_DETECTED    → store.activateDeception(data.source_ip), store.addAlert
    EVENTS.TOPOLOGY_UPDATE   → store.updateTopology(data.nodes, data.edges, data.generation)
    EVENTS.TOPOLOGY_MUTATING → store.setMutating(true), then setMutating(false) after 2200ms
    EVENTS.ATTACKER_ACTION   → store.addAction(data), store.incrementStat based on action_type
    EVENTS.PROFILE_UPDATE    → store.setAttackerProfile(data)
    EVENTS.MITRE_TAG         → store.tagMitreTechnique(data.technique_id, data.name, data.tactic)
    EVENTS.ALERT             → store.addAlert(data.message, data.severity)
    EVENTS.CONTAINER_SPAWNED → store.addAlert('Container spawned: ' + data.node_type, 'info')
    EVENTS.CANARY_TRIGGERED  → store.markCanaryTriggered(data.token_id, data.triggered_by_ip),
                               store.addAlert('🐦 Canary triggered: ' + data.label, 'canary')
    EVENTS.CREDENTIAL_STOLEN → store.markCredentialStolen(data.cred_id, data.accessed_at),
                               store.addAlert('Fake credential accessed: ' + data.filename, 'warning')
    EVENTS.LURE_SPAWNED      → store.addAlert('Adaptive lure deployed: ' + data.lure_type, 'info')
  On unmount: remove all listeners (socket.off for each event).
  Return: { isConnected: boolean } based on socket.connected

Call useSocketEvents() once at the top of App.jsx."
```
**Commit:** `feat(frontend): socket.io client singleton + event wiring hook`

---

### Task 2.3 — Dashboard layout + StatsBar
```
Prompt to AI:
"Create frontend/src/components/Dashboard.jsx — the main layout shell.
Full-screen dark layout (#0d0d0d background).

Top bar (h-14, border-bottom 0.5px #2a2a2a):
  Left: ShadowMesh logo text (white, 16px bold)
  Center: Live status pill — gray 'Monitoring' when inactive,
    red pulsing dot + 'THREAT ACTIVE' when isDeceptionActive from store
  Right: Session timer (counts up from when deception activated, format MM:SS)

Left panel (w-72, border-right):
  StatsBar component (see below)
  AttackerProfile component (placeholder div for now)

Center panel (flex-1):
  NetworkGraph component (placeholder div, min-h-96, border)

Right panel (w-80, border-left):
  AlertFeed component (placeholder)
  MitreHeatmap component (placeholder, h-64)

Create frontend/src/components/StatsBar.jsx:
  Four metric cards in a 2x2 grid using Zustand sessionStats:
  - Dwell Time (formats seconds to MM:SS)
  - Nodes Explored
  - Login Attempts
  - Commands Run
  Card style: bg-[#161616] border border-[#2a2a2a] rounded-lg p-3
  Label: text-xs text-gray-500 uppercase tracking-wider
  Value: text-2xl font-medium text-white
  Animate value changes with framer-motion (scale spring on number change)"
```
**Commit:** `feat(frontend): dashboard layout shell + statsbar metric cards`

---

### Task 2.4 — AlertFeed component
```
Prompt to AI:
"Create frontend/src/components/AlertFeed.jsx.
Reads alerts array from Zustand store.

Layout: scrollable list, newest alert at top, max height fills right panel.

Each alert item:
  Left accent bar — color by severity:
    'critical' → shadowRed (#E24B4A)
    'warning'  → shadowAmber (#EF9F27)
    'info'     → shadowGreen (#1D9E75)
    'mitre'    → shadowPurple (#7F77DD)
  Alert message text (14px, text-gray-200)
  Timestamp (12px, text-gray-500, format HH:MM:SS)

Animate new alerts sliding in from top using framer-motion AnimatePresence + motion.div:
  initial: { opacity: 0, y: -12 }
  animate: { opacity: 1, y: 0 }
  exit:    { opacity: 0, height: 0 }
  transition: { duration: 0.2 }

Empty state: 'No alerts — system monitoring' in gray italic

Section header: 'LIVE ALERTS' in uppercase tracking-widest text-xs text-gray-500,
  with a small red dot that pulses when isDeceptionActive"
```
**Commit:** `feat(frontend): alert feed with framer-motion slide-in animations`

---

## Phase 3 — AI Layer
> **T3 — Hour 2 to 8**
> Goal: Groq profiler working, NetworkX topology generator producing real output, MITRE mapper tagging actions.

### Task 3.1 — NetworkX topology generator
```
Prompt to AI:
"Create backend/ai/topology.py.

Import: networkx, random, ipaddress, json, pathlib

Load configs/node_templates.json at module load:
{
  'web_server':   { 'ports': [80, 443, 8080], 'banner': 'Apache/2.4.41', 'os': 'Ubuntu 20.04' },
  'db_server':    { 'ports': [3306, 5432],    'banner': 'MySQL 8.0.28',  'os': 'CentOS 7'    },
  'auth_service': { 'ports': [389, 636, 88],  'banner': 'OpenLDAP 2.4',  'os': 'Windows Server 2019' },
  'file_server':  { 'ports': [445, 139, 21],  'banner': 'Samba 4.11',    'os': 'Windows Server 2016' },
  'api_gateway':  { 'ports': [443, 8443],     'banner': 'nginx/1.18.0',  'os': 'Ubuntu 22.04' },
  'mail_server':  { 'ports': [25, 143, 587],  'banner': 'Postfix 3.4',   'os': 'Debian 11'   },
  'workstation':  { 'ports': [135, 3389],     'banner': 'RDP',           'os': 'Windows 10'  }
}

async def generate_topology(generation: int = 0) → TopologySnapshot:
  node_count = random.randint(9, 14)

  # Barabási–Albert: scale-free graph, matches real enterprise growth patterns
  G = nx.barabasi_albert_graph(n=node_count, m=2, seed=random.randint(0, 9999))

  node_types = list(NODE_TEMPLATES.keys())
  weights = [0.20, 0.15, 0.10, 0.15, 0.15, 0.10, 0.15]  # realistic enterprise distribution

  subnet = ipaddress.IPv4Network('172.20.0.0/24')
  available_ips = list(subnet.hosts())[5:]  # skip first 5 (gateway/infra)
  random.shuffle(available_ips)

  nodes = []
  for i, graph_node in enumerate(G.nodes()):
    node_type = random.choices(node_types, weights=weights, k=1)[0]
    template = NODE_TEMPLATES[node_type]
    # Add realistic imperfections: random extra open ports, slight banner variations
    ports = template['ports'][:]
    if random.random() < 0.3:
      ports.append(random.choice([22, 8080, 9000, 10050]))  # random extra port
    banner_variation = template['banner']
    if random.random() < 0.25:
      banner_variation += f' (Ubuntu)' if 'Apache' in banner_variation else ''

    nodes.append(NetworkNode(
      node_id=f'node_{generation}_{i}',
      ip=str(available_ips[i % len(available_ips)]),
      node_type=node_type,
      ports=sorted(set(ports)),
      banner=banner_variation,
      os=template['os'],
      is_fake=True,
    ))

  edges = [(f'node_{generation}_{u}', f'node_{generation}_{v}') for u, v in G.edges()]
  return TopologySnapshot(nodes=nodes, edges=edges, generation=generation)

async def mutate_topology(current: TopologySnapshot) → TopologySnapshot:
  # Keep ~40% of nodes (simulate partial reshuffle), regenerate the rest
  new = await generate_topology(generation=current.generation + 1)
  return new"
```
**Commit:** `feat(ai): networkx barabasi-albert topology generator with node templates`

---

### Task 3.2 — Groq attacker profiler
```
Prompt to AI:
"Create backend/ai/profiler.py.

Import: groq, os, json, backend.models (AttackerAction, AttackerProfile)

groq_client = groq.AsyncGroq(api_key=os.environ['GROQ_API_KEY'])

SYSTEM_PROMPT = '''You are a threat intelligence analyst inside a cyber deception platform.
You receive a log of attacker actions inside a fake network and must profile the attacker.
Always respond ONLY with a valid JSON object — no markdown, no explanation, no backticks.
JSON schema:
{
  skill_level: 'Script Kiddie' | 'Intermediate' | 'Advanced' | 'Nation-State APT',
  objective: string (one sentence — what are they after?),
  apt_resemblance: string (e.g. 'APT29', 'Lazarus Group', 'Unknown'),
  tools_detected: string[] (e.g. ['nmap', 'hydra', 'mimikatz']),
  confidence: float (0.0–1.0),
  summary: string (2 sentences max — behavioral summary for the SOC)
}'''

async def profile_attacker(attacker_ip: str, actions: list[AttackerAction]) → AttackerProfile:
  if len(actions) < 2:
    # Not enough data yet — return a low-confidence placeholder
    return AttackerProfile(
      attacker_ip=attacker_ip,
      skill_level='Unknown',
      objective='Reconnaissance in progress',
      apt_resemblance='Unknown',
      tools_detected=[],
      confidence=0.1,
      summary='Insufficient data for profiling. Monitoring continues.'
    )

  # Build a concise action log for the prompt
  action_log = '\n'.join([
    f'[{a.action_type}] → {a.target_node_id}: {a.detail} (MITRE: {a.mitre_technique_id or "untagged"})'
    for a in actions[-20:]  # last 20 actions
  ])

  user_msg = f'''Attacker IP: {attacker_ip}
Total actions observed: {len(actions)}
Recent action log:
{action_log}
Profile this attacker.'''

  response = await groq_client.chat.completions.create(
    model='llama-3.3-70b-versatile',
    messages=[
      {'role': 'system', 'content': SYSTEM_PROMPT},
      {'role': 'user', 'content': user_msg}
    ],
    max_tokens=400,
    temperature=0.3,
  )

  raw = response.choices[0].message.content.strip()
  # Strip any accidental markdown fences
  if raw.startswith('```'):
    raw = raw.split('```')[1]
    if raw.startswith('json'):
      raw = raw[4:]
  data = json.loads(raw)
  return AttackerProfile(attacker_ip=attacker_ip, **data)

IMPORTANT: wrap the json.loads call in try/except — if Groq returns malformed JSON,
log the error and return a fallback AttackerProfile with confidence=0.0 and
summary='AI profiling error — raw response logged.'"
```
**Commit:** `feat(ai): groq llm attacker profiler with json parsing and fallback`

---

### Task 3.3 — MITRE ATT&CK mapper
```
Prompt to AI:
"Create backend/mitre/mapper.py.

Import: mitreattack.stix20.MitreAttackData, pathlib, re

MITRE_JSON_PATH = pathlib.Path(__file__).parent / 'enterprise-attack.json'

class MitreMapper:
  def __init__(self):
    self.attack_data = MitreAttackData(str(MITRE_JSON_PATH))
    self._technique_cache = {}  # technique_id → { name, tactic, description_short }
    self._build_cache()

  def _build_cache(self):
    techniques = self.attack_data.get_techniques(remove_revoked_deprecated=True)
    for t in techniques:
      tid = t.get('external_references', [{}])[0].get('external_id', '')
      name = t.get('name', '')
      tactics = [phase['phase_name'] for phase in t.get('kill_chain_phases', [])]
      desc = t.get('description', '')[:120]  # first 120 chars
      self._technique_cache[tid] = { 'name': name, 'tactic': tactics[0] if tactics else 'unknown', 'description': desc }

  def tag_action(self, action_type: str, detail: str) → dict | None:
    # Rule-based mapping — deterministic, fast, no LLM needed for this
    ACTION_MAP = {
      'port_scan':      ('T1046', 'Network Service Discovery'),
      'login_attempt':  ('T1110', 'Brute Force'),
      'command_exec':   ('T1059', 'Command and Scripting Interpreter'),
      'data_access':    ('T1005', 'Data from Local System'),
      'lateral_move':   ('T1021', 'Remote Services'),
      'file_access':    ('T1083', 'File and Directory Discovery'),
      'credential':     ('T1078', 'Valid Accounts'),
    }
    # Check detail string for keyword hints too
    detail_lower = detail.lower()
    if 'ssh' in detail_lower or 'rdp' in detail_lower:
      tid, name = 'T1021', 'Remote Services'
    elif 'password' in detail_lower or 'auth' in detail_lower or 'login' in detail_lower:
      tid, name = 'T1110', 'Brute Force'
    elif 'nmap' in detail_lower or 'scan' in detail_lower:
      tid, name = 'T1046', 'Network Service Discovery'
    else:
      result = ACTION_MAP.get(action_type)
      if not result:
        return None
      tid, name = result
    cached = self._technique_cache.get(tid)
    if not cached:
      return None
    return { 'technique_id': tid, 'technique_name': cached['name'], 'tactic': cached['tactic'] }

mitre_mapper = MitreMapper()  # singleton — load once at startup"
```
**Commit:** `feat(mitre): att&ck mapper with cached technique lookup and rule-based tagging`

---

### Task 3.4 — Topology mutation engine
```
Prompt to AI:
"Create backend/ai/mutator.py.

Import: asyncio, time
From other modules: topology.generate_topology, socket io sio instance,
  routes.current_topology, EVENTS

FINGERPRINT_PATTERNS = [
  'timing_probe', 'ttl_analysis', 'banner_comparison',
  'port_timing', 'os_fingerprint', 'syn_probe'
]

async def detect_fingerprinting(action: AttackerAction) → bool:
  Detect if an attacker is trying to fingerprint (test if servers are real).
  Return True if:
    action.action_type == 'port_scan' AND the scan hit >12 ports in one action
    OR detail string contains any keyword from FINGERPRINT_PATTERNS
    OR action.detail contains 'timing' or 'fingerprint' or '-O' (nmap OS detection)

async def trigger_mutation(sio, current_generation: int) → TopologySnapshot:
  Step 1: Emit EVENTS.TOPOLOGY_MUTATING to all clients (frontend starts fog animation)
  Step 2: await asyncio.sleep(1.5) — let animation play
  Step 3: new_topology = await topology.mutate_topology(current_generation)
  Step 4: Emit EVENTS.TOPOLOGY_UPDATE with new_topology dict to all clients
  Step 5: Emit EVENTS.ALERT { message: 'Topology reshuffled — attacker lost their map', severity: 'info' }
  Step 6: return new_topology

Call detect_fingerprinting() from the POST /api/attacker/action route.
If it returns True, call trigger_mutation() and update routes.current_topology."
```
**Commit:** `feat(ai): topology mutation engine with fingerprint detection trigger`

---

### Task 3.5 — Adaptive lure generation
```
Prompt to AI:
"Create backend/ai/lure_generator.py.

This module reads the attacker's Groq profile and automatically spawns a more targeted
fake container designed to match what the attacker is hunting for.

Import: asyncio, random
From models: AttackerProfile, NetworkNode, TopologySnapshot
From deception.container_manager: spawn_container
From events: EVENTS

OBJECTIVE_TO_LURE = {
  'credential harvesting': {
    node_type: 'auth_service',
    label: 'Corporate SSO / Active Directory',
    hint: 'Spawning fake AD — attacker is hunting credentials'
  },
  'financial data': {
    node_type: 'db_server',
    label: 'Finance DB — Q3 payroll and transactions',
    hint: 'Spawning fake finance DB — attacker targeting financial data'
  },
  'intellectual property': {
    node_type: 'file_server',
    label: 'Engineering file share — R&D documents',
    hint: 'Spawning fake file server — attacker targeting IP'
  },
  'espionage': {
    node_type: 'api_gateway',
    label: 'Internal comms API — email + calendar',
    hint: 'Spawning fake API gateway — attacker targeting comms'
  },
}

async def maybe_spawn_lure(
  profile: AttackerProfile,
  current_topology: TopologySnapshot,
  sio,
  generation: int
) → NetworkNode | None:
  Determine if a lure should be spawned based on objective keyword matching.
  Match profile.objective.lower() against OBJECTIVE_TO_LURE keys using substring search.
  If no match found: return None (don't spam lures).

  # Deduplicate: don't spawn same lure type twice
  existing_types = [n.node_type for n in current_topology.nodes]
  lure_config = matched result from OBJECTIVE_TO_LURE
  if existing_types.count(lure_config['node_type']) >= 2:
    return None  # already enough of this type

  # Build a new NetworkNode for the lure
  from ipaddress import IPv4Network
  import random
  subnet = IPv4Network('172.20.0.0/24')
  available = [str(h) for h in subnet.hosts()][30:]  # use upper range for lures
  lure_node = NetworkNode(
    node_id=f'lure_{generation}_{random.randint(100,999)}',
    ip=random.choice(available),
    node_type=lure_config['node_type'],
    ports=[443, 8443],
    banner=f'Adaptive Lure — {lure_config[\"label\"]}',
    os='Ubuntu 22.04',
    is_fake=True,
  )

  # Spawn the container
  cid = await spawn_container(lure_node)
  if cid:
    lure_node = lure_node.model_copy(update={'container_id': cid})
    await sio.emit(EVENTS['LURE_SPAWNED'], {
      'node_id': lure_node.node_id,
      'node_type': lure_node.node_type,
      'label': lure_config['label'],
      'hint': lure_config['hint'],
    })
    await sio.emit(EVENTS['ALERT'], {
      'message': f'Adaptive lure deployed: {lure_config[\"hint\"]}',
      'severity': 'info'
    })
  return lure_node

Call maybe_spawn_lure() from backend/api/routes.py inside the profile update block
(after every Groq profile refresh), passing the updated profile and current topology."
```
**Commit:** `feat(ai): adaptive lure generator — spawns targeted fake services based on attacker objective`

---
> **T4 — Hour 2 to 8**
> Goal: Fake SSH, HTTP, DB containers buildable and runnable. Neo4j schema initialized. docker-compose working end-to-end.

### Task 4.1 — Fake SSH honeypot container
```
Prompt to AI:
"Create docker/fake-ssh/Dockerfile and docker/fake-ssh/server.py.

A Python paramiko-based fake SSH server that:
  - Listens on port 22 inside the container (mapped to a dynamic host port)
  - Accepts ANY username/password combination (always 'succeeds' after a realistic 800ms delay)
  - After login, drops the attacker into a fake bash shell that:
      Responds to: ls, pwd, whoami, id, cat /etc/passwd, uname -a, ps aux, netstat -an, history
      Each command returns realistic-looking but fake output
      ls → 'Documents  Downloads  .ssh  .bash_history  financial_reports  employee_data'
      whoami → 'admin'
      cat /etc/passwd → a realistic /etc/passwd with 20 fake users
      uname -a → 'Linux db-prod-01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 GNU/Linux'
      Any other command → 'bash: [command]: command not found'
  - For EVERY interaction (login attempt, command), POSTs to http://backend:8000/api/attacker/action
    with { attacker_ip, action_type, target_node_id, detail, timestamp }
  - target_node_id comes from NODE_ID environment variable (set when container is spawned)
  - Never actually executes any real system command — all responses are hardcoded strings

Dockerfile: FROM python:3.11-slim, pip install paramiko requests, COPY server.py, CMD python server.py
ENV variables: NODE_ID, ATTACKER_CALLBACK_URL (= http://backend:8000)"
```
**Commit:** `feat(docker): fake ssh honeypot with paramiko and backend callback`

---

### Task 4.2 — Fake HTTP, DB, API, and Auth containers
```
Prompt to AI:
"Create four Flask-based fake service containers:

--- docker/fake-http/server.py (port 80) ---
Mimics an internal employee web app.
  GET /          → HTML 'Internal Employee Portal — Login Required'
  GET /api/      → JSON { version: '2.3.1', endpoints: ['/api/users', '/api/reports', '/api/config'] }
  GET /api/users → JSON list of 8 fake employees with name, role, email @corp.internal
  GET /api/config → JSON { db_host: '172.20.0.12', db_port: 3306, environment: 'production', debug: false }
  POST /api/login → always { success: false, error: 'Invalid credentials' } after 600ms
  Any other route → 404 realistic nginx HTML
  Server header: 'Apache/2.4.41 (Ubuntu)', X-Powered-By: 'PHP/7.4.33'
  ALL requests: POST callback to /api/attacker/action with action_type='data_access'

--- docker/fake-db/server.py (port 3306 via HTTP) ---
Mimics phpMyAdmin / MySQL admin.
  GET /       → fake phpMyAdmin login HTML
  POST /login → 401 after 400ms, logs credential attempt
  GET /tables → JSON ['users', 'transactions', 'employee_payroll', 'audit_log', 'customer_pii']
  GET /dump   → JSON with 10 rows of realistic-looking fake employee_payroll data
  Server header: 'nginx/1.14.0', mimics MySQL 8.0.28
  ALL requests: POST callback, action_type='data_access'

--- docker/fake-api/server.py (port 8443) ---
Mimics an internal REST API gateway (think internal microservices).
  GET  /v1/health     → { status: 'ok', version: '3.1.4', env: 'production' }
  GET  /v1/services   → JSON list of 6 fake internal service names with endpoints
  GET  /v1/tokens     → JSON { api_key: 'sk-prod-a7f3...REDACTED', expires: '2025-12-31' }
                         (fake token — fires credential_stolen alert when accessed)
  GET  /v1/employees  → JSON list of 15 fake employees with SSN, salary fields (all fake)
  POST /v1/auth/token → always { error: 'unauthorized' } after 300ms
  Server header: 'nginx/1.18.0', X-API-Version: '3.1.4'
  ALL requests: POST callback, action_type='data_access'
  NOTE: GET /v1/tokens specifically POSTs with action_type='credential_theft'

--- docker/fake-auth/server.py (port 389 via HTTP — LDAP-style) ---
Mimics a corporate LDAP / SSO / Active Directory endpoint.
  GET  /ldap/search?cn=* → XML response with 20 fake AD users, their groups, and
                            fake password hashes (bcrypt-style strings, not real)
  POST /ldap/bind         → { result: 'invalidCredentials', code: 49 } — standard LDAP error
  GET  /sso/metadata      → fake SAML XML metadata with org name 'Corp Internal SSO'
  POST /sso/login         → redirect to fake login page, logs credential attempt
  Server header: mimics Microsoft-IIS/10.0
  ALL requests: POST callback, action_type='login_attempt'

All four Dockerfiles: FROM python:3.11-slim, pip install flask requests, COPY server.py,
  CMD python server.py
ENV for all: NODE_ID, ATTACKER_CALLBACK_URL"
```
**Commit:** `feat(docker): four distinct fake service honeypots — http, db, api, auth`

---

### Task 4.3 — Docker container manager
```
Prompt to AI:
"Create backend/deception/container_manager.py.

Import: docker, asyncio, os
docker_client = docker.from_env()

CONTAINER_IMAGES = {
  'web_server':   'shadowmesh-fake-http',
  'db_server':    'shadowmesh-fake-db',
  'auth_service': 'shadowmesh-fake-auth',
  'file_server':  'shadowmesh-fake-http',
  'api_gateway':  'shadowmesh-fake-api',
  'mail_server':  'shadowmesh-fake-http',
  'workstation':  'shadowmesh-fake-http',
}

active_containers: dict[str, str] = {}  # node_id → container_id

async def spawn_container(node: NetworkNode) → str | None:
  image = CONTAINER_IMAGES.get(node.node_type)
  if not image:
    return None
  try:
    container = docker_client.containers.run(
      image,
      detach=True,
      environment={
        'NODE_ID': node.node_id,
        'ATTACKER_CALLBACK_URL': 'http://host.docker.internal:8000'
      },
      network='shadowmesh_deception_net',
      hostname=f'fake-{node.node_type}-{node.node_id[-4:]}',
      name=f'sm_{node.node_id}',
      remove=True,  # auto-remove on stop
      mem_limit='64m',
      cpu_period=100000,
      cpu_quota=25000,  # 25% max CPU per container
      security_opt=['no-new-privileges:true'],
      cap_drop=['ALL'],
    )
    active_containers[node.node_id] = container.id
    return container.id
  except Exception as e:
    print(f'Container spawn failed for {node.node_id}: {e}')
    return None

async def teardown_all():
  for node_id, container_id in list(active_containers.items()):
    try:
      c = docker_client.containers.get(container_id)
      c.stop(timeout=2)
    except:
      pass
  active_containers.clear()

async def spawn_topology(topology: TopologySnapshot, sio):
  await teardown_all()
  for node in topology.nodes:
    cid = await spawn_container(node)
    if cid:
      topology.nodes[topology.nodes.index(node)] = node.model_copy(update={'container_id': cid})
      await sio.emit('container_spawned', {'node_id': node.node_id, 'node_type': node.node_type})"
```
**Commit:** `feat(deception): docker container manager — spawn, teardown, resource limits`

---

### Task 4.4 — Neo4j schema initialization + health check
```
Prompt to AI:
"Update backend/database/neo4j_client.py (from Task 1.3).
Add an async health_check() method:
  Runs RETURN 1 AS n, returns True if successful, False on any error.
  Used by GET /health endpoint.

Add async def seed_demo_data():
  Only called if the DB is empty (check node count == 0).
  Creates a sample Attacker node with ip='192.168.1.100' and
  one connected Node { node_id: 'node_demo', node_type: 'web_server' }
  with a PERFORMED relationship { action_type: 'port_scan', timestamp: current epoch }.
  This ensures the attack graph panel has something to show on first launch.

Update FastAPI lifespan startup:
  1. await neo4j_client.init_schema()
  2. healthy = await neo4j_client.health_check()
  3. if healthy: await neo4j_client.seed_demo_data()
  4. print with emoji: '✅ Neo4j connected' or '❌ Neo4j connection failed'

Also update GET /health to call health_check() and report:
  { status: 'ok', neo4j: bool, mitre_loaded: bool, active_containers: int }"
```
**Commit:** `feat(backend): neo4j health check, schema init, and demo seed data`

---

### Task 4.5 — Fake credential generator
```
Prompt to AI:
"Create backend/deception/credentials.py.

This module generates fake credential files and plants them inside fake containers.
When the attacker downloads them, the container POSTs a callback to fire alerts.

Import: uuid, time, os, random

CREDENTIAL_TEMPLATES = {
  'env_file': {
    'filename': '.env',
    'template': '''
DB_HOST=172.20.0.12
DB_PORT=3306
DB_USER=prod_admin
DB_PASSWORD=Sup3rS3cur3!2024
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SECRET=hs256-prod-secret-do-not-share
STRIPE_SECRET_KEY=[REDACTED]
'''
  },
  'aws_key': {
    'filename': 'credentials.csv',
    'template': 'User Name,Access key ID,Secret access key\nprod-admin,[REDACTED],[REDACTED]\n'
  },
  'ssh_key': {
    'filename': 'id_rsa',
    'template': '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA' + 'A' * 800 + '\n-----END RSA PRIVATE KEY-----\n'
  },
  'db_password': {
    'filename': 'db_credentials.txt',
    'template': 'Production DB Credentials\nHost: 172.20.0.12\nUser: root\nPassword: Pr0d@2024!\nDatabase: corp_main\n'
  },
}

class CredentialManager:
  def __init__(self):
    self._credentials: dict[str, FakeCredential] = {}  # cred_id → FakeCredential

  def generate_for_node(self, node_id: str) → list[FakeCredential]:
    Pick 2 random credential types for this node.
    For each:
      cred_id = f'cred_{node_id}_{uuid.uuid4().hex[:8]}'
      cred_type = chosen type key
      template = CREDENTIAL_TEMPLATES[cred_type]
      cred = FakeCredential(
        cred_id=cred_id,
        node_id=node_id,
        cred_type=cred_type,
        filename=template['filename'],
        content=template['template'],
      )
      self._credentials[cred_id] = cred
    Return the list.

  def get_credential(self, cred_id: str) → FakeCredential | None:
    return self._credentials.get(cred_id)

  def mark_accessed(self, cred_id: str) → FakeCredential | None:
    cred = self._credentials.get(cred_id)
    if cred:
      cred.accessed = True
      cred.accessed_at = time.time()
    return cred

  def get_all_for_node(self, node_id: str) → list[FakeCredential]:
    return [c for c in self._credentials.values() if c.node_id == node_id]

cred_manager = CredentialManager()  # singleton

Add a FastAPI route GET /api/creds/{node_id}/{cred_id} that:
  1. Returns the credential content as plain text (application/octet-stream)
     so it looks like a real file download
  2. Calls cred_manager.mark_accessed(cred_id)
  3. Emits EVENTS.CREDENTIAL_STOLEN via Socket.IO with { cred_id, filename, cred_type, attacker_ip }
     (attacker_ip from request headers X-Forwarded-For or request.client.host)
  4. Calls alerting.slack.alert_credential_stolen(attacker_ip, filename, cred_type)
  5. Logs AttackerAction with action_type='credential_theft'

Update fake containers (fake-http, fake-api) to include links to these credential files:
  In fake-http GET /api/config, add: backup_config_url: '/api/creds/{node_id}/env_file'
  In fake-api GET /v1/tokens, serve from /api/creds/{node_id}/aws_key instead of inline"
```
**Commit:** `feat(deception): fake credential generator with download endpoint and theft alerts`

---

### Task 4.6 — Canary tokens
```
Prompt to AI:
"Create backend/deception/canary.py.

Canary tokens are fake URLs planted inside fake documents and API responses.
When an attacker visits the URL (e.g. in a browser or curl), it fires an alert.
This is a lightweight implementation — no external service needed.

Import: uuid, time, pathlib

class CanaryManager:
  def __init__(self):
    self._tokens: dict[str, CanaryToken] = {}  # token_id → CanaryToken

  def generate_for_node(self, node_id: str, count: int = 2) → list[CanaryToken]:
    Generate count canary tokens for a node.
    Token types and labels:
      'document': label='Q3_Financial_Report.pdf', description='embedded in fake file server'
      'url':      label='Internal Wiki — Credentials Page', description='linked in fake HTTP response'
    For each:
      token_id = uuid.uuid4().hex
      token_url = f'/api/canary/{token_id}'   # served by FastAPI
      token = CanaryToken(
        token_id=token_id,
        node_id=node_id,
        token_url=token_url,
        token_type=chosen_type,
        label=chosen_label,
      )
      self._tokens[token_id] = token
    Return list.

  def get_token(self, token_id: str) → CanaryToken | None:
    return self._tokens.get(token_id)

  def mark_triggered(self, token_id: str, triggered_by_ip: str) → CanaryToken | None:
    token = self._tokens.get(token_id)
    if token and not token.triggered:
      token.triggered = True
      token.triggered_at = time.time()
      token.triggered_by_ip = triggered_by_ip
    return token

  def get_all_for_node(self, node_id: str) → list[CanaryToken]:
    return [t for t in self._tokens.values() if t.node_id == node_id]

canary_manager = CanaryManager()  # singleton

Add FastAPI route GET /api/canary/{token_id}:
  1. Get token = canary_manager.get_token(token_id)
  2. If not found → return 404
  3. attacker_ip = request.client.host or X-Forwarded-For header
  4. canary_manager.mark_triggered(token_id, attacker_ip)
  5. Emit EVENTS.CANARY_TRIGGERED via Socket.IO:
     { token_id, label: token.label, node_id: token.node_id, triggered_by_ip: attacker_ip }
  6. Call alerting.slack.alert_canary_triggered(attacker_ip, token.label, token.node_id)
  7. Log AttackerAction: action_type='canary_trigger', detail=f'Canary accessed: {token.label}'
  8. Return a realistic HTTP 200 response — a fake HTML page or PDF placeholder
     so the attacker doesn't immediately know they triggered an alert:
     HTML: '<html><body>403 Forbidden — Access Denied</body></html>' with 403 status

Integrate canary URLs into fake containers:
  In fake-http GET /api/users, append a field: internal_wiki_url pointing to a canary /api/canary/{id}
  In fake-api GET /v1/employees, include a note_url for each employee pointing to a canary

Call canary_manager.generate_for_node(node.node_id) and
  cred_manager.generate_for_node(node.node_id) from container_manager.spawn_topology()
  after each container is successfully spawned."
```
**Commit:** `feat(deception): canary token system — planted URLs with silent alert on access`

---
> **T2 — Hour 6 to 10** (after Phase 1 is stable)
> Goal: Real port scan detection running as a background thread, emitting Socket.IO events.

### Task 5.1 — Scapy port scan detector
```
Prompt to AI:
"Create backend/detection/scanner.py.

Import: scapy.all (Ether, IP, TCP, UDP, sniff), threading, time, asyncio, collections

SCAN_WINDOW_SECONDS = 10
SCAN_THRESHOLD_PORTS = 5   # >5 unique ports from same IP in 10s = port scan
LATERAL_THRESHOLD = 3      # >3 unique target IPs from same IP = lateral movement

class ReconDetector:
  def __init__(self, interface: str, callback):
    self.interface = interface
    self.callback = callback  # async function: async def on_event(scan_event: ScanEvent)
    self._port_hits: dict[str, list[tuple[int, float]]] = defaultdict(list)  # src_ip → [(port, timestamp)]
    self._target_hits: dict[str, list[tuple[str, float]]] = defaultdict(list) # src_ip → [(dst_ip, timestamp)]
    self._alerted_ips: set[str] = set()  # IPs already flagged to avoid spam
    self._running = False
    self._loop = None

  def _packet_handler(self, packet):
    if not (IP in packet and TCP in packet):
      return
    src_ip = packet[IP].src
    dst_port = packet[TCP].dport
    dst_ip = packet[IP].dst

    # Skip loopback and Docker internal
    if src_ip.startswith('127.') or src_ip.startswith('172.17.'):
      return

    now = time.time()

    # Track port hits per source IP
    self._port_hits[src_ip].append((dst_port, now))
    # Prune old hits outside window
    self._port_hits[src_ip] = [(p, t) for p, t in self._port_hits[src_ip] if now - t < SCAN_WINDOW_SECONDS]

    # Track lateral movement (unique targets)
    self._target_hits[src_ip].append((dst_ip, now))
    self._target_hits[src_ip] = [(d, t) for d, t in self._target_hits[src_ip] if now - t < SCAN_WINDOW_SECONDS]

    unique_ports = len(set(p for p, _ in self._port_hits[src_ip]))
    unique_targets = len(set(d for d, _ in self._target_hits[src_ip]))

    if unique_ports >= SCAN_THRESHOLD_PORTS and src_ip not in self._alerted_ips:
      self._alerted_ips.add(src_ip)
      scan_type = 'lateral_movement' if unique_targets >= LATERAL_THRESHOLD else 'port_scan'
      event = ScanEvent(
        source_ip=src_ip,
        scan_type=scan_type,
        ports_hit=list(set(p for p, _ in self._port_hits[src_ip])),
        timestamp=now
      )
      # Schedule the async callback safely from this sync thread
      asyncio.run_coroutine_threadsafe(self.callback(event), self._loop)

  def start(self, loop: asyncio.AbstractEventLoop):
    self._loop = loop
    self._running = True
    thread = threading.Thread(
      target=lambda: sniff(iface=self.interface, prn=self._packet_handler,
                           store=False, stop_filter=lambda _: not self._running),
      daemon=True
    )
    thread.start()
    print(f'🔍 Scapy detector listening on {self.interface}')

  def stop(self):
    self._running = False"
```
**Commit:** `feat(detection): scapy recon detector — port scan + lateral movement`

---

### Task 5.2 — Wire detector into FastAPI lifespan
```
Prompt to AI:
"Update backend/main.py lifespan to start the Scapy detector.

In the startup section:
  from detection.scanner import ReconDetector
  import asyncio, os

  async def on_recon_detected(scan_event: ScanEvent):
    # Emit to all connected frontend clients
    await sio.emit(EVENTS['RECON_DETECTED'], scan_event.model_dump())
    # Activate deception if not already active
    from api.routes import current_topology, attacker_profiles
    if scan_event.source_ip not in attacker_profiles:
      # Generate fresh topology
      new_topology = await topology.generate_topology(generation=0)
      await routes.set_topology(new_topology)
      await sio.emit(EVENTS['TOPOLOGY_UPDATE'], new_topology.model_dump())
      # Spawn containers (run in background, don't block)
      asyncio.create_task(container_manager.spawn_topology(new_topology, sio))
      await sio.emit(EVENTS['ALERT'], {
        'message': f'Recon detected from {scan_event.source_ip} — deception fabric activated',
        'severity': 'critical'
      })
    # Log to Neo4j
    await neo4j_client.create_attacker(scan_event.source_ip)

  interface = os.getenv('NETWORK_INTERFACE', 'eth0')
  detector = ReconDetector(interface=interface, callback=on_recon_detected)
  loop = asyncio.get_event_loop()
  detector.start(loop)

In the shutdown section:
  detector.stop()
  await container_manager.teardown_all()
  await neo4j_client.close()"
```
**Commit:** `feat(backend): wire scapy detector into fastapi lifespan with auto-deception`

---

### Task 5.3 — Demo attacker simulator script
```
Prompt to AI:
"Create scripts/simulate_attacker.py.
This is the script run DURING THE DEMO to trigger the whole system.
It should be realistic and cinematic — not instant.

Steps (with realistic delays):
  1. Print '[ ShadowMesh Demo — Simulated APT Attack ]' header
  2. Phase 1 — Port Scan (5 seconds):
     Use Python socket to attempt connections to ports [22, 80, 443, 3306, 5432, 8080, 445, 3389, 25, 389]
     on target subnet 172.20.0.x (try .10 through .20)
     Print each attempt: 'Scanning 172.20.0.12:443 ...'
     Sleep 0.2s between each
  3. Phase 2 — Service Probe (3 seconds):
     POST http://localhost:8000/api/attacker/action with action_type='port_scan',
       detail='nmap -sV -O scan detected — 11 ports across 4 hosts', attacker_ip='192.168.1.100'
  4. Sleep 3s ('Attacker mapping network...')
  5. Phase 3 — Login Attempt:
     POST /api/attacker/action: action_type='login_attempt', detail='SSH brute force: admin/password123'
     Print 'Attempting SSH login to 172.20.0.14...'
  6. Sleep 2s
  7. Phase 4 — Command Execution:
     POST /api/attacker/action: action_type='command_exec', detail='exec: cat /etc/passwd'
     POST /api/attacker/action: action_type='command_exec', detail='exec: ls -la /home/admin'
  8. Sleep 2s
  9. Phase 5 — Credential Theft:
     GET http://localhost:8000/api/creds/{first_node_id}/env_file (triggers credential_stolen)
     Print 'Found .env file — downloading...'
     Print first 200 chars of response
     Sleep 1s
  10. Phase 6 — Canary Trigger:
     GET http://localhost:8000/api/users (triggers internal_wiki_url link)
     Parse response for a canary URL and GET it (triggers canary_triggered)
     Print 'Following internal wiki link...'
     Sleep 2s
  11. Phase 7 — Fingerprinting Attempt (triggers mutation):
     POST /api/attacker/action: action_type='port_scan', detail='os fingerprint probe — TTL timing analysis'
     Print 'Attacker running OS fingerprinting...'
  12. Sleep 4s (mutation happens)
  13. Phase 8 — Lateral Movement:
     POST /api/attacker/action: action_type='lateral_move', detail='RDP attempt to 172.20.0.18'

Run as: python scripts/simulate_attacker.py
Accept --target-ip flag (default 192.168.1.100)
Accept --backend-url flag (default http://localhost:8000)"
```
**Commit:** `feat(scripts): cinematic demo attacker simulator`

---

## Phase 6 — Integration Sprint
> **ALL 4 PEOPLE — Hour 10 to 16**
> Goal: Every component talking to every other. End-to-end flow works once.

### Task 6.1 — Wire profiler into action route
```
Prompt to AI:
"Update backend/api/routes.py POST /api/attacker/action handler.

After saving the action to Neo4j:
  1. Tag with MITRE: mitre_result = mitre_mapper.tag_action(action.action_type, action.detail)
     If tagged: update action.mitre_technique_id and action.mitre_technique_name
     Emit EVENTS.MITRE_TAG: { technique_id, technique_name, tactic, attacker_ip }
  2. Append action to in-memory list: attacker_actions[action.attacker_ip].append(action)
     (attacker_actions is a defaultdict(list) at module level)
  3. Profile if enough actions (every 3 new actions):
     actions_for_ip = attacker_actions[action.attacker_ip]
     if len(actions_for_ip) % 3 == 0:
       profile = await profiler.profile_attacker(action.attacker_ip, actions_for_ip)
       attacker_profiles[action.attacker_ip] = profile
       await sio.emit(EVENTS['PROFILE_UPDATE'], profile.model_dump())
       # Try to spawn an adaptive lure based on updated profile
       lure_node = await lure_generator.maybe_spawn_lure(profile, current_topology, sio, current_topology.generation)
       if lure_node:
         current_topology.nodes.append(lure_node)
  4. Check for fingerprinting and trigger mutation if detected:
     if await mutator.detect_fingerprinting(action):
       new_topology = await mutator.trigger_mutation(sio, current_topology.generation)
       update current_topology = new_topology
       asyncio.create_task(alerting.slack.alert_topology_mutated(new_topology.generation))
  5. Emit EVENTS.ATTACKER_ACTION with the (now MITRE-tagged) action to all clients"
```
**Commit:** `feat(backend): wire mitre tagging + groq profiling into action route`

---

### Task 6.2 — NetworkGraph component (react-force-graph-2d)
```
Prompt to AI:
"Create frontend/src/components/NetworkGraph.jsx.
Uses react-force-graph-2d for the live topology visualization.
Reads nodes and edges from Zustand store (useShadowStore).

Setup:
  import ForceGraph2D from 'react-force-graph-2d'
  import { useShadowStore } from '../store/useShadowStore'
  import { useRef, useEffect } from 'react'

Data transform for ForceGraph2D:
  graphData = {
    nodes: nodes.map(n => ({
      id: n.node_id,
      ip: n.ip,
      nodeType: n.node_type,
      ports: n.ports,
      banner: n.banner,
    })),
    links: edges.map(([src, tgt]) => ({ source: src, target: tgt }))
  }

Node rendering (nodeCanvasObject):
  Draw a circle — color by node type:
    web_server: #1D9E75 (green), db_server: #E24B4A (red),
    auth_service: #7F77DD (purple), file_server: #EF9F27 (amber),
    api_gateway: #378ADD (blue), mail_server: #D4537E (pink), workstation: #888780 (gray)
  Radius: 8px, with a 2px glow effect when the node has been hit by the attacker
    (check if any action targets this node_id)
  Draw IP address in white 9px below the circle

isMutating state:
  When true (from store), apply a CSS class that makes the entire graph container
  blur and opacity-50 for 2 seconds, then snap back.
  Use framer-motion on the wrapper div:
    animate={{ filter: isMutating ? 'blur(4px)' : 'blur(0px)', opacity: isMutating ? 0.4 : 1 }}
    transition={{ duration: 0.3 }}

ForceGraph2D props:
  backgroundColor='#0d0d0d'
  linkColor='#2a2a2a'
  linkWidth={1}
  d3AlphaDecay={0.02}  (slower settling for smoother animation)
  cooldownTicks={150}
  nodePointerAreaPaint: paint larger hit area so nodes are easy to click
  onNodeClick: show a tooltip/panel with node details (ip, ports, banner, os)

Wrap in a div with className='w-full h-full' — ForceGraph fills it."
```
**Commit:** `feat(frontend): react-force-graph-2d live topology with node coloring and mutation blur`

---

### Task 6.3 — MITRE ATT&CK heatmap (D3.js)
```
Prompt to AI:
"Create frontend/src/components/MitreHeatmap.jsx using D3.js.
Reads mitreTechniques from Zustand store: { [technique_id]: { name, count, tactic } }

Layout: a compact grid of technique cells, one per detected technique.
  Cell size: 48x28px, arranged in a flex-wrap grid.
  Cell background: scales from #1a1a1a (zero hits) → #7F77DD (low) → #E24B4A (high hits)
  Use d3.scaleSequential([0, maxCount], d3.interpolateRgb('#2a2a2a', '#E24B4A'))
  Cell text: technique ID (e.g. T1046) in 10px white bold
  Tooltip on hover: show full technique name and tactic

When a new technique is added (count goes from 0 to 1):
  Animate the cell flashing bright white → its color using CSS @keyframes flash (0.6s)

Tactic header rows (group cells by tactic):
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Exfiltration', 'Command and Control', 'Impact'
  Header: text-[10px] text-gray-500 uppercase mb-1 mt-2

Empty state: 'No TTPs detected yet' gray italic

Section header: 'MITRE ATT&CK' + technique count badge"
```
**Commit:** `feat(frontend): d3 mitre att&ck heatmap with tactic grouping and flash animation`

---

### Task 6.4 — AttackerProfile panel
```
Prompt to AI:
"Create frontend/src/components/AttackerProfile.jsx.
Reads attackerProfile from Zustand store (null when no attacker profiled yet).

When null:
  Show a gray animated scanning indicator:
  'Behavioral analysis pending...' with a pulsing dot

When profile exists, show:
  Top: Attacker IP in monospace, bold, white
  Skill Level badge — color coded:
    'Script Kiddie' → green, 'Intermediate' → amber,
    'Advanced' → orange, 'Nation-State APT' → red (pulsing border)
  APT Resemblance: small purple badge with the APT name
  Confidence: thin horizontal bar (0–100%, color from red to green)
  Objective: italic text, gray-200, 13px
  Tools Detected: flex-wrap row of monospace tags (e.g. 'nmap', 'hydra')
  Summary: text-sm text-gray-300, line-height 1.6

Animate the entire panel appearing with framer-motion:
  initial: { opacity: 0, y: 8 }
  animate: { opacity: 1, y: 0 }
  transition: { duration: 0.4 }

When profile updates (new Groq response), animate just the changed fields
  using a key prop change to trigger re-mount animation."
```
**Commit:** `feat(frontend): attacker profile panel with groq data and skill level badges`

---

## Phase 7 — Dashboard Polish: The WOW Moment
> **Dealer — Hour 16 to 20**
> Goal: The demo looks cinematic. Every animation is tight. The topology reshuffle is the money shot.

### Task 7.1 — Demo trigger controls
```
Prompt to AI:
"Add a Demo Control Bar to Dashboard.jsx.
Only visible in development (import.meta.env.DEV).
Fixed position, bottom-center, semi-transparent dark background.

Three buttons:
  1. '⚡ Trigger Scan' — emits EVENTS.TRIGGER_SCAN via socket to backend
  2. '🔑 Simulate Login' — emits EVENTS.TRIGGER_LOGIN
  3. '🌫 Trigger Mutation' — emits EVENTS.TRIGGER_MUTATE

Backend socket handlers for these (add to main.py):
  @sio.on(EVENTS.TRIGGER_SCAN)
  → Create a fake ScanEvent with source_ip='192.168.1.100' and call on_recon_detected()

  @sio.on(EVENTS.TRIGGER_LOGIN)
  → POST internally to /api/attacker/action with action_type='login_attempt',
    detail='SSH brute force: root/admin123', attacker_ip='192.168.1.100',
    target_node_id = first node in current_topology.nodes

  @sio.on(EVENTS.TRIGGER_MUTATE)
  → Call mutator.trigger_mutation(sio, current_topology.generation)
    and update current_topology

Style buttons: bg-[#1a1a1a] border border-[#333] text-white text-sm px-4 py-2 rounded-lg
  hover:border-shadowGreen transition-colors"
```
**Commit:** `feat(frontend): demo control bar with socket-triggered attack simulation`

---

### Task 7.2 — Topology mutation fog animation
```
Prompt to AI:
"Make the topology reshuffle animation cinematic.
This is the most important visual moment in the demo.

In NetworkGraph.jsx, when isMutating becomes true:
  Phase 1 (0–400ms): Nodes start drifting — increase d3AlphaDecay to 0.5 so graph
    becomes chaotic/unstable. Apply blur filter to graph canvas (4px).
  Phase 2 (400–1200ms): Show a centered overlay text on the graph area:
    'TOPOLOGY RESHUFFLING' in red, monospace, blinking (CSS animation)
    with a scan-line effect (thin horizontal red line sweeping top to bottom)
  Phase 3 (1200–2200ms): New nodes snap in — graph restabilizes with new positions.
    Remove blur. Flash each new node white → their color.
  Phase 4 (done): Emit an alert 'Attacker reconnaissance invalidated — new topology online'

The scan-line overlay:
  A div absolutely positioned over the graph, pointer-events-none
  A 2px red horizontal line animated with CSS:
    @keyframes scanline { from { top: 0% } to { top: 100% } }
    animation: scanline 0.8s linear infinite during mutation

Implement using a combination of:
  framer-motion for blur/opacity transitions
  useEffect watching isMutating for the timing phases
  CSS keyframes injected via a style tag for the scanline"
```
**Commit:** `feat(frontend): cinematic topology mutation animation with scanline overlay`

---

### Task 7.3 — Final dashboard polish
```
Prompt to AI:
"Polish pass on the ShadowMesh dashboard.

1. Top status bar:
   When isDeceptionActive flips to true, animate it:
     Background transitions from transparent → rgba(226,75,74,0.1) (red glow)
     Status text does a typewriter effect: 'THREAT ACTIVE — DECEPTION FABRIC ONLINE'
     Use framer-motion layout animation on the pill

2. Connecting lines between panels:
   Show a thin 1px green line from AlertFeed items to the corresponding
   NetworkGraph node when the alert references a node_id (if applicable)
   (Skip if complex — fallback: just highlight the node in the graph when an alert is clicked)

3. Background grid:
   Subtle dark grid pattern on the main background (#0d0d0d with 1px lines every 40px, opacity 3%)
   CSS: background-image: linear-gradient(#ffffff05 1px, transparent 1px), linear-gradient(90deg, #ffffff05 1px, transparent 1px)
   background-size: 40px 40px

4. Terminal-style alert feed:
   Give AlertFeed a monospace font for the message text (font-mono)
   Prefix each alert with a timestamp and severity code:
   '[14:23:07] [CRIT] Recon detected from 192.168.1.100'

5. Node tooltip:
   When hovering a graph node, show a dark tooltip with:
   IP, node type, ports list, banner, OS, container_id (truncated)
   Positioned near cursor using onNodeHover prop"
```
**Commit:** `feat(frontend): dashboard polish — status animation, grid bg, monospace feed, tooltips`

---

## Phase 8 — Demo Hardening
> **ALL 4 PEOPLE — Hour 20 to 24**
> Goal: The demo works 10/10 times. No crashes. No awkward silences.

### Task 8.1 — End-to-end smoke test
```
Prompt to AI:
"Create scripts/smoke_test.py — a pre-demo checklist script.
Run this 1 hour before judging.

Tests (print ✅ or ❌ for each):
  1. GET http://localhost:8000/health → status: ok, neo4j: true, mitre_loaded: true
  2. Socket.IO connection test — connect, emit ping, assert pong within 2s
  3. POST /api/detect/scan with a fake ScanEvent — assert 200 + deception_activated
  4. GET /api/topology/current — assert node_count > 0
  5. POST /api/attacker/action (port_scan) — assert 200 + mitre_id in response
  6. POST /api/attacker/action x5 — assert profile endpoint returns 200
  7. GET http://localhost:5173 — assert 200 (frontend is up)
  8. Neo4j: run a simple query via neo4j_client.health_check()
  9. Docker: docker_client.ping() → True
  10. Canary: GET /api/canary/{any_token_id} — assert 403 response (canary fires correctly)
  11. Credential: GET /api/creds/{any_node_id}/{any_cred_id} — assert content returned
  12. Slack: if SLACK_WEBHOOK_URL set → POST test message, assert 200 from Slack

Print summary: 'X/12 checks passed. System ready.' or list failures."
```
**Commit:** `test: pre-demo smoke test script`

---

### Task 8.2 — Error boundaries + graceful fallbacks
```
Prompt to AI:
"Add error resilience to the frontend and backend.

Frontend — React Error Boundary:
  Create frontend/src/components/ErrorBoundary.jsx (class component).
  Wrap NetworkGraph, MitreHeatmap, AttackerProfile each in their own ErrorBoundary.
  On error: show a dark fallback card with the component name and 'Reconnecting...'
    with a spinning loader — never let one panel crash the whole dashboard.

Frontend — Socket.IO reconnect UI:
  In useSocketEvents, track socket.connected in local state.
  Show a toast at top of screen when disconnected: 'Backend connection lost — reconnecting'
  Remove toast when reconnected. Use framer-motion for the toast slide-in.

Backend — Global exception handler:
  In main.py, add FastAPI exception_handler for Exception:
    Log the error, return JSON { error: str(e) } with 500 status.
    Never crash the server on a bad request.

Backend — Groq API fallback:
  In profiler.py, if groq_client.chat.completions.create raises any exception
  (network error, rate limit, etc.) — catch it, return the low-confidence fallback profile.
  Log: 'Groq API error — using fallback profile: {error}'"
```
**Commit:** `feat: error boundaries, socket reconnect ui, backend exception handlers`

---

### Task 8.3 — Demo script + rehearsal notes
```
Prompt to AI:
"Create docs/DEMO_SCRIPT.md — the exact script for the 5-minute hackathon demo.

Format:

## ShadowMesh — 5 Minute Demo Script

### Setup (before judges arrive)
- [ ] docker-compose up -d (all services healthy)
- [ ] Frontend open at localhost:5173 on the presentation screen
- [ ] scripts/simulate_attacker.py ready in a terminal (not yet run)
- [ ] Neo4j Browser open at localhost:7474 (optional — shows graph DB if asked)
- [ ] .env has valid GROQ_API_KEY

### Minute 1 — The Problem (talking points, no typing)
Explain: 'Sophisticated attackers don't immediately steal data. They spend weeks
  mapping a network — and current defenses are blind to this phase.'
Show: dashboard idle, 'Monitoring' status. 'This is ShadowMesh — watching silently.'

### Minute 2 — The Attack Begins
Action: Run python scripts/simulate_attacker.py in the terminal.
Narrate: 'An attacker just got inside our network and started a port scan.'
Show: Dashboard status flips to THREAT ACTIVE. Network graph animates — nodes appear.
Say: 'ShadowMesh just generated a completely fake enterprise network — in real time.
  Everything the attacker sees is a trap.'

### Minute 3 — Attacker Engages Fake Assets
Narrate: 'The attacker found what looks like an SSH server and a database. They're logging in.'
Show: AlertFeed filling with events. MITRE heatmap lighting up (T1046, T1110).
Say: 'Every keystroke is logged. Every command captured. They have no idea they're in our fabric.'

### Minute 4 — The Mutation (money shot)
Narrate: 'Now the attacker gets suspicious. They run an OS fingerprinting probe.'
Watch: Topology fog animation. Scanline. Graph reshuffles.
Say: 'The moment ShadowMesh detected fingerprinting — it regenerated the entire topology.
  The attacker's map is now useless. They're starting from zero.'
Show: AttackerProfile panel — 'Intermediate. Credential harvesting. Resembles APT29.'

### Minute 5 — The Intelligence
Show: 'We've been watching for 3 minutes. Here is what we know about this attacker.'
Point to: skill level, tools detected, objective, MITRE techniques.
Closing: 'ShadowMesh doesn't just block attacks. It turns every attacker into an intelligence source.'"
```
**Commit:** `docs: 5-minute demo script with setup checklist`

---

## Phase 9 — Reliability Hardening (if time permits)
> **All 4 people — Hour 24+ or if Phase 8 finishes early**
> Goal: Patch every gap that makes this demo-only rather than real software.
> These are independent tasks — assign one per person, run in parallel.

---

### Task 9.1 — Redis persistence layer
> **Owner: T4**
```
Prompt to AI:
"Add Redis as a hot-state persistence layer to ShadowMesh.

Add to requirements.txt: redis==5.0.4

Create backend/database/redis_client.py:

import redis.asyncio as aioredis, json, os, time

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
TTL_SESSION = 86400  # 24 hours

class RedisClient:
  def __init__(self):
    self.r = aioredis.from_url(REDIS_URL, decode_responses=True)

  async def health_check() → bool:
    try: await self.r.ping(); return True
    except: return False

  # --- Topology ---
  async def save_topology(snapshot: TopologySnapshot):
    await self.r.set('shadowmesh:topology:current', snapshot.model_dump_json(), ex=TTL_SESSION)

  async def load_topology() → TopologySnapshot | None:
    raw = await self.r.get('shadowmesh:topology:current')
    return TopologySnapshot.model_validate_json(raw) if raw else None

  # --- Attacker actions ---
  async def append_action(action: AttackerAction):
    key = f'shadowmesh:actions:{action.attacker_ip}'
    await self.r.rpush(key, action.model_dump_json())
    await self.r.expire(key, TTL_SESSION)
    await self.r.ltrim(key, -200, -1)  # keep last 200 actions per attacker

  async def load_actions(attacker_ip: str) → list[AttackerAction]:
    raws = await self.r.lrange(f'shadowmesh:actions:{attacker_ip}', 0, -1)
    return [AttackerAction.model_validate_json(r) for r in raws]

  async def get_all_attacker_ips() → list[str]:
    keys = await self.r.keys('shadowmesh:actions:*')
    return [k.split(':')[-1] for k in keys]

  # --- Profiles ---
  async def save_profile(profile: AttackerProfile):
    await self.r.hset('shadowmesh:profiles', profile.attacker_ip, profile.model_dump_json())
    await self.r.expire('shadowmesh:profiles', TTL_SESSION)

  async def load_all_profiles() → dict[str, AttackerProfile]:
    raw = await self.r.hgetall('shadowmesh:profiles')
    return {ip: AttackerProfile.model_validate_json(v) for ip, v in raw.items()}

  # --- Canary tokens ---
  async def save_canary(token: CanaryToken):
    await self.r.hset('shadowmesh:canaries', token.token_id, token.model_dump_json())

  async def load_all_canaries() → dict[str, CanaryToken]:
    raw = await self.r.hgetall('shadowmesh:canaries')
    return {tid: CanaryToken.model_validate_json(v) for tid, v in raw.items()}

  # --- Credentials ---
  async def save_credential(cred: FakeCredential):
    await self.r.hset('shadowmesh:creds', cred.cred_id, cred.model_dump_json())

  async def load_all_credentials() → dict[str, FakeCredential]:
    raw = await self.r.hgetall('shadowmesh:creds')
    return {cid: FakeCredential.model_validate_json(v) for cid, v in raw.items()}

redis_client = RedisClient()  # singleton

Update FastAPI lifespan startup:
  1. await redis_client.health_check() → print '✅ Redis connected' or '❌ Redis failed'
  2. Load state on startup (order matters):
     saved_topology = await redis_client.load_topology()
     if saved_topology: routes.current_topology = saved_topology (resume session)
     saved_profiles = await redis_client.load_all_profiles()
     routes.attacker_profiles.update(saved_profiles)
     for ip in await redis_client.get_all_attacker_ips():
       routes.attacker_actions[ip] = await redis_client.load_actions(ip)
     canary_manager._tokens = await redis_client.load_all_canaries()
     cred_manager._credentials = await redis_client.load_all_credentials()

Update every state-mutation call to also write to Redis:
  - After topology update → await redis_client.save_topology(new_topology)
  - After action logged → await redis_client.append_action(action)
  - After profile update → await redis_client.save_profile(profile)
  - After canary generated → await redis_client.save_canary(token)
  - After credential generated → await redis_client.save_credential(cred)

Add REDIS_URL=redis://localhost:6379 to .env.example"
```
**Commit:** `feat(persistence): redis hot-state layer — survives backend restarts`

---

### Task 9.2 — Multi-attacker session model
> **Owner: Dealer**
```
Prompt to AI:
"Upgrade ShadowMesh to support tracking multiple simultaneous attackers.

BACKEND changes (backend/api/routes.py):
  GET /api/attackers → returns list of all attacker IPs with their stats:
    [{ ip, action_count, first_seen, last_seen, skill_level, mitre_count }]
    Pulls from attacker_actions dict + attacker_profiles dict.

  GET /api/attacker/{ip}/actions → returns last 50 actions for that specific IP

  Socket.IO: ensure EVERY emitted event includes attacker_ip field in payload.
    Update all sio.emit calls in routes.py to always include attacker_ip.

FRONTEND changes:

1. Update useShadowStore.js:
   Remove: attackerProfile: null
   Add:
     attackerProfiles: {},        // { [ip]: AttackerProfile }
     focusedAttackerIp: null,     // IP of the attacker currently shown in the dashboard
     activeSessions: [],          // [{ ip, action_count, first_seen, skill_level }]
   New actions:
     setFocusedAttacker(ip)       // focus the dashboard on a specific attacker
     updateSession(ip, stats)     // update or add a session entry in activeSessions
     setAttackerProfiles(profiles) // bulk-set from Redis reload

2. Update useSocketEvents.js:
   EVENTS.PROFILE_UPDATE → store.attackerProfiles[data.attacker_ip] = data
                           store.updateSession(data.attacker_ip, data)
   EVENTS.ATTACKER_ACTION → only increment stats for data.attacker_ip
   EVENTS.RECON_DETECTED  → store.activateDeception(data.source_ip),
                            store.setFocusedAttacker(data.source_ip) (auto-focus first attacker)

3. Create frontend/src/components/AttackerList.jsx:
   Shows all active attacker sessions in the left sidebar.
   Each entry:
     - IP address (monospace)
     - Skill level badge (color coded as before)
     - Action count + dwell time
     - 'Active' green dot if last_seen within 60s, gray 'Idle' otherwise
   Click any entry → store.setFocusedAttacker(ip)
   The focused attacker gets a highlighted border (shadowGreen 1px)
   Animate new attackers appearing with framer-motion slide-in

4. Update AttackerProfile.jsx:
   Read from: store.attackerProfiles[store.focusedAttackerIp] ?? null
   Show 'Select an attacker' empty state if focusedAttackerIp is null

5. Update NetworkGraph.jsx:
   Each node gets colored by which attacker most recently hit it:
   - No attacker: node default color by type
   - Attacker 1 (first IP alphabetically): shadowRed glow
   - Attacker 2: shadowAmber glow
   - Attacker 3+: shadowPurple glow
   Track: nodeHits = { [node_id]: attacker_ip } — updated on ATTACKER_ACTION events
   The glow is a 2px outer ring on the node canvas circle, not the fill."
```
**Commit:** `feat(multi-attacker): session model, attacker list panel, focused profile view`

---

### Task 9.3 — IsolationForest behavioral anomaly detection
> **Owner: T3**
```
Prompt to AI:
"Add real machine learning to ShadowMesh: scikit-learn IsolationForest for
behavioral anomaly detection on attacker action sequences.

Add to requirements.txt: scikit-learn==1.4.2, numpy==1.26.4

Create backend/ai/anomaly_detector.py:

import numpy as np
from sklearn.ensemble import IsolationForest
import time

FEATURE_NAMES = [
  'timing_delta_ms',     # ms since last action (low = automated, high = manual/slow)
  'port_entropy',        # Shannon entropy of ports scanned (high = broad sweep)
  'unique_ports_5s',     # unique ports hit in last 5 seconds
  'login_rate_60s',      # login attempts in last 60 seconds
  'command_diversity',   # number of unique command types so far
  'lateral_spread',      # unique target IPs in last 60 seconds
  'action_type_encoded', # port_scan=0, login=1, command=2, data=3, lateral=4, cred=5, canary=6
]

def generate_benign_training_data(n_samples: int = 2000) → np.ndarray:
  Generate synthetic 'normal' network traffic feature vectors.
  Normal traffic characteristics:
    - timing_delta_ms: random between 200-5000ms (human or scheduled, not bursty)
    - port_entropy: low (0.1-0.4) — connecting to known services only
    - unique_ports_5s: 1-3
    - login_rate_60s: 0-2
    - command_diversity: 1-4
    - lateral_spread: 1-2
    - action_type_encoded: biased toward 2 (command) and 3 (data access)
  Add small Gaussian noise to each feature.
  Return np.array of shape (n_samples, 7).

class AnomalyDetector:
  def __init__(self):
    self.model = IsolationForest(
      n_estimators=100,
      contamination=0.05,  # expect 5% anomalies
      random_state=42,
      n_jobs=-1
    )
    self._trained = False
    self._action_history: dict[str, list] = {}  # ip → list of feature vectors
    self._last_action_time: dict[str, float] = {}  # ip → timestamp

  def train(self):
    X_train = generate_benign_training_data(2000)
    self.model.fit(X_train)
    self._trained = True
    print('✅ IsolationForest trained on 2000 synthetic benign samples')

  def featurize(self, action: AttackerAction, history: list[AttackerAction]) → np.ndarray:
    ip = action.attacker_ip
    now = action.timestamp

    # timing_delta_ms
    last_time = self._last_action_time.get(ip, now)
    timing_delta = min((now - last_time) * 1000, 30000)
    self._last_action_time[ip] = now

    # port_entropy — from detail string
    import re
    ports = [int(p) for p in re.findall(r'\b\d{2,5}\b', action.detail) if int(p) < 65536]
    if ports:
      counts = np.bincount(ports, minlength=65536)
      counts = counts[counts > 0]
      p = counts / counts.sum()
      port_entropy = -np.sum(p * np.log2(p + 1e-9))
    else:
      port_entropy = 0.0

    # unique_ports_5s
    recent = [a for a in history if now - a.timestamp < 5]
    unique_ports_5s = len(set(
      p for a in recent
      for p in re.findall(r'\b\d{2,5}\b', a.detail)
      if int(p) < 65536
    ))

    # login_rate_60s
    login_rate = sum(1 for a in history if now - a.timestamp < 60 and a.action_type == 'login_attempt')

    # command_diversity
    command_diversity = len(set(a.action_type for a in history))

    # lateral_spread
    lateral_spread = len(set(a.target_node_id for a in history if now - a.timestamp < 60))

    # action_type encoded
    type_map = {'port_scan':0,'login_attempt':1,'command_exec':2,'data_access':3,'lateral_move':4,'credential_theft':5,'canary_trigger':6}
    action_encoded = type_map.get(action.action_type, 2)

    return np.array([[timing_delta, port_entropy, unique_ports_5s, login_rate, command_diversity, lateral_spread, action_encoded]])

  def score(self, action: AttackerAction, history: list[AttackerAction]) → dict:
    if not self._trained:
      return { 'threat_score': 0.5, 'is_anomalous': False, 'confidence': 0.0 }
    features = self.featurize(action, history)
    raw_score = self.model.decision_function(features)[0]  # negative = more anomalous
    prediction = self.model.predict(features)[0]  # -1 = anomaly, 1 = normal
    # Normalize to 0-1 threat score (higher = more anomalous)
    threat_score = float(np.clip(1 - (raw_score + 0.5), 0, 1))
    return {
      'threat_score': round(threat_score, 3),
      'is_anomalous': prediction == -1,
      'features': dict(zip(FEATURE_NAMES, features[0].tolist()))
    }

anomaly_detector = AnomalyDetector()  # singleton

In FastAPI lifespan startup: anomaly_detector.train() — runs in 0.3s, non-blocking.

In POST /api/attacker/action (routes.py), after MITRE tagging:
  score_result = anomaly_detector.score(action, attacker_actions[action.attacker_ip])
  await sio.emit('threat_score', {
    'attacker_ip': action.attacker_ip,
    'threat_score': score_result['threat_score'],
    'is_anomalous': score_result['is_anomalous'],
    'action_id': str(action.timestamp)
  })
  If score_result['is_anomalous'] and score_result['threat_score'] > 0.75:
    await sio.emit(EVENTS['ALERT'], {
      'message': f'High-anomaly action detected (score: {score_result[\"threat_score\"]:.2f}) — possible APT behavior',
      'severity': 'critical'
    })

FRONTEND — add ThreatScore to AttackerProfile.jsx:
  Socket listener for 'threat_score' event → store in Zustand as latestThreatScore: float
  Render below the skill level badge:
    'ML Anomaly Score' label + a gradient bar (green→amber→red, 0.0→0.5→1.0)
    Animate the bar width with framer-motion spring transition
    Show 'ANOMALOUS' badge in red when is_anomalous is true"
```
**Commit:** `feat(ai): isolationforest behavioral anomaly detection — real ml threat scoring`

---

### Task 9.4 — DNS honeypot responder
> **Owner: T2**
```
Prompt to AI:
"Create backend/detection/dns_honeypot.py — a lightweight DNS responder
that turns every DNS query into intelligence and fires alerts on planted hostnames.

Add to requirements.txt: dnslib==0.9.24

Import: dnslib (DNSRecord, QTYPE, RR, A), threading, socket, time, asyncio

PLANTED_HOSTNAMES = {
  'finance-db.corp.internal':     'Finance DB canary — attacker targeting financial data',
  'hr-share.corp.internal':       'HR file share canary — attacker targeting HR data',
  'ad-dc.corp.internal':          'Active Directory DC canary — attacker targeting identity',
  'backup-server.corp.internal':  'Backup server canary — attacker targeting backups',
  'dev-gitlab.corp.internal':     'GitLab canary — attacker targeting source code',
  'vault.corp.internal':          'HashiCorp Vault canary — attacker targeting secrets',
}

FAKE_IP_POOL = ['172.20.0.11','172.20.0.12','172.20.0.13','172.20.0.14','172.20.0.15']

class DNSHoneypot:
  def __init__(self, interface_ip: str, callback):
    self.interface_ip = interface_ip
    self.callback = callback  # async def on_dns_query(query_info: dict)
    self._running = False
    self._loop = None
    self._query_log: list[dict] = []  # in-memory DNS query log

  def _handle_query(self, data: bytes, addr: tuple, sock: socket.socket):
    try:
      request = DNSRecord.parse(data)
      qname = str(request.q.qname).rstrip('.')
      qtype = QTYPE[request.q.qtype]
      fake_ip = random.choice(FAKE_IP_POOL)

      # Build a realistic DNS response
      reply = request.reply()
      reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip), ttl=300))
      sock.sendto(reply.pack(), addr)

      query_info = {
        'hostname': qname,
        'query_type': qtype,
        'source_ip': addr[0],
        'resolved_to': fake_ip,
        'timestamp': time.time(),
        'is_planted': qname in PLANTED_HOSTNAMES,
        'canary_hint': PLANTED_HOSTNAMES.get(qname, None),
      }
      self._query_log.append(query_info)

      # Fire async callback safely from sync thread
      asyncio.run_coroutine_threadsafe(self.callback(query_info), self._loop)

    except Exception as e:
      print(f'DNS handler error: {e}')

  def start(self, loop: asyncio.AbstractEventLoop):
    self._loop = loop
    self._running = True
    def run():
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.bind(('0.0.0.0', 53))
      sock.settimeout(1.0)
      print('🌐 DNS honeypot listening on UDP :53')
      while self._running:
        try:
          data, addr = sock.recvfrom(512)
          # Handle each query in a thread so we don't block
          threading.Thread(target=self._handle_query, args=(data, addr, sock), daemon=True).start()
        except socket.timeout:
          continue
      sock.close()
    threading.Thread(target=run, daemon=True).start()

  def get_query_log(self) → list[dict]:
    return self._query_log[-100:]  # last 100 queries

  def stop(self):
    self._running = False

Wire into FastAPI lifespan startup (main.py):

  async def on_dns_query(query_info: dict):
    # Every DNS query is intelligence — emit to dashboard
    await sio.emit('dns_query', query_info)

    if query_info['is_planted']:
      # Planted hostname accessed — high-value canary
      await sio.emit(EVENTS['ALERT'], {
        'message': f'DNS canary triggered: {query_info[\"hostname\"]} — {query_info[\"canary_hint\"]}',
        'severity': 'canary'
      })
      await sio.emit(EVENTS['CANARY_TRIGGERED'], {
        'token_id': f'dns_{query_info[\"hostname\"]}',
        'label': query_info['hostname'],
        'node_id': 'dns_layer',
        'triggered_by_ip': query_info['source_ip']
      })
      asyncio.create_task(alerting.slack.alert_canary_triggered(
        query_info['source_ip'], query_info['hostname'], 'dns_layer'
      ))
    else:
      # Every non-planted query reveals what attacker is looking for
      await neo4j_client.log_action(AttackerAction(
        attacker_ip=query_info['source_ip'],
        action_type='port_scan',
        target_node_id='dns_layer',
        detail=f'DNS lookup: {query_info[\"hostname\"]} → {query_info[\"resolved_to\"]}',
        timestamp=query_info['timestamp'],
        mitre_technique_id='T1018',
        mitre_technique_name='Remote System Discovery'
      ))

  dns_honeypot = DNSHoneypot(interface_ip=os.getenv('NETWORK_INTERFACE', 'eth0'), callback=on_dns_query)
  dns_honeypot.start(asyncio.get_event_loop())

Add GET /api/dns/queries → returns dns_honeypot.get_query_log() (for dashboard intel panel)

FRONTEND — add a DNS Intelligence panel to the right sidebar below AlertFeed:
  Small collapsible section labeled 'DNS INTELLIGENCE'
  Shows last 10 DNS queries: hostname | resolved to | source IP | timestamp
  Planted hostname queries highlighted in amber with canary icon
  Provides attacker intent clues judges can read: 'attacker is looking for vault.corp.internal'"
```
**Commit:** `feat(detection): dns honeypot responder — all queries logged, planted names trigger alerts`

---

### Task 9.5 — Docker orchestrator sidecar
> **Owner: T4**
```
Prompt to AI:
"Implement the orchestrator sidecar pattern to remove Docker socket exposure from the backend.

CREATE orchestrator/app.py — a minimal Flask app:

from flask import Flask, request, jsonify
import docker, os

app = Flask(__name__)
docker_client = docker.from_env()

ALLOWED_IMAGES = {
  'shadowmesh-fake-http', 'shadowmesh-fake-db',
  'shadowmesh-fake-api',  'shadowmesh-fake-auth', 'shadowmesh-fake-ssh'
}

@app.route('/health')
def health():
  try: docker_client.ping(); return jsonify({ 'status': 'ok' })
  except Exception as e: return jsonify({ 'status': 'error', 'detail': str(e) }), 500

@app.route('/spawn', methods=['POST'])
def spawn():
  data = request.json
  image = data.get('image')
  if image not in ALLOWED_IMAGES:
    return jsonify({ 'error': 'image not allowed' }), 403
  try:
    container = docker_client.containers.run(
      image,
      detach=True,
      environment={
        'NODE_ID': data['node_id'],
        'ATTACKER_CALLBACK_URL': data.get('callback_url', 'http://backend:8000')
      },
      network=os.getenv('DECEPTION_NETWORK', 'shadowmesh_deception_net'),
      hostname=data.get('hostname', f'fake-{data[\"node_id\"][-6:]}'),
      name=f'sm_{data[\"node_id\"]}',
      remove=True,
      mem_limit='64m',
      cpu_period=100000,
      cpu_quota=25000,
      security_opt=['no-new-privileges:true', 'seccomp=default'],
      cap_drop=['ALL'],
      read_only=True,        # read-only root filesystem
      tmpfs={'/tmp': 'size=32m'},  # writable /tmp only
    )
    return jsonify({ 'container_id': container.id, 'status': 'running' })
  except Exception as e:
    return jsonify({ 'error': str(e) }), 500

@app.route('/teardown/<node_id>', methods=['DELETE'])
def teardown(node_id):
  try:
    c = docker_client.containers.get(f'sm_{node_id}')
    c.stop(timeout=2)
    return jsonify({ 'status': 'stopped' })
  except docker.errors.NotFound:
    return jsonify({ 'status': 'not_found' }), 404
  except Exception as e:
    return jsonify({ 'error': str(e) }), 500

@app.route('/teardown-all', methods=['DELETE'])
def teardown_all():
  stopped = []
  for c in docker_client.containers.list():
    if c.name.startswith('sm_'):
      try: c.stop(timeout=2); stopped.append(c.name)
      except: pass
  return jsonify({ 'stopped': stopped })

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=9000)

orchestrator/Dockerfile:
  FROM python:3.11-slim
  RUN pip install flask docker
  COPY app.py .
  CMD python app.py

UPDATE backend/deception/container_manager.py:
  Remove all direct docker_client calls.
  Replace with httpx calls to http://orchestrator:9000:

  ORCHESTRATOR_URL = os.getenv('ORCHESTRATOR_URL', 'http://localhost:9000')

  async def spawn_container(node: NetworkNode) → str | None:
    image = CONTAINER_IMAGES.get(node.node_type)
    if not image: return None
    try:
      async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f'{ORCHESTRATOR_URL}/spawn', json={
          'image': image,
          'node_id': node.node_id,
          'hostname': f'fake-{node.node_type}-{node.node_id[-4:]}',
          'callback_url': 'http://backend:8000',
        })
        if resp.status_code == 200:
          return resp.json()['container_id']
    except Exception as e:
      print(f'Orchestrator spawn error: {e}')
    return None

  async def teardown_all():
    try:
      async with httpx.AsyncClient(timeout=10) as client:
        await client.delete(f'{ORCHESTRATOR_URL}/teardown-all')
    except Exception as e:
      print(f'Orchestrator teardown error: {e}')

  async def teardown_node(node_id: str):
    try:
      async with httpx.AsyncClient(timeout=5) as client:
        await client.delete(f'{ORCHESTRATOR_URL}/teardown/{node_id}')
    except: pass

Add ORCHESTRATOR_URL=http://localhost:9000 to .env.example
Remove /var/run/docker.sock volume mount from backend in docker-compose.yml (done in Task 0.2 already)."
```
**Commit:** `feat(security): docker orchestrator sidecar — socket isolation, seccomp, read-only containers`

---

| Decision | Choice | Why |
|---|---|---|
| Detection | Scapy (not eBPF) | eBPF needs kernel headers + BCC setup. Scapy works on any Linux in minutes. Same detection quality. |
| Topology AI | NetworkX Barabási–Albert | No training data needed. Statistically valid. Defensible to judges. |
| LLM | Groq llama-3.3-70b-versatile | Dealer already has keys. Instant — no Ollama download wait. Same model family as the draft. |
| Backend framework | FastAPI + python-socketio | Python ecosystem matches Scapy + NetworkX + mitreattack-python. No language switching. |
| Graph DB | Neo4j 5.19 | Dealer used this in Graphy. Direct skill reuse. Native graph queries for attack paths. |
| Network graph | react-force-graph-2d | Dealer used this in Graphy. Plug-in-play with the same data shape. |
| State management | Zustand | Dealer used this in Graphy. Zero setup friction. |
| Container isolation | cap_drop ALL + mem_limit 64m | Prevents fake containers from becoming real attack vectors. |
| MITRE mapping | Rule-based (not LLM) | Deterministic, instant, no token cost. LLM reserved for profiling where nuance matters. |
| Canary tokens | Self-hosted FastAPI route | No external dependency. canarytokens.org library dropped — same result in 30 lines. |
| Fake credentials | Generated strings in-memory | Served on demand via file download endpoint. Attacker gets realistic content, we get the alert. |
| Adaptive lures | Objective keyword matching | Simple, reliable, no extra LLM call. Profile objective string drives container spawn decision. |
| Slack alerts | httpx POST to incoming webhook | Universal. Judges see a real phone notification during demo — high impact, 10 lines of code. |
| Demo attacker | Python script (not real nmap) | Controllable, reproducible, works in any environment. No dependency on nmap install. |

---

## Environment Variables

### backend (.env)
```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=shadowmesh
GROQ_API_KEY=gsk_...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
NETWORK_INTERFACE=eth0
FAKE_NETWORK_SUBNET=172.20.0.0/24
BACKEND_PORT=8000
```

### frontend (.env)
```
VITE_BACKEND_URL=http://localhost:8000
VITE_SOCKET_URL=http://localhost:8000
```

---

## Phase 10 — Critical Failure Prevention
> **Do these BEFORE anything in Phase 9. These are not improvements — they are fixes for things that WILL break the demo.**

### Task 10.1 — Fix async/thread race condition on shared state
> **Owner: T2**
```
Prompt to AI:
"Fix the shared state race condition in backend/api/routes.py.

current_topology, attacker_actions, and attacker_profiles are plain Python dicts
mutated from three concurrent sources: FastAPI async loop, Scapy thread, DNS thread.
Two threads writing simultaneously = corrupted topology, KeyErrors, broken demo.

Add a module-level asyncio.Lock:
  state_lock = asyncio.Lock()

Wrap EVERY write to shared state:
  async with state_lock:
    <mutation here>

Locations to wrap:
  1. POST /api/detect/scan → setting current_topology after generate_topology()
  2. POST /api/attacker/action → appending to attacker_actions[ip], setting attacker_profiles[ip]
  3. POST /api/topology/mutate → setting current_topology
  4. on_recon_detected() callback (called from Scapy thread)
  5. on_dns_query() callback (called from DNS thread)

READ operations (GET endpoints) do not need the lock — Python GIL protects simple reads.

Also add a sequence counter:
  _event_sequence: int = 0
  Increment inside state_lock on every write.
  Include in every topology_update Socket.IO payload as 'sequence': _event_sequence
  Frontend can detect missed updates (sequence gap) and request a fresh GET /api/topology/current."
```
**Commit:** `fix(critical): asyncio.Lock on all shared state mutations — prevents race condition`

---

### Task 10.2 — Auto-detect network interface + validate on startup
> **Owner: T2**
```
Prompt to AI:
"Fix the silent Scapy failure when NETWORK_INTERFACE env var is wrong.

In backend/detection/scanner.py add:

def detect_network_interface() -> str:
  Try in order:
    1. NETWORK_INTERFACE env var — if set and valid, use it
    2. Parse 'ip route show default' → extract 'dev INTERFACE_NAME' with regex r'dev (\S+)'
    3. scapy get_if_list() filtered: exclude 'lo', 'docker*', 'br-*', 'veth*'
       Return first remaining interface
    4. Last resort: return 'lo' with a warning (detects nothing but does not crash)
  Print: '🔍 Detected network interface: {interface}'

In ReconDetector.start():
  Before sniff(), validate:
    from scapy.all import get_if_list
    if self.interface not in get_if_list():
      print(f'❌ Interface {self.interface} not found. Available: {get_if_list()}')
      print('Set NETWORK_INTERFACE=auto or a valid name in .env')
      return  # disable detection gracefully — do NOT crash backend

Change .env.example: NETWORK_INTERFACE=auto

Add smoke_test check: verify detector interface is in get_if_list() and is not 'lo'"
```
**Commit:** `fix(critical): auto-detect network interface — prevents silent Scapy failure`

---

### Task 10.3 — Pre-build Docker images + startup teardown + unique names
> **Owner: T4**
```
Prompt to AI:
"Fix three Docker failure modes in one task.

FIX 1 — scripts/build_images.sh:
  #!/bin/bash
  echo '🔨 Building ShadowMesh honeypot images...'
  docker build -t shadowmesh-fake-ssh   ./docker/fake-ssh   || exit 1
  docker build -t shadowmesh-fake-http  ./docker/fake-http  || exit 1
  docker build -t shadowmesh-fake-db    ./docker/fake-db    || exit 1
  docker build -t shadowmesh-fake-api   ./docker/fake-api   || exit 1
  docker build -t shadowmesh-fake-auth  ./docker/fake-auth  || exit 1
  echo '✅ All honeypot images built.'
  chmod +x build_images.sh

Add to smoke_test.py: for each image in ALLOWED_IMAGES → docker_client.images.get(image) ✅ or ❌

FIX 2 — Startup teardown in orchestrator/app.py:
  def startup_cleanup():
    print('🧹 Cleaning leftover containers...')
    for c in docker_client.containers.list(all=True):
      if c.name.startswith('sm_'):
        try: c.stop(timeout=1); c.remove(force=True)
        except: pass
  Call startup_cleanup() in if __name__ == '__main__': before app.run()

FIX 3 — Unique container name suffix in orchestrator/app.py spawn():
  import time
  name = f'sm_{data[\"node_id\"]}_{int(time.time()) % 100000}'
  Guarantees uniqueness even if teardown partially fails."
```
**Commit:** `fix(critical): pre-build script, startup teardown, timestamped container names`

---

### Task 10.4 — Neo4j optional startup with retry backoff
> **Owner: T4**
```
Prompt to AI:
"Fix Neo4j startup race condition. Backend must start even if Neo4j is slow.

In backend/database/neo4j_client.py add:

  async def connect_with_retry(max_attempts=10, delay=3.0) -> bool:
    for attempt in range(max_attempts):
      try:
        async with self.driver.session() as session:
          await session.run('RETURN 1')
        await self.init_schema()
        print(f'✅ Neo4j connected (attempt {attempt+1})')
        return True
      except Exception as e:
        print(f'⏳ Neo4j not ready ({attempt+1}/{max_attempts}): {e}')
        await asyncio.sleep(delay)
    print('❌ Neo4j unavailable — memory-only mode')
    return False

Add module flag: NEO4J_AVAILABLE = False
Set True only when connect_with_retry returns True.

Wrap ALL neo4j calls (log_action, create_attacker, get_attack_path) with:
  if not NEO4J_AVAILABLE: return  # graceful no-op

In FastAPI lifespan: replace init_schema() with connect_with_retry()
  (waits up to 30 seconds — Neo4j is always ready by then in practice)

In docker-compose.yml update backend depends_on:
  depends_on:
    neo4j: { condition: service_healthy }
    redis: { condition: service_healthy }"
```
**Commit:** `fix(high): neo4j optional with retry backoff — backend starts regardless`

---

### Task 10.5 — Deterministic heuristic profiler (Groq fallback)
> **Owner: T3**
```
Prompt to AI:
"Add a local deterministic profiler that runs BEFORE Groq — guarantees the
AttackerProfile panel always has data even if Groq is rate-limited or down.

In backend/ai/profiler.py add heuristic_profile(attacker_ip, actions) -> AttackerProfile:

  TOOL_SIGNATURES = {
    'nmap':       ['nmap', 'port scan', '-sV', '-O', 'SYN'],
    'hydra':      ['hydra', 'brute force', 'password spray'],
    'metasploit': ['metasploit', 'exploit/', 'payload/'],
    'mimikatz':   ['mimikatz', 'lsass', 'credential dump'],
    'netcat':     ['netcat', 'nc -', 'reverse shell'],
  }

  all_detail = ' '.join(a.detail.lower() for a in actions)
  tools_detected = [t for t, sigs in TOOL_SIGNATURES.items() if any(s in all_detail for s in sigs)]

  scan_count  = sum(1 for a in actions if a.action_type == 'port_scan')
  login_count = sum(1 for a in actions if a.action_type == 'login_attempt')
  cred_count  = sum(1 for a in actions if a.action_type == 'credential_theft')
  lat_count   = sum(1 for a in actions if a.action_type == 'lateral_move')

  skill = ('Advanced' if cred_count > 0 or lat_count > 0
           else 'Intermediate' if len(tools_detected) >= 2 or login_count > 5
           else 'Script Kiddie' if login_count > 15
           else 'Unknown')

  objective = ('Credential harvesting' if cred_count > 0
               else 'Lateral movement' if lat_count > 0
               else 'Data exfiltration' if 'data' in all_detail
               else 'Reconnaissance')

  apt = ('APT29 pattern' if 'mimikatz' in tools_detected and lat_count > 0
         else 'Lazarus pattern' if scan_count > 8 and login_count > 10
         else 'Unknown / unclassified')

  return AttackerProfile(attacker_ip=attacker_ip, skill_level=skill,
    objective=objective, apt_resemblance=apt, tools_detected=tools_detected or ['unknown'],
    confidence=0.55, summary=f'Heuristic: {len(actions)} actions, {len(tools_detected)} tools.')

Update profile_attacker():
  1. Run heuristic_profile() immediately — emit PROFILE_UPDATE instantly
  2. Then try Groq async in a background task
  3. If Groq succeeds → emit updated profile with confidence > 0.55
  4. If Groq fails → heuristic profile already on dashboard, no empty panel

Frontend AttackerProfile.jsx: show 'LOCAL' badge when confidence <= 0.55,
  'AI ENHANCED' green badge when confidence > 0.55"
```
**Commit:** `fix(high): local heuristic profiler — profile always visible, groq enriches async`

---

### Task 10.6 — MITRE lazy load + Vite WebSocket proxy
> **Owner: T3 (MITRE) + Dealer (Vite)**
```
Prompt to AI (T3):
"Fix MitreMapper to lazy-load with graceful fallback if file missing.

In backend/mitre/mapper.py change __init__ to catch all errors:
  def __init__(self):
    self._technique_cache = {}
    self._loaded = False
    try:
      if not MITRE_JSON_PATH.exists():
        print('⚠️ enterprise-attack.json missing — run scripts/download_mitre.py')
        return
      self.attack_data = MitreAttackData(str(MITRE_JSON_PATH))
      self._build_cache()
      self._loaded = True
      print(f'✅ MITRE loaded: {len(self._technique_cache)} techniques')
    except Exception as e:
      print(f'⚠️ MITRE load failed: {e}')

  def tag_action(self, action_type, detail):
    if not self._loaded: return None  # graceful no-op"

Prompt to AI (Dealer):
"Fix vite.config.js to support Socket.IO WebSocket upgrades.
The missing ws:true causes Socket.IO to fall back to polling.

server: {
  proxy: {
    '/api': { target: 'http://localhost:8000', changeOrigin: true },
    '/socket.io': {
      target: 'http://localhost:8000',
      changeOrigin: true,
      ws: true,              ← critical
      rewriteWsOrigin: true,
    }
  }
}

In socket.js:
  const socket = io(import.meta.env.DEV ? '' : import.meta.env.VITE_SOCKET_URL, {
    path: '/socket.io',
    transports: ['websocket', 'polling'],  // websocket first
    autoConnect: true,
  })"
```
**Commit:** `fix(medium): mitre lazy-load graceful fallback + vite ws:true proxy`

---

### Task 10.7 — NetworkGraph stable keys + simulation reset on mutation
> **Owner: Dealer**
```
Prompt to AI:
"Fix react-force-graph-2d crash when topology updates mid-simulation.

In NetworkGraph.jsx:
  const graphRef = useRef();
  const prevPositions = useRef({});  // { [node_id]: { x, y } }

  // Before nodes change, snapshot current D3 positions
  useEffect(() => {
    if (graphRef.current) {
      graphRef.current.graphData().nodes.forEach(n => {
        prevPositions.current[n.id] = { x: n.x, y: n.y };
      });
    }
  }, [nodes]);

  const graphData = useMemo(() => ({
    nodes: nodes.map(n => ({
      id: n.node_id,
      ip: n.ip, nodeType: n.node_type, ports: n.ports, banner: n.banner,
      // Restore previous x/y to prevent jarring jump on topology update
      ...(prevPositions.current[n.node_id] || {}),
    })),
    links: edges.map(([s, t]) => ({ source: s, target: t }))
  }), [nodes, edges]);

  // On mutation end: clear old positions + reheat simulation
  useEffect(() => {
    if (!isMutating && graphRef.current) {
      prevPositions.current = {};
      graphRef.current.d3ReheatSimulation();
    }
  }, [isMutating]);

  Pass graphRef to <ForceGraph2D ref={graphRef} graphData={graphData} ... />"
```
**Commit:** `fix(medium): stable node positions + d3 reheat on mutation — prevents force-graph crash`

---

## Phase 10 Summary

| Task | Risk | Level | Owner | Est. Time |
|---|---|---|---|---|
| 10.1 | Async/thread race condition | **CRITICAL** | T2 | 45 min |
| 10.2 | Wrong network interface silent fail | **CRITICAL** | T2 | 30 min |
| 10.3 | Images not built + name collision | **CRITICAL** | T4 | 45 min |
| 10.4 | Neo4j startup race | **HIGH** | T4 | 30 min |
| 10.5 | Groq rate-limit, empty profile panel | **HIGH** | T3 | 60 min |
| 10.6 | MITRE crash + Vite WS proxy | **MEDIUM** | T3 + Dealer | 30 min |
| 10.7 | Force-graph crash on mutation | **MEDIUM** | Dealer | 30 min |

**~5 hours total across 4 people in parallel. Do not skip any of these.**

---

## Phase 11 — Deception Depth
> **Goal: Make every fake asset undetectable to sophisticated attackers.**
> Inspired by: Smokescreen (persona/RDP), Acalvio (projection sensors), market gaps (protocols, documents).
> No time constraint — build these properly.

---

### Task 11.1 — Persona decoys
```
Prompt to AI:
"Create backend/deception/persona_generator.py.

A persona is a fake human identity injected into every fake container at spawn time,
making it look like a real person has been using that server for years.

class PersonaGenerator:
  First, generate a realistic fake person:
    name: random from a list of 50 common names (first + last)
    username: firstname.lastname or first initial + lastname
    email: username@{fake_domain} where fake_domain is one of
      [corp-internal.io, acme-tech.net, globalfinance.org, devteam.internal]
    ssh_key_comment: username@hostname
    timezone: random from [UTC+5:30, UTC-5, UTC+1, UTC-8, UTC+8]
    role: random from [backend-dev, devops-engineer, data-analyst, sysadmin, finance-analyst]

  def generate_bash_history(persona) → str:
    Generate 40-80 realistic bash history lines matching the persona's role.
    devops-engineer history includes: kubectl, docker, terraform, ansible commands
    backend-dev includes: git, python, pip, pytest, curl API calls
    data-analyst includes: python, jupyter, psql, mysql, pandas scripts
    sysadmin includes: systemctl, journalctl, netstat, cron, rsync
    finance-analyst includes: python scripts, sftp, openssl, gpg commands
    Mix real-looking server hostnames (db-prod-01, api-gateway-02) in the commands.
    Include some failed commands (exit code comments) for realism.
    Return as newline-joined string.

  def generate_ssh_known_hosts(persona) → str:
    Generate 8-15 fake SSH known_hosts entries.
    Format: '{ip} ssh-rsa AAAA{random_64_chars}= {persona.username}@{hostname}'
    Use realistic internal IPs in 172.16.x.x, 10.0.x.x ranges.

  def generate_git_config(persona) → str:
    Return a realistic .gitconfig:
    [user]
      name = {persona.name}
      email = {persona.email}
    [core]
      editor = vim
    [alias]
      st = status
      co = checkout
      br = branch
      lg = log --oneline --graph

  def generate_env_file(persona) → str:
    Return a fake .env file matching their role.
    devops: Kubernetes tokens, Terraform vars, Docker registry creds (all fake)
    backend-dev: DATABASE_URL, API_KEY, JWT_SECRET, REDIS_URL (all fake but realistic)
    sysadmin: SMTP_PASSWORD, BACKUP_KEY, MONITORING_TOKEN (all fake)
    Finance: SFTP_PASSWORD, ENCRYPTION_KEY, REPORTING_API_KEY (all fake)

  def generate_full_persona_files(persona) → dict[str, str]:
    Returns mapping of filepath → content for all persona files:
    {
      '/root/.bash_history': generate_bash_history(persona),
      '/root/.ssh/known_hosts': generate_ssh_known_hosts(persona),
      '/root/.gitconfig': generate_git_config(persona),
      '/root/.env': generate_env_file(persona),
      '/root/.profile': '# .profile for {persona.username}\nexport PATH=$PATH:/usr/local/bin\n',
      '/etc/hostname': random fake hostname like 'db-prod-01' or 'api-gw-02',
    }

Update container_manager.py spawn_container():
  After container starts, inject persona files using docker exec:
  for filepath, content in persona_files.items():
    docker_client.containers.get(cid).exec_run(
      f'bash -c \"mkdir -p $(dirname {filepath}) && cat > {filepath} << HEREDOC\n{content}\nHEREDOC\"'
    )

Update fake SSH server (docker/fake-ssh/server.py):
  Load persona files from /persona/ directory (mounted at container start).
  When attacker runs 'cat /root/.bash_history' → return real-looking history.
  When attacker runs 'cat /root/.ssh/known_hosts' → return known_hosts.
  When attacker runs 'cat /root/.gitconfig' → return git config.
  When attacker runs 'cat /root/.env' → fire credential_stolen alert AND return content.
  When attacker runs 'whoami' → return persona.username instead of 'admin'.
  When attacker runs 'id' → return 'uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)'"
```
**Commit:** `feat(deception): persona generator — fake human identity injected into every container`

---

### Task 11.2 — RDP replay engine
```
Prompt to AI:
"Create docker/fake-rdp/ — a fake Windows RDP server that replays a recorded session.

This is inspired by Smokescreen's IllusionBLACK RDP replay feature.
A real attacker connecting via RDP should see a convincing Windows desktop activity,
not a blank screen or refused connection.

Implementation approach (simplified for our stack):
  Use Python with the 'twisted' library to handle RDP protocol negotiation.
  We don't need to implement full RDP rendering — just enough to:
    1. Complete the RDP handshake (CredSSP/NLA negotiation)
    2. Accept any credentials (log them)
    3. Return a pre-rendered bitmap stream showing a fake Windows desktop

Dockerfile:
  FROM python:3.11-slim
  RUN pip install twisted impacket requests
  COPY server.py rdp_session.py desktop_bitmap.py .
  CMD python server.py

server.py:
  Listen on TCP port 3389.
  On connection: log source IP, log connection attempt.
  POST callback to backend: action_type='login_attempt', detail='RDP connection from {ip}'
  Complete basic RDP protocol X.224 connection request (TPKT/X.224/MCS).
  After negotiation: serve a pre-generated bitmap of a fake Windows 10 desktop.
  The 'desktop' shows: Windows taskbar, fake File Explorer window open showing
    folders named 'Q3_Reports', 'Payroll_2024', 'Client_Contracts', 'SSH_Keys'.
  Any keyboard input: log it and fire EVENTS.ATTACKER_ACTION command_exec.
  When attacker 'opens' any folder (any keypress): fire canary alert for that folder name.

  The pre-generated bitmap (desktop_bitmap.py):
    Generate a 800x600 pixel PNG of a minimal fake Windows 10 desktop using Pillow.
    Dark taskbar at bottom, Start button, clock showing current time.
    File Explorer window in the center showing the fake folders.
    Save as base64 — sent as RDP bitmap update PDU.

  Note: Full RDP protocol implementation is complex. Implement the minimum:
    - X.224 CR/CC (Connection Request / Connection Confirm)
    - MCS Connect Initial / Connect Response
    - After that: serve our bitmap and log all traffic
    A real attacker's RDP client will show something (not a clean connection refused)
    which is more convincing than an instant reset.

ENV: NODE_ID, ATTACKER_CALLBACK_URL"
```
**Commit:** `feat(deception): rdp replay honeypot — fake windows desktop on port 3389`

---

### Task 11.3 — Projection sensors (lightweight decoys)
```
Prompt to AI:
"Create backend/detection/projection_sensor.py.

Projection sensors project fake network presence without running Docker containers.
This lets us populate the fake topology with 50+ nodes instead of 10-14,
using ARP responses and TCP banner replies — no container overhead.

Inspired by Acalvio ShadowPlex's projection model.

Import: scapy.all, threading, socket, time, asyncio

BANNER_TEMPLATES = {
  'web_server':   b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 0\r\n\r\n',
  'db_server':    b'\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x32\x38\x00',  # MySQL greeting
  'ssh_server':   b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n',
  'smtp_server':  b'220 mail.corp.internal ESMTP Postfix (Ubuntu)\r\n',
  'ftp_server':   b'220 (vsFTPd 3.0.3)\r\n',
  'telnet':       b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f',  # telnet negotiation
  'redis':        b'+PONG\r\n',
  'elasticsearch': b'HTTP/1.1 200 OK\r\nX-elastic-product: Elasticsearch\r\n\r\n',
}

class ProjectionSensor:
  def __init__(self, interface: str, subnet: str, callback):
    self.interface = interface
    self.subnet = subnet  # e.g. '172.20.0.0/24'
    self.callback = callback
    self._projected_ips: dict[str, dict] = {}  # ip → {node_type, ports}
    self._running = False
    self._loop = None

  def project_node(self, ip: str, node_type: str, ports: list[int]):
    Store ip → {node_type, ports} in self._projected_ips.
    This tells the ARP/TCP responder to answer for this IP.

  def _handle_arp(self, packet):
    If ARP request WHO-HAS matches any ip in self._projected_ips:
      Send ARP reply IS-AT with a fake MAC address (randomly generated per IP, stable per session).
      This makes the fake IP appear on the network to anyone doing ARP scans.

  def _handle_tcp(self, packet):
    If TCP SYN to any ip in self._projected_ips AND port in that node's ports:
      1. Complete TCP handshake (SYN-ACK)
      2. Wait for first data packet
      3. Send back the matching BANNER_TEMPLATES[node_type]
      4. Fire callback: AttackerAction(action_type='port_scan', detail=f'TCP probe on {ip}:{port}')
      5. Close connection after banner

  def start(self, loop):
    self._loop = loop
    self._running = True
    threading.Thread(target=self._sniff_loop, daemon=True).start()
    print(f'🔦 Projection sensor active on {self.interface} — projecting {len(self._projected_ips)} nodes')

  def _sniff_loop(self):
    from scapy.all import sniff, ARP, TCP
    sniff(iface=self.interface,
          filter='arp or tcp',
          prn=lambda p: self._handle_arp(p) if ARP in p else self._handle_tcp(p),
          store=False,
          stop_filter=lambda _: not self._running)

  def stop(self):
    self._running = False

In topology.generate_topology():
  Split nodes into two tiers:
    Tier 1 (30% of nodes): FULL containers — these are the high-interaction honeypots.
    Tier 2 (70% of nodes): PROJECTED — lightweight banner responders only.
  Return topology with a 'tier' field on each NetworkNode: 'full' | 'projected'

In container_manager.spawn_topology():
  Full-tier nodes → spawn Docker container as before.
  Projected-tier nodes → call projection_sensor.project_node(ip, node_type, ports).
  This means a 50-node topology only needs 15 full containers + 35 projected nodes."
```
**Commit:** `feat(deception): projection sensors — 50+ fake nodes without docker overhead`

---

### Task 11.4 — Protocol honeypot expansion
```
Prompt to AI:
"Expand the fake service container set with 4 new protocol honeypots.
Each is a standalone Python service responding to its protocol.

--- docker/fake-smb/server.py (SMB file share, port 445) ---
Use impacket's SimpleSMBServer to create a fake SMB share.
Share names: 'Finance', 'HR_Documents', 'Engineering', 'Backups', 'CEO_Files'
Each share appears to contain files (listed via SMB directory listing):
  Finance: Q3_Report.xlsx, Payroll_2024.csv, Budget_Forecast.docx
  HR_Documents: Employee_Contracts.pdf, Salary_Review.xlsx
  Engineering: Architecture_Diagram.pdf, API_Keys.txt, deploy.sh
Any file access attempt → POST callback: action_type='data_access',
  detail=f'SMB file access: \\\\{hostname}\\{share}\\{filename}'
Any login attempt → POST callback: action_type='login_attempt'
All file 'downloads' served as fake content (empty or minimal placeholder).
Server banner: 'Windows Server 2019 Standard' (mimics real Windows file server).

--- docker/fake-mqtt/server.py (MQTT IoT broker, port 1883) ---
Use the 'amqtt' library to run a real MQTT broker that logs everything.
On any SUBSCRIBE: log the topic pattern as intelligence
  (reveals what IoT data the attacker is looking for: /sensors/temp, /factory/plc/1, etc.)
On any PUBLISH: log the topic + payload
On any CONNECT: log clientId and credentials
Fire callback for every interaction.
Publish fake 'sensor data' to enticing topics every 5 seconds:
  /factory/plc/temperature → 'value:87.3,unit:celsius,alarm:false'
  /sensors/door/status → 'open'
This gives attackers something to subscribe to and watch.

--- docker/fake-redis/server.py (Redis, port 6379) ---
Implement minimal Redis protocol (RESP) — just enough to respond to:
  PING → +PONG
  INFO → realistic Redis server info string with fake metrics
  KEYS * → list of enticing fake key names: ['user:admin:session', 'api:secret:key',
    'db:password:master', 'jwt:signing:secret', 'stripe:api:key']
  GET {key} → fake but realistic-looking value for that key
    user:admin:session → 'eyJhbGciOiJIUzI1NiJ9.{fake_jwt_payload}.{fake_sig}'
    api:secret:key → 'sk-prod-a7f3c9e2b1d4f8a0c3e6b9d2f5a8c1e4'
    stripe:api:key → '[REDACTED]'
  Every GET of sensitive keys → fire credential_stolen alert
  AUTH command → always succeed (log credentials)

--- docker/fake-elastic/server.py (Elasticsearch HTTP, port 9200) ---
Flask app mimicking Elasticsearch REST API.
  GET / → realistic cluster info JSON with fake node name, cluster name 'prod-cluster'
  GET /_cat/indices → list of enticing fake indices:
    ['user-data-2024', 'financial-transactions', 'employee-records',
     'customer-pii', 'audit-logs-2024', 'payment-history']
  GET /{index}/_search → return 3 fake documents with realistic field names
    user-data: { 'email': 'john.admin@corp.com', 'password_hash': '{bcrypt_fake}', 'role': 'admin' }
    financial-transactions: { 'amount': 45000, 'account': '****4521', 'type': 'wire' }
  POST /{index}/_search → same as GET _search (log the query body as intelligence)
  Every document 'access' → fire data_access alert with index name
  Server header: 'Elasticsearch/8.11.0'

All four Dockerfiles: FROM python:3.11-slim, install relevant libraries, COPY server.py
Add all four to CONTAINER_IMAGES dict in container_manager.py
Add all four to orchestrator/app.py ALLOWED_IMAGES"
```
**Commit:** `feat(deception): SMB + MQTT + Redis + Elasticsearch honeypots — full protocol coverage`

---

### Task 11.5 — Decoy document generator
```
Prompt to AI:
"Create backend/deception/document_generator.py.

Generate fake Office documents, PDFs, and text files that contain embedded canary tokens.
When an attacker exfiltrates and opens these files, the canary fires — even after they
have left our network. This is the key innovation: post-exfiltration detection.

Add to requirements.txt: python-docx==1.1.0, reportlab==4.1.0, Pillow==10.3.0

DOCUMENT_TEMPLATES = {
  'financial_report': {
    'filename': 'Q3_Financial_Report_2024.docx',
    'title': 'Q3 2024 Financial Report — CONFIDENTIAL',
    'content_paragraphs': [
      'This report contains proprietary financial information...',
      'Total revenue Q3 2024: $47,823,441',
      'Operating margin: 23.4%',
      'For questions contact: finance@corp.internal',
    ],
    'canary_url_label': 'Click here for the full unredacted report',
  },
  'employee_credentials': {
    'filename': 'IT_Credentials_Master.txt',
    'title': 'IT Infrastructure Credentials — DO NOT DISTRIBUTE',
    'content_lines': [
      'Production DB: db-prod-01.internal:5432 | User: prod_admin | Pass: Pr0d@2024!',
      'AWS Console: https://corp.signin.aws.amazon.com | User: aws-admin@corp.com',
      'VPN: vpn.corp.internal | Shared secret: VPN_S3cr3t_2024',
      'Backup server: 10.0.1.50 | User: backup | Key: /root/.ssh/backup_rsa',
    ],
  },
  'architecture_diagram': {
    'filename': 'Network_Architecture_Q4_2024.pdf',
    'title': 'Internal Network Architecture — RESTRICTED',
    'sections': ['Production Network', 'Database Tier', 'API Gateway', 'Jump Hosts'],
  },
  'payroll_data': {
    'filename': 'Payroll_Dec_2024.xlsx',
    'title': 'December 2024 Payroll',
  },
}

class DocumentGenerator:
  def generate_docx(self, template_key: str, canary_url: str) → bytes:
    Create a Word document using python-docx.
    Add document title as Heading 1.
    Add content paragraphs.
    Add a hyperlink at the bottom: text=template['canary_url_label'], url=canary_url
    The hyperlink is styled like a normal link — blue underlined text.
    Return document as bytes (BytesIO).

  def generate_txt(self, template_key: str, canary_url: str) → bytes:
    Create a plain text file.
    Include content lines from template.
    Add at the bottom: 'Additional resources: {canary_url}'
    Return as bytes.

  def generate_pdf(self, template_key: str, canary_url: str) → bytes:
    Create a PDF using reportlab.
    Title page, section headers, placeholder content.
    Add a 'Source document' link at the bottom pointing to canary_url.
    Return as bytes.

For each generated document:
  1. Create a CanaryToken for it via canary_manager
  2. The token_url IS the canary — embedded as a hyperlink in the document
  3. Store document bytes in memory (or Redis) keyed by token_id
  4. Add FastAPI route: GET /api/docs/{token_id}/{filename}
     → Returns the document as application/octet-stream download
     → This is what the attacker finds linked in fake file server listings

Embed document links in fake-smb and fake-http containers:
  In fake-smb: when attacker lists Finance share → include Q3_Financial_Report_2024.docx
    with a URL pointing to GET /api/docs/{token_id}/Q3_Financial_Report_2024.docx
  In fake-http GET /api/config: add 'reports_url' field pointing to a document
  Generate 2-3 documents per topology generation, plant links in appropriate containers."
```
**Commit:** `feat(deception): decoy document generator — post-exfiltration canary detection`

---

## Phase 12 — Intelligence Upgrades
> **Goal: Make ShadowMesh's AI layer the most capable in the market.**
> Inspired by: Attivo/Illusive (AD deception), market gap (cloud deception, RL topology), Acalvio/CounterCraft (STIX export).

---

### Task 12.1 — Active Directory deception
```
Prompt to AI:
"Extend backend/deception/fake_ad.py — a complete fake Active Directory environment.

This is the biggest gap vs Attivo/Illusive. When attackers do LDAP enumeration,
they should find a rich fake AD with hundreds of objects to enumerate.

Add to requirements.txt: impacket==0.12.0

class FakeActiveDirectory:
  Generate a fake AD domain: corp.internal (or configurable)

  def generate_users(count=50) → list[dict]:
    Generate realistic AD user objects:
    Each user has: sAMAccountName, distinguishedName, mail, displayName,
      memberOf (one of [Domain Admins, IT Staff, Finance, Engineering, HR]),
      userAccountControl, pwdLastSet, lastLogon,
      description (some have 'Password: {weak_password}' in description — a classic AD mistake)
    Make 2-3 users members of 'Domain Admins' — high-value targets
    Make 1 user a 'Service Account' with description containing a fake password

  def generate_computers(count=20) → list[dict]:
    Fake computer objects: workstation names like CORP-WS-001, servers like CORP-SRV-DB01
    Each has: dNSHostName, operatingSystem, operatingSystemVersion, lastLogonTimestamp

  def generate_groups() → list[dict]:
    Domain Admins, Enterprise Admins, IT Staff, Finance Users, Engineering,
    Backup Operators, Remote Desktop Users — all with member lists

  def to_ldap_response(self, search_filter: str, attributes: list[str]) → list[dict]:
    Given an LDAP search filter (e.g. '(objectClass=user)', '(&(objectClass=user)(memberOf=CN=Domain Admins...))'),
    return matching objects with requested attributes.
    This drives the fake-auth container's LDAP responses.

Update fake-auth/server.py (docker/fake-auth/):
  Replace the simple LDAP stub with a full FakeActiveDirectory-backed server.

  Load FakeActiveDirectory data at startup (inject as JSON env var or mount).

  LDAP endpoints:
    POST /ldap/bind → always succeed, log credentials (fires login_attempt alert)
    GET  /ldap/search → parse filter parameter, return matching AD objects as LDAP entries
    GET  /ldap/users → return all user objects (paginated)
    GET  /ldap/groups → return all group objects
    GET  /ldap/computers → return all computer objects

  When attacker queries Domain Admins members → fire high-priority alert:
    'Attacker enumerated Domain Admins — likely privilege escalation planning'
    MITRE tag: T1087.002 (Account Discovery: Domain Account)
  When attacker queries a service account → fire credential alert
  When attacker finds the user with password in description → fire critical alert

  Make the LDAP responses realistic:
    Include proper LDAP result codes (0 = success, 32 = no such object)
    Include proper schema attributes (objectClass, objectGUID, etc.)
    Serialize as JSON (our HTTP-based LDAP stub) or proper BER encoding (advanced)"
```
**Commit:** `feat(deception): active directory deception — full fake AD with users, groups, computers`

---

### Task 12.2 — Cloud deception layer
```
Prompt to AI:
"Create backend/deception/cloud_deception.py — fake cloud credentials and fake cloud endpoints.

No commercial product has fake cloud infrastructure as deception targets.
This is a genuine market gap.

STRATEGY:
  Generate fake-looking but structurally valid AWS/Azure/GCP credentials.
  Plant them in fake containers.
  When attacker finds and uses them, they hit our fake cloud API endpoint
  (via hosts file manipulation or credential URL that points to us).
  We log the exact API call they attempted — giving us their tools and objectives.

Part 1 — Fake credential generation:

class CloudCredentialGenerator:
  def generate_aws_credentials() → dict:
    return {
      'access_key_id': 'AKIA' + ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16)),
      'secret_access_key': base64.b64encode(os.urandom(30)).decode()[:40],
      'region': 'us-east-1',
      'account_id': ''.join(random.choices('0123456789', k=12)),
    }
    Format as ~/.aws/credentials file content.

  def generate_azure_credentials() → dict:
    Fake Azure service principal JSON:
    { 'clientId': str(uuid4()), 'clientSecret': secrets.token_urlsafe(32),
      'subscriptionId': str(uuid4()), 'tenantId': str(uuid4()),
      'activeDirectoryEndpointUrl': 'https://login.microsoftonline.com',
      'resourceManagerEndpointUrl': 'https://management.azure.com/',
      'comment': 'Production deployment service principal — DO NOT SHARE' }

  def generate_gcp_service_account() → dict:
    Fake GCP service account JSON key file:
    { 'type': 'service_account', 'project_id': 'corp-production',
      'private_key_id': secrets.token_hex(20),
      'private_key': '-----BEGIN RSA PRIVATE KEY-----\n' + base64.b64encode(os.urandom(400)).decode() + '\n-----END RSA PRIVATE KEY-----',
      'client_email': 'deploy-sa@corp-production.iam.gserviceaccount.com',
      'client_id': ''.join(random.choices('0123456789', k=21)),
      'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
      'token_uri': 'https://oauth2.googleapis.com/token' }

Part 2 — Fake cloud API endpoint:

Add FastAPI routes that mimic AWS STS/IAM:
  GET  /fake-aws/sts/GetCallerIdentity
    → Return fake AWS identity response (attacker's CLI 'aws sts get-caller-identity' hits this)
    → Fire CLOUD_CREDENTIAL_USED alert with their source IP and AWS region in the request
    → MITRE tag: T1552.001 (Credentials In Files)
    → Slack alert: 'AWS credential used by attacker — GetCallerIdentity called from {ip}'

  POST /fake-aws/iam/ListUsers
    → Return list of 10 fake IAM users (reveals they're doing AWS enumeration)
    → Fire alert: MITRE T1087.004 (Cloud Account Discovery)

  ANY /fake-aws/* → catch-all: log the full request (method, path, headers, body)
    This reveals exactly which AWS services they're targeting.

Part 3 — Plant credentials in fake containers:
  fake-api/server.py GET /v1/config → add aws_credentials_url pointing to canary endpoint
  fake-ssh server: add ~/.aws/credentials to persona files (generates fake AWS creds)
  When those creds are downloaded → fire credential_stolen
  When those creds are USED (hit the fake AWS endpoint) → fire cloud_credential_used

Add new Socket.IO event: 'cloud_credential_used' → { provider, api_call, attacker_ip, region }
Add Slack alert function: alert_cloud_credential_used(ip, provider, api_call)"
```
**Commit:** `feat(deception): cloud deception layer — fake AWS/Azure/GCP credentials with live-use detection`

---

### Task 12.3 — Reinforcement learning topology optimizer
```
Prompt to AI:
"Replace random Barabasi-Albert topology generation with a reinforcement learning agent
that learns which network topologies maximize attacker engagement and intelligence collection.

Add to requirements.txt: gymnasium==0.29.1, numpy==1.26.4 (already included)

Create backend/ai/rl_topology.py:

The RL formulation:
  STATE: vector of [attacker_skill_level (0-3), actions_taken (0-50), 
         current_topology_generation (0-10), session_duration_minutes (0-120),
         unique_nodes_hit (0-20), credential_attempts (0-30)]

  ACTION: integer 0-7 selecting topology configuration:
    0: hub-and-spoke (few highly connected nodes, many leaves) → good for low-skill attackers
    1: mesh (all nodes densely connected) → good for advanced lateral movement scenarios
    2: layered (DMZ → internal → core tiering) → realistic enterprise pattern
    3: star (one central server, many endpoints) → good for credential harvesting scenarios
    4: random (Barabasi-Albert, our current approach) → baseline
    5: financial-heavy (more DB + API nodes, fewer workstations) → if attacker targets finance
    6: dev-heavy (more API + file servers, git-like paths) → if attacker targets IP
    7: admin-heavy (more auth + windows nodes) → if attacker targets credentials/AD

  REWARD: computed after each topology serves an attacker session:
    +1.0 for each unique attacker action observed (engagement)
    +2.0 for each MITRE technique tagged (intelligence value)
    +3.0 for credential access or canary trigger (high-value intel)
    -1.0 if attacker disconnects within 60 seconds (bored — topology wasn't convincing)
    +0.5 for each minute attacker stays engaged (dwell time reward)

import gymnasium as gym
import numpy as np

class TopologyEnv(gym.Env):
  observation_space = gym.spaces.Box(low=0, high=200, shape=(6,), dtype=np.float32)
  action_space = gym.spaces.Discrete(8)

  def step(self, action):
    Record action choice. Return (obs, reward, done=True, truncated=False, info={}).
    done=True because each episode is one attacker session.

  def reset(self, seed=None):
    Return zeroed observation vector.

class RLTopologyOptimizer:
  Use a simple Q-learning table (not deep RL — we have limited data):
    self.q_table = np.zeros((discretized_state_count, 8))
    learning_rate = 0.1
    discount_factor = 0.9
    epsilon = 0.3  (exploration rate — 30% random, 70% exploit)

  def choose_topology(self, attacker_profile: AttackerProfile) → int:
    Build state vector from attacker profile.
    If random() < epsilon → return random action (exploration)
    Else → return argmax(q_table[state]) (exploitation)

  def update(self, state, action, reward, next_state):
    q_table[state][action] += lr * (reward + gamma * max(q_table[next_state]) - q_table[state][action])

  def save(self, path='backend/ai/q_table.npy'):
    np.save(path, self.q_table)

  def load(self, path='backend/ai/q_table.npy'):
    if os.path.exists(path): self.q_table = np.load(path)

Integrate into topology.generate_topology():
  If attacker_profile is available → use rl_optimizer.choose_topology(profile)
  Else → use action=4 (random Barabasi-Albert, same as before)
  Generate topology matching the chosen action's configuration.
  After session ends (attacker disconnects or 30min timeout) → compute reward and update Q-table.
  Save Q-table after each update (persistent learning across sessions).

The Q-table persists to disk and to Redis. Over time the system learns
  which network shapes work best against which attacker skill levels."
```
**Commit:** `feat(ai): reinforcement learning topology optimizer — system learns from every session`

---

### Task 12.4 — STIX/TAXII threat intelligence export
```
Prompt to AI:
"Create backend/intelligence/stix_exporter.py — export attacker profiles as STIX 2.1.

STIX (Structured Threat Information eXpression) is the global standard for sharing
threat intelligence with ISACs, government agencies, and law enforcement.
This turns every attacker session into a shareable threat intelligence report.

Add to requirements.txt: stix2==3.0.1

from stix2 import (ThreatActor, AttackPattern, Malware, Tool,
                    Relationship, Bundle, Report, Indicator,
                    ExternalReference, KillChainPhase)
import uuid, datetime

class STIXExporter:
  def profile_to_stix_bundle(self, profile: AttackerProfile,
                               actions: list[AttackerAction]) → dict:
    Build a complete STIX 2.1 Bundle from an attacker session.

    1. ThreatActor object:
       name = profile.apt_resemblance or 'Unknown Threat Actor'
       sophistication = { 'Script Kiddie': 'minimal', 'Intermediate': 'intermediate',
                          'Advanced': 'advanced', 'Nation-State APT': 'strategic' }[skill_level]
       aliases = [profile.attacker_ip]
       goals = [profile.objective]
       resource_level = 'government' if 'APT' in skill_level else 'criminal enterprise'

    2. Tool objects (one per tool in profile.tools_detected):
       name = tool_name
       tool_types = ['exploitation', 'reconnaissance', 'credential-exploitation']

    3. AttackPattern objects (one per unique MITRE technique observed):
       name = action.mitre_technique_name
       external_references = [ExternalReference(source_name='mitre-attack',
         external_id=action.mitre_technique_id,
         url=f'https://attack.mitre.org/techniques/{technique_id}')]
       kill_chain_phases from the tactic name

    4. Indicator object:
       name = f'Attacker IP: {profile.attacker_ip}'
       pattern = f\"[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '{profile.attacker_ip}']\"
       valid_from = datetime of first action
       indicator_types = ['malicious-activity', 'network-traffic']

    5. Relationship objects:
       ThreatActor USES Tool (for each tool)
       ThreatActor USES AttackPattern (for each MITRE technique)
       ThreatActor ATTRIBUTED-TO Indicator (IP)

    6. Report object:
       name = f'ShadowMesh Session Report — {profile.attacker_ip} — {datetime.now().date()}'
       description = profile.summary
       published = datetime.now()
       object_refs = [all object IDs above]

    7. Bundle:
       Return Bundle(objects=[all objects]).serialize(pretty=True) as JSON string

Add FastAPI routes:
  GET /api/intelligence/stix/{attacker_ip}
    → Build and return STIX bundle for that attacker's session
    → Content-Type: application/stix+json
  GET /api/intelligence/stix/all
    → Return bundle of all attacker sessions combined
  GET /api/intelligence/report/{attacker_ip}
    → Return a human-readable HTML threat intelligence report
    → Include: session timeline, MITRE heatmap summary, tools detected,
      confidence score, recommended IOCs to block

Add dashboard button: 'Export STIX 2.1' → downloads the bundle JSON for the focused attacker
Add dashboard button: 'Generate Report' → opens the HTML report in a new tab"
```
**Commit:** `feat(intelligence): stix 2.1 threat intelligence export — shareable attacker profiles`

---

## Phase 13 — Integration Layer
> **Goal: Make ShadowMesh fit into real security stacks and deploy in under 3 minutes.**
> Inspired by: Attivo (SIEM), Acalvio/Illusive (breadcrumb agent), Thinkst (zero-config).

---

### Task 13.1 — SIEM/SOAR integration
```
Prompt to AI:
"Create backend/integrations/ — native SIEM and SOAR integrations.

SIEM integration means ShadowMesh alerts appear automatically in the security team's
existing dashboard without them having to open another tool.

--- backend/integrations/siem.py ---

class SIEMIntegration:
  def __init__(self):
    self.splunk_hec_url = os.getenv('SPLUNK_HEC_URL', '')
    self.splunk_hec_token = os.getenv('SPLUNK_HEC_TOKEN', '')
    self.elastic_url = os.getenv('ELASTIC_URL', '')
    self.elastic_api_key = os.getenv('ELASTIC_API_KEY', '')
    self.sentinel_workspace_id = os.getenv('SENTINEL_WORKSPACE_ID', '')
    self.sentinel_shared_key = os.getenv('SENTINEL_SHARED_KEY', '')

  async def send_to_splunk(self, event: AttackerAction, profile: AttackerProfile = None):
    Format as Splunk HEC JSON event:
    {
      'time': event.timestamp,
      'host': 'shadowmesh',
      'source': 'shadowmesh:deception',
      'sourcetype': 'shadowmesh:attacker_action',
      'index': 'security',
      'event': {
        'action': event.action_type,
        'src_ip': event.attacker_ip,
        'dest': event.target_node_id,
        'detail': event.detail,
        'mitre_id': event.mitre_technique_id,
        'mitre_name': event.mitre_technique_name,
        'skill_level': profile.skill_level if profile else 'unknown',
        'objective': profile.objective if profile else 'unknown',
        'severity': 'critical' if event.action_type in ['credential_theft','canary_trigger'] else 'high'
      }
    }
    POST to {splunk_hec_url}/services/collector with Authorization: Splunk {token}
    Wrap in try/except — SIEM failure must never crash the main app.

  async def send_to_elastic(self, event: AttackerAction):
    POST to {elastic_url}/shadowmesh-deception/_doc with ApiKey auth.
    Index: 'shadowmesh-deception-{YYYY.MM.DD}'
    Document: same fields as Splunk event, ECS (Elastic Common Schema) format:
    { '@timestamp': ISO datetime, 'event.action': event.action_type,
      'source.ip': event.attacker_ip, 'destination.domain': event.target_node_id,
      'threat.technique.id': [event.mitre_technique_id],
      'tags': ['shadowmesh', 'deception', 'honeypot'] }

  async def send_to_sentinel(self, event: AttackerAction):
    Microsoft Sentinel uses the Data Collector API (HTTPS + HMAC-SHA256 signature).
    Build the request with proper Authorization header:
    SharedKey {workspace_id}:{base64(HMAC-SHA256(string_to_sign, shared_key))}
    POST to https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01
    Log-Type header: ShadowMeshDeception

  async def send_syslog_cef(self, event: AttackerAction, host: str = 'localhost', port: int = 514):
    Format as CEF (Common Event Format) — works with any SIEM:
    'CEF:0|ShadowMesh|DeceptionPlatform|1.0|{event.action_type}|{event.detail}|7|
    src={event.attacker_ip} dst={event.target_node_id} cs1={event.mitre_technique_id}
    cs1Label=MITRETechnique cs2={event.mitre_technique_name} cs2Label=MITREName'
    Send via UDP syslog to configured host:port.

Integrate into POST /api/attacker/action — after logging, fire SIEM in background:
  asyncio.create_task(siem.send_to_splunk(action, profile))
  asyncio.create_task(siem.send_to_elastic(action))
  asyncio.create_task(siem.send_to_sentinel(action))
  asyncio.create_task(siem.send_syslog_cef(action))

Add to .env.example:
  SPLUNK_HEC_URL=
  SPLUNK_HEC_TOKEN=
  ELASTIC_URL=
  ELASTIC_API_KEY=
  SENTINEL_WORKSPACE_ID=
  SENTINEL_SHARED_KEY=
  SYSLOG_HOST=localhost
  SYSLOG_PORT=514"
```
**Commit:** `feat(integrations): siem/soar — splunk, elastic, sentinel, syslog-cef output`

---

### Task 13.2 — Endpoint breadcrumb agent
```
Prompt to AI:
"Create agents/breadcrumb_agent.py — a lightweight Python agent that plants fake
credentials and paths on real machines, pointing into ShadowMesh's deception fabric.

This is the most powerful deception technique from Attivo/Illusive:
The attacker compromises a real endpoint, does credential dumping,
finds fake credentials pointing to our fake servers, and follows them.
They never left our fabric.

The agent is designed to run on real machines with minimal footprint.
Single Python file, no external dependencies beyond stdlib.
Can be deployed via Ansible, Chef, or simple SSH.

agents/breadcrumb_agent.py:

SHADOWMESH_CONFIG = {
  'server_url': os.getenv('SHADOWMESH_URL', 'http://shadowmesh:8000'),
  'fake_server_ips': [],  # fetched from ShadowMesh topology API
  'update_interval': 3600,  # re-fetch topology hourly
}

BREADCRUMB_TARGETS = [
  {'path': os.path.expanduser('~/.ssh/known_hosts'), 'type': 'ssh_known_hosts'},
  {'path': os.path.expanduser('~/.aws/credentials'),  'type': 'aws_credentials'},
  {'path': os.path.expanduser('~/.env'),              'type': 'env_file'},
  {'path': '/etc/hosts',                              'type': 'hosts_entry'},
  {'path': os.path.expanduser('~/.bash_history'),     'type': 'bash_history'},
]

class BreadcrumbAgent:
  def fetch_topology(self) → list[dict]:
    GET {server_url}/api/topology/current → parse nodes list
    Return [{ ip, node_type, ports, node_id }]

  def plant_ssh_known_hosts(self, fake_nodes: list[dict]):
    Append fake SSH fingerprints to ~/.ssh/known_hosts:
      {ip} ssh-rsa AAAA{realistic_fake_key}= deploy@corp.internal
    For each web_server and api_gateway node.
    Use APPEND mode — never overwrite existing entries.
    Tag with comment: # corp-infra-managed

  def plant_aws_credentials(self, fake_nodes: list[dict]):
    Append fake AWS profile to ~/.aws/credentials:
      [corp-prod]
      aws_access_key_id = {fake_key_from_shadowmesh}
      aws_secret_access_key = {fake_secret_from_shadowmesh}
      region = us-east-1
    The credentials point to ShadowMesh's fake AWS endpoint.

  def plant_bash_history(self, fake_nodes: list[dict]):
    Append realistic-looking commands referencing fake server IPs to ~/.bash_history:
      ssh admin@{fake_db_ip}
      mysql -h {fake_db_ip} -u root -p
      aws --profile corp-prod s3 ls
      curl http://{fake_api_ip}/api/config

  def plant_hosts_entry(self, fake_nodes: list[dict]):
    Append to /etc/hosts (requires sudo):
      {fake_ip}  finance-db.corp.internal  # corp-infra
      {fake_ip}  hr-share.corp.internal    # corp-infra
    These are our planted DNS canary hostnames.

  def cleanup(self):
    Remove all planted breadcrumbs (tagged with # corp-infra-managed comment).
    Called when deactivating or rotating topology.

  def run(self):
    Fetch topology every update_interval seconds.
    Plant breadcrumbs on each run.
    Log planted paths to {server_url}/api/breadcrumbs/report

Add FastAPI route POST /api/breadcrumbs/report:
  Accepts agent heartbeats: { agent_host, planted_paths, timestamp }
  Stores in Redis. Shown in dashboard as 'X breadcrumb agents active'

Add dashboard indicator: 'Breadcrumb agents: {n} active' — small green pill in status bar"
```
**Commit:** `feat(agents): endpoint breadcrumb agent — plants fake credentials on real machines`

---

### Task 13.3 — Attack surface mapper
```
Prompt to AI:
"Create backend/detection/surface_mapper.py — scan the real network segment before
generating fake topology, so our fake network mirrors the real one statistically.

This makes our fake topology indistinguishable from the real infrastructure —
not just 'a realistic enterprise network' but 'THIS specific enterprise network'.

Import: scapy.all (ARP, srp), socket, asyncio, ipaddress

class AttackSurfaceMapper:
  def __init__(self, subnet: str, interface: str):
    self.subnet = subnet  # e.g. '192.168.1.0/24'
    self.interface = interface

  async def discover_hosts(self) → list[dict]:
    Use ARP broadcast to discover live hosts in the subnet.
    scapy srp(ARP(pdst=self.subnet), timeout=2, iface=self.interface, verbose=False)
    For each responding host: record IP, MAC address.
    Do NOT scan these hosts further — just note they exist (passive presence detection).
    Return [{ ip, mac }]

  async def estimate_service_distribution(self, live_hosts: list[dict]) → dict:
    For each discovered host, do a quick TCP SYN scan on common ports:
    [22, 80, 443, 3306, 5432, 445, 389, 3389, 8080, 8443]
    Timeout: 0.5s per port. Do NOT connect — just SYN and check for SYN-ACK.
    Categorize each host:
      port 80/443 open → web_server
      port 3306/5432 open → db_server
      port 389 open → auth_service
      port 445 open → file_server
      port 3389 open → workstation
      port 22 only → generic_server

    Return distribution: { 'web_server': 3, 'db_server': 2, 'auth_service': 1, ... }

  async def generate_mirrored_topology(self, target_count: int = 15) → TopologySnapshot:
    Call discover_hosts() + estimate_service_distribution().
    Generate a fake topology with the same TYPE RATIOS as the real network.
    If real network is 40% web servers → fake topology is 40% web servers.
    Use different IPs (from our deception subnet 172.20.0.0/24) for all fake nodes.
    Return TopologySnapshot with mirrored distribution.

Integrate into main.py:
  On startup: run surface_mapper.generate_mirrored_topology() in the background.
  Store result as default_topology_template.
  When deception is first activated: use mirrored topology instead of random.
  After first mutation: use RL optimizer to choose topology style.

Add to smoke_test: surface mapper discovers at least 1 host on the subnet."
```
**Commit:** `feat(detection): attack surface mapper — fake topology mirrors real network ratios`

---

### Task 13.4 — Zero-config bootstrap script
```
Prompt to AI:
"Create scripts/bootstrap.sh — a single script that installs, configures, and starts
ShadowMesh in under 3 minutes on any Linux machine with Docker installed.

Inspired by Thinkst Canary's zero-friction deployment philosophy.

#!/bin/bash
set -e

echo '╔═══════════════════════════════════╗'
echo '║   ShadowMesh — Bootstrap v1.0     ║'
echo '╚═══════════════════════════════════╝'

# Step 1: Check prerequisites
command -v docker >/dev/null 2>&1 || { echo '❌ Docker not found. Install from https://docs.docker.com/get-docker/'; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo '❌ docker-compose not found.'; exit 1; }

# Step 2: Auto-detect network interface
INTERFACE=$(ip route show default 2>/dev/null | awk '/default/ { print $5 }' | head -1)
if [ -z '$INTERFACE' ]; then
  INTERFACE=$(ip link show | awk -F: '($2 ~ /^[[:space:]]*eth|ens|enp|wlan/) {gsub(' ', '', $2); print $2}' | head -1)
fi
echo '🔍 Detected network interface: '$INTERFACE

# Step 3: Generate .env if missing
if [ ! -f .env ]; then
  echo '📝 Creating .env from template...'
  cp .env.example .env
  sed -i s/NETWORK_INTERFACE=auto/NETWORK_INTERFACE=$INTERFACE/ .env
  # Prompt for required vars
  read -p '   Groq API Key (get from console.groq.com): ' GROQ_KEY
  sed -i s/GROQ_API_KEY=/GROQ_API_KEY=$GROQ_KEY/ .env
  read -p '   Slack Webhook URL (optional, press enter to skip): ' SLACK_URL
  if [ -n '$SLACK_URL' ]; then
    sed -i s|SLACK_WEBHOOK_URL=|SLACK_WEBHOOK_URL=$SLACK_URL| .env
  fi
fi

# Step 4: Download MITRE ATT&CK data
if [ ! -f backend/mitre/enterprise-attack.json ]; then
  echo '📥 Downloading MITRE ATT&CK dataset...'
  python3 scripts/download_mitre.py
fi

# Step 5: Build all images
echo '🔨 Building honeypot images...'
bash scripts/build_images.sh

# Step 6: Start all services
echo '🚀 Starting ShadowMesh...'
docker-compose up -d

# Step 7: Wait for health
echo '⏳ Waiting for services...'
MAX_WAIT=60
WAITED=0
while ! curl -sf http://localhost:8000/health >/dev/null 2>&1; do
  sleep 2; WAITED=$((WAITED+2))
  if [ $WAITED -ge $MAX_WAIT ]; then echo '❌ Timeout waiting for backend'; exit 1; fi
done

# Step 8: Run smoke tests
echo '🧪 Running smoke tests...'
python3 scripts/smoke_test.py

echo ''
echo '✅ ShadowMesh is running!'
echo ''
echo '   Dashboard:  http://localhost:5173'
echo '   API:        http://localhost:8000'
echo '   Neo4j:      http://localhost:7474'
echo ''
echo '   To simulate an attack:    python3 scripts/simulate_attacker.py'
echo '   To stop:                  docker-compose down'
echo ''

Make the script executable: chmod +x scripts/bootstrap.sh

Also create scripts/teardown.sh:
  Gracefully stops all services, removes containers, preserves volumes.
  docker-compose down
  docker ps -a | grep sm_ | awk '{print $1}' | xargs -r docker rm -f
  echo '✅ ShadowMesh stopped. Data preserved in Docker volumes.'"
```
**Commit:** `feat(deploy): zero-config bootstrap — full install in under 3 minutes`

---

## Phase 11–13 Summary

| Task | Feature | Inspired by | Impact |
|---|---|---|---|
| 11.1 | Persona decoys | Smokescreen | Fake human fingerprint in every container — years of bash history, git config, SSH keys |
| 11.2 | RDP replay engine | Smokescreen | Fake Windows desktop on port 3389 — hardest to fingerprint honeypot type |
| 11.3 | Projection sensors | Acalvio | 50+ fake nodes without Docker overhead — ARP + banner responders |
| 11.4 | Protocol expansion | Gap | SMB, MQTT, Redis, Elasticsearch honeypots — full enterprise protocol coverage |
| 11.5 | Decoy documents | Gap | Fake Office/PDF files with embedded canary URLs — post-exfiltration detection |
| 12.1 | Active Directory deception | Attivo / Illusive | Full fake AD: 50 users, 20 computers, groups — biggest gap vs commercial products |
| 12.2 | Cloud deception layer | Gap | Fake AWS/Azure/GCP credentials + fake cloud API endpoint — no commercial product has this |
| 12.3 | RL topology optimizer | Gap | System learns which network shapes maximize attacker engagement over time |
| 12.4 | STIX/TAXII export | CounterCraft | Every attacker session becomes shareable threat intelligence in global standard format |
| 13.1 | SIEM/SOAR integration | Attivo | Native Splunk, Elastic, Sentinel, CEF syslog — alerts appear in existing SOC dashboards |
| 13.2 | Breadcrumb agent | Acalvio / Illusive | Plants fake credentials on real machines — attacker follows breadcrumbs into deception fabric |
| 13.3 | Attack surface mapper | Gap | Fake topology mirrors real network ratios — statistically indistinguishable from actual infrastructure |
| 13.4 | Zero-config bootstrap | Thinkst | Single script, under 3 minutes, auto-detects interface, prompts for only 2 variables |

---

## Phase Summary

| Phase | Owner | What gets built | Target hours |
|---|---|---|---|
| 0 | ALL | Scaffold, Compose, shared models (+ FakeCredential, CanaryToken), MITRE download | 0–2 |
| 1 | T2 | FastAPI + Socket.IO + Neo4j client + REST routes + **Slack webhook** | 2–6 |
| 2 | Dealer | React layout, Zustand (+ canary/cred state), Socket.IO wiring, AlertFeed | 2–6 |
| 3 | T3 | Groq profiler, NetworkX topology, MITRE mapper, mutator, **adaptive lure generator** | 2–8 |
| 4 | T4 | **4 distinct fake containers** (http/db/api/auth), container manager, **fake creds**, **canary tokens**, Neo4j | 2–8 |
| 5 | T2 | Scapy detector + demo simulator (+ credential theft + canary phases) | 6–10 |
| 6 | ALL | Integration — every component wired, Slack fires, lures spawn, canaries alert | 10–16 |
| 7 | Dealer | NetworkGraph, MITRE heatmap, AttackerProfile, polish | 16–20 |
| 8 | ALL | Smoke test (12 checks), error handling, demo script rehearsal | 20–24 |
| **10** | **All (parallel)** | **7 critical failure fixes — race condition, interface detection, Docker images, Neo4j retry, heuristic profiler, MITRE lazy load, force-graph stable keys** | **alongside P6–P8** |
| **9** | **All (parallel)** | **Redis persistence, multi-attacker frontend, IsolationForest ML, DNS honeypot, orchestrator sidecar** | **if time permits** |

---

## Pre-Demo Checklist

```
[ ] scripts/build_images.sh ran successfully — all 5 images exist
[ ] NETWORK_INTERFACE=auto in .env → smoke test confirms correct interface detected
[ ] docker-compose up -d → all containers healthy (neo4j, redis, orchestrator, backend, frontend)
[ ] python scripts/smoke_test.py → 12/12 passed
[ ] python scripts/download_mitre.py → enterprise-attack.json exists
[ ] GROQ_API_KEY is valid (test with a curl to Groq API)
[ ] SLACK_WEBHOOK_URL is set → send a test message, confirm it arrives
[ ] Frontend loads at localhost:5173
[ ] Socket.IO connects as WebSocket (not polling) — check browser Network tab → WS
[ ] Trigger scan via Demo Control Bar → topology appears in graph (containers actually running)
[ ] Fake creds reachable: GET /api/creds/{node_id}/{cred_id} returns content
[ ] Canary fires: GET /api/canary/{token_id} → alert appears in dashboard
[ ] AttackerProfile shows LOCAL badge within 1 second of first action (heuristic works)
[ ] simulate_attacker.py runs cleanly end-to-end
[ ] Topology mutation animation plays without graph crash
[ ] AttackerProfile upgrades to AI ENHANCED badge after Groq enrichment
[ ] MITRE heatmap shows at least 3 techniques after full simulation
[ ] Rehearse the 5-minute demo script at least twice
[ ] Run demo twice in a row — second run starts clean (teardown working)
```
