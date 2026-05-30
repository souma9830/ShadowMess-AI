#!/bin/bash
# scripts/bootstrap.sh
# Task 13.4 - Zero-config bootstrap for ShadowMesh
# Installs, configures, and starts ShadowMesh in under 3 minutes on any Linux
# machine with Docker installed. Inspired by Thinkst Canary's deployment philosophy.
#
# Usage:
#   chmod +x scripts/bootstrap.sh
#   ./scripts/bootstrap.sh

set -e

echo '╔═══════════════════════════════════╗'
echo '║   ShadowMesh — Bootstrap v1.0     ║'
echo '╚═══════════════════════════════════╝'
echo ''

# ---------------------------------------------------------------------------
# Step 1: Check prerequisites
# ---------------------------------------------------------------------------
echo '🔍 Checking prerequisites...'

command -v docker >/dev/null 2>&1 || {
  echo '❌ Docker not found. Install from https://docs.docker.com/get-docker/'
  exit 1
}

# Support both standalone docker-compose and plugin form
COMPOSE_CMD=''
if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD='docker-compose'
elif docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD='docker compose'
else
  echo '❌ docker-compose not found. Install from https://docs.docker.com/compose/'
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {
  echo '❌ python3 not found. Please install Python 3.9+.'
  exit 1
}

echo '✅ Prerequisites satisfied.'
echo ''

# ---------------------------------------------------------------------------
# Step 2: Auto-detect network interface
# ---------------------------------------------------------------------------
INTERFACE=$(ip route show default 2>/dev/null | awk '/default/ { print $5 }' | head -1)
if [ -z "$INTERFACE" ]; then
  INTERFACE=$(ip link show 2>/dev/null | awk -F: '($2 ~ /^ *(eth|ens|enp|wlan)/) {gsub(/ /,"",$2); print $2}' | head -1)
fi
if [ -z "$INTERFACE" ]; then
  INTERFACE="eth0"
  echo "⚠️  Could not detect interface — defaulting to eth0."
fi
echo "🌐 Detected network interface: $INTERFACE"
echo ''

# ---------------------------------------------------------------------------
# Step 3: Generate .env if missing
# ---------------------------------------------------------------------------
if [ ! -f .env ]; then
  echo '📝 Creating .env from template...'
  if [ ! -f .env.example ]; then
    echo '❌ .env.example not found. Are you running from the ShadowMesh root directory?'
    exit 1
  fi
  cp .env.example .env
  sed -i "s/NETWORK_INTERFACE=auto/NETWORK_INTERFACE=$INTERFACE/" .env

  echo ''
  read -rp '   Groq API Key (get free key from console.groq.com): ' GROQ_KEY
  if [ -n "$GROQ_KEY" ]; then
    sed -i "s/GROQ_API_KEY=/GROQ_API_KEY=$GROQ_KEY/" .env
    echo '   ✅ GROQ_API_KEY saved.'
  else
    echo '   ⚠️  No Groq key provided — profiler will run in local heuristic mode.'
  fi

  echo ''
  read -rp '   Slack Webhook URL (optional — press Enter to skip): ' SLACK_URL
  if [ -n "$SLACK_URL" ]; then
    sed -i "s|SLACK_WEBHOOK_URL=|SLACK_WEBHOOK_URL=$SLACK_URL|" .env
    echo '   ✅ SLACK_WEBHOOK_URL saved.'
  fi

  echo ''
  echo '✅ .env configured.'
else
  echo '✅ .env already exists — skipping configuration.'
fi
echo ''

# ---------------------------------------------------------------------------
# Step 4: Download MITRE ATT&CK dataset
# ---------------------------------------------------------------------------
if [ ! -f backend/mitre/enterprise-attack.json ]; then
  echo '📥 Downloading MITRE ATT&CK dataset (~60 MB)...'
  python3 scripts/download_mitre.py
  echo '✅ MITRE dataset ready.'
else
  echo '✅ MITRE ATT&CK dataset already present.'
fi
echo ''

# ---------------------------------------------------------------------------
# Step 5: Install Python dependencies (for scripts)
# ---------------------------------------------------------------------------
echo '📦 Installing Python dependencies...'
pip3 install -q -r requirements.txt
echo '✅ Python dependencies installed.'
echo ''

# ---------------------------------------------------------------------------
# Step 6: Install frontend dependencies
# ---------------------------------------------------------------------------
if [ -d frontend ] && [ ! -d frontend/node_modules ]; then
  echo '📦 Installing frontend npm packages...'
  cd frontend
  npm install --legacy-peer-deps --silent
  cd ..
  echo '✅ Frontend packages installed.'
fi
echo ''

# ---------------------------------------------------------------------------
# Step 7: Build Docker images
# ---------------------------------------------------------------------------
echo '🔨 Building Docker images...'
$COMPOSE_CMD build --parallel
echo '✅ Docker images built.'
echo ''

# ---------------------------------------------------------------------------
# Step 8: Start all services
# ---------------------------------------------------------------------------
echo '🚀 Starting ShadowMesh...'
$COMPOSE_CMD up -d
echo ''

# ---------------------------------------------------------------------------
# Step 9: Wait for backend health
# ---------------------------------------------------------------------------
echo '⏳ Waiting for services to become healthy...'
MAX_WAIT=120
WAITED=0
until curl -sf http://localhost:8000/health >/dev/null 2>&1; do
  sleep 3
  WAITED=$((WAITED + 3))
  printf '   %ds elapsed...\r' "$WAITED"
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo ''
    echo '❌ Timeout waiting for backend. Check logs: docker-compose logs backend'
    exit 1
  fi
done
echo ''
echo '✅ Backend healthy.'
echo ''

# ---------------------------------------------------------------------------
# Step 10: Run smoke tests
# ---------------------------------------------------------------------------
echo '🧪 Running smoke tests...'
python3 scripts/smoke_test.py || {
  echo '⚠️  Some smoke tests failed — check output above.'
  echo '   ShadowMesh is still running but may have issues.'
}
echo ''

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo '╔════════════════════════════════════════╗'
echo '║   ✅  ShadowMesh is running!           ║'
echo '╚════════════════════════════════════════╝'
echo ''
echo '   Dashboard:   http://localhost:5173'
echo '   API:         http://localhost:8000'
echo '   API docs:    http://localhost:8000/docs'
echo '   Neo4j:       http://localhost:7474  (user: neo4j / pass: shadowmesh)'
echo ''
echo '   Simulate an attack:   python3 scripts/simulate_attacker.py'
echo '   View logs:            docker-compose logs -f'
echo '   Stop everything:      bash scripts/teardown.sh'
echo ''
