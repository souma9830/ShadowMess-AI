#!/bin/bash
# scripts/teardown.sh
# Task 13.4 - Graceful teardown for ShadowMesh
# Stops all services, removes honeypot containers, preserves named volumes (data).
#
# Usage:
#   bash scripts/teardown.sh

set -e

echo '╔═══════════════════════════════════╗'
echo '║   ShadowMesh — Teardown           ║'
echo '╚═══════════════════════════════════╝'
echo ''

# Detect compose command
COMPOSE_CMD=''
if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD='docker-compose'
elif docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD='docker compose'
fi

# Stop docker-compose services
if [ -n "$COMPOSE_CMD" ] && [ -f docker-compose.yml ]; then
  echo '🛑 Stopping ShadowMesh services...'
  $COMPOSE_CMD down
  echo '✅ Services stopped.'
fi

# Remove any lingering sm_* honeypot containers spawned dynamically
LINGERING=$(docker ps -a --format '{{.ID}} {{.Names}}' 2>/dev/null | grep ' sm_' | awk '{print $1}')
if [ -n "$LINGERING" ]; then
  echo '🧹 Removing lingering honeypot containers...'
  echo "$LINGERING" | xargs docker rm -f
  echo '✅ Honeypot containers removed.'
fi

echo ''
echo '✅ ShadowMesh stopped. Named volumes preserved (Neo4j data, Redis data).'
echo '   To remove volumes too: docker-compose down -v'
echo ''
