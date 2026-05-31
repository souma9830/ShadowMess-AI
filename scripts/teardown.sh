#!/bin/bash
<<<<<<< HEAD
# scripts/teardown.sh
# Task 13.4 - Graceful teardown for ShadowMesh
# Stops all services, removes honeypot containers, preserves named volumes (data).
#
# Usage:
#   bash scripts/teardown.sh
=======
# ShadowMesh — Graceful Teardown
# Stops all services, removes honeypot containers, preserves data volumes.
>>>>>>> 38d5f488fa059baa9e803a273fda1e611995d0ed

set -e

echo '╔═══════════════════════════════════╗'
echo '║   ShadowMesh — Teardown           ║'
echo '╚═══════════════════════════════════╝'
<<<<<<< HEAD
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
=======

echo '🛑 Stopping docker-compose services...'
docker-compose down 2>/dev/null || docker compose down 2>/dev/null || true

echo '🧹 Removing leftover honeypot containers...'
CONTAINERS=$(docker ps -a --filter "name=sm_" -q 2>/dev/null)
if [ -n "$CONTAINERS" ]; then
  echo "$CONTAINERS" | xargs docker rm -f 2>/dev/null || true
  echo "   Removed $(echo "$CONTAINERS" | wc -l) containers"
else
  echo "   No leftover containers found"
fi

echo ''
echo '✅ ShadowMesh stopped. Data preserved in Docker volumes.'
echo '   To remove all data: docker volume rm neo4j_data neo4j_logs redis_data'
echo '   To restart: docker-compose up -d'
>>>>>>> 38d5f488fa059baa9e803a273fda1e611995d0ed
