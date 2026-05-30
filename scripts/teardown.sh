#!/bin/bash
# ShadowMesh — Graceful Teardown
# Stops all services, removes honeypot containers, preserves data volumes.

set -e

echo '╔═══════════════════════════════════╗'
echo '║   ShadowMesh — Teardown           ║'
echo '╚═══════════════════════════════════╝'

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
