#!/bin/bash
set -e

echo "[*] Building ShadowMesh honeypot images..."

docker build -t shadowmesh-fake-ssh           ./docker/fake-ssh           || exit 1
docker build -t shadowmesh-fake-http          ./docker/fake-http          || exit 1
docker build -t shadowmesh-fake-db            ./docker/fake-db            || exit 1
docker build -t shadowmesh-fake-api           ./docker/fake-api           || exit 1
docker build -t shadowmesh-fake-auth          ./docker/fake-auth          || exit 1
docker build -t shadowmesh-fake-rdp           ./docker/fake-rdp           || exit 1
docker build -t shadowmesh-fake-smb           ./docker/fake-smb           || exit 1
docker build -t shadowmesh-fake-mqtt          ./docker/fake-mqtt          || exit 1
docker build -t shadowmesh-fake-redis         ./docker/fake-redis         || exit 1
docker build -t shadowmesh-fake-elasticsearch ./docker/fake-elasticsearch || exit 1

echo "[+] All 10 honeypot images built successfully."
echo "    shadowmesh-fake-ssh"
echo "    shadowmesh-fake-http"
echo "    shadowmesh-fake-db"
echo "    shadowmesh-fake-api"
echo "    shadowmesh-fake-auth"
echo "    shadowmesh-fake-rdp"
echo "    shadowmesh-fake-smb"
echo "    shadowmesh-fake-mqtt"
echo "    shadowmesh-fake-redis"
echo "    shadowmesh-fake-elasticsearch"
