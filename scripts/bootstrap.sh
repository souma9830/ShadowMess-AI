#!/bin/bash
# ShadowMesh Zero-Friction Bootstrap Script
# Deploys the entire stack in under 3 minutes.

set -e

echo "============================================================"
echo "    ShadowMesh - Zero-Friction Setup"
echo "============================================================"

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "[!] Docker is not installed. Please install Docker Desktop or Docker Engine."
    exit 1
fi

# Copy .env if not exists
if [ ! -f .env ]; then
    echo "[*] Creating .env from .env.example..."
    cp .env.example .env
fi

# Prompt for API key
read -p "[?] Enter Groq API Key (leave blank if you don't have one): " GROQ_KEY
if [ -n "$GROQ_KEY" ]; then
    sed -i "s/^GROQ_API_KEY=.*/GROQ_API_KEY=${GROQ_KEY}/" .env
fi

# Prompt for Network Interface
echo "[?] Enter the network interface for Scapy to listen on (e.g., eth0, wlan0). "
read -p "    Press Enter to auto-detect: " IFACE
if [ -n "$IFACE" ]; then
    sed -i "s/^NETWORK_INTERFACE=.*/NETWORK_INTERFACE=${IFACE}/" .env
fi

echo "[*] Building and starting ShadowMesh containers..."
docker compose up -d --build

echo "============================================================"
echo "[+] Deployment Complete!"
echo "[+] Frontend Dashboard:  http://localhost:5173"
echo "[+] Backend API:         http://localhost:8000"
echo "[+] Neo4j Browser:       http://localhost:7474 (neo4j/shadowmesh)"
echo "============================================================"
echo "[!] To simulate an attack, run: python scripts/simulate_attacker.py"
