#!/bin/bash
set -e

echo "[*] ShadowMesh Pre-Demo Checklist: Building and Pulling Images"

# Base images used by topology generator
echo "[1/2] Pulling base deception images..."
docker pull ubuntu:20.04
docker pull ubuntu:22.04
docker pull centos:7
docker pull nginx:1.18.0
docker pull mysql:8.0.28
docker pull httpd:2.4

echo "[2/2] Rebuilding backend and orchestrator images (if needed)..."
docker-compose build

echo "[+] Pre-demo image setup complete. You are ready to run."
