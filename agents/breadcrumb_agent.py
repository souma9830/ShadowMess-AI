"""
ShadowMesh — Task 13.2: Endpoint Breadcrumb Agent
==================================================
A lightweight standalone agent that plants fake credentials and paths on real
machines, pointing into ShadowMesh's deception fabric. When an attacker
compromises the endpoint and follows the breadcrumbs, they enter our trap.

Deployment: Single file, no external dependencies beyond stdlib.
Run via: python breadcrumb_agent.py
Can be deployed via Ansible, Chef, or simple SSH.

Environment variables:
  SHADOWMESH_URL  — Backend API URL (default: http://localhost:8000)
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import socket
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional

SHADOWMESH_URL = os.getenv("SHADOWMESH_URL", "http://localhost:8000")
UPDATE_INTERVAL = int(os.getenv("BREADCRUMB_INTERVAL", "3600"))
BREADCRUMB_TAG = "# corp-infra-managed"

AGENT_HOST = platform.node() or socket.gethostname()


class BreadcrumbAgent:

    def __init__(self, server_url: str = SHADOWMESH_URL):
        self.server_url = server_url.rstrip("/")
        self._planted_paths: List[str] = []

    def fetch_topology(self) -> List[Dict]:
        try:
            url = f"{self.server_url}/api/topology/current"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return data.get("nodes", [])
        except Exception as e:
            print(f"[breadcrumb] Failed to fetch topology: {e}")
            return []

    def plant_ssh_known_hosts(self, fake_nodes: List[Dict]) -> List[str]:
        path = Path.home() / ".ssh" / "known_hosts"
        path.parent.mkdir(parents=True, exist_ok=True)

        entries = []
        for node in fake_nodes:
            if node.get("node_type") in ("web_server", "api_gateway", "db_server"):
                ip = node.get("ip", "172.20.0.10")
                fake_key = secrets.token_urlsafe(48)
                entry = f"{ip} ssh-rsa AAAA{fake_key}= deploy@corp.internal {BREADCRUMB_TAG}"
                entries.append(entry)

        if entries:
            existing = path.read_text() if path.exists() else ""
            new_entries = [e for e in entries if e.split(" ")[0] not in existing]
            if new_entries:
                with open(path, "a") as f:
                    f.write("\n" + "\n".join(new_entries) + "\n")
                self._planted_paths.append(str(path))

        return entries

    def plant_aws_credentials(self, fake_nodes: List[Dict]) -> Optional[str]:
        path = Path.home() / ".aws" / "credentials"
        path.parent.mkdir(parents=True, exist_ok=True)

        fake_key_id = "AKIA" + secrets.token_hex(8).upper()
        fake_secret = secrets.token_urlsafe(30)

        profile_block = (
            f"\n[corp-prod] {BREADCRUMB_TAG}\n"
            f"aws_access_key_id = {fake_key_id}\n"
            f"aws_secret_access_key = {fake_secret}\n"
            f"region = us-east-1\n"
        )

        existing = path.read_text() if path.exists() else ""
        if "corp-prod" not in existing:
            with open(path, "a") as f:
                f.write(profile_block)
            self._planted_paths.append(str(path))

        return profile_block

    def plant_bash_history(self, fake_nodes: List[Dict]) -> List[str]:
        path = Path.home() / ".bash_history"

        commands = []
        for node in fake_nodes[:5]:
            ip = node.get("ip", "172.20.0.10")
            ntype = node.get("node_type", "web_server")
            if ntype == "db_server":
                commands.append(f"mysql -h {ip} -u root -p")
                commands.append(f"psql -h {ip} -U admin -d production")
            elif ntype == "web_server":
                commands.append(f"curl http://{ip}/api/config")
            elif ntype == "api_gateway":
                commands.append(f"curl -H 'Authorization: Bearer sk-prod-xxx' http://{ip}/v1/health")
            elif ntype == "auth_service":
                commands.append(f"ldapsearch -H ldap://{ip} -b 'dc=corp,dc=internal' '(objectClass=user)'")
            commands.append(f"ssh admin@{ip}")

        commands.append("aws --profile corp-prod s3 ls")
        commands.append("aws --profile corp-prod sts get-caller-identity")

        tagged = [f"{cmd}  {BREADCRUMB_TAG}" for cmd in commands]

        if tagged:
            existing = path.read_text() if path.exists() else ""
            new_cmds = [c for c in tagged if c not in existing]
            if new_cmds:
                with open(path, "a") as f:
                    f.write("\n".join(new_cmds) + "\n")
                self._planted_paths.append(str(path))

        return commands

    def plant_hosts_entry(self, fake_nodes: List[Dict]) -> List[str]:
        hosts_path = Path("/etc/hosts")
        if not hosts_path.exists() or not os.access(hosts_path, os.W_OK):
            return []

        entries = []
        hostnames = [
            ("finance-db.corp.internal", "db_server"),
            ("hr-share.corp.internal", "file_server"),
            ("ad-dc.corp.internal", "auth_service"),
            ("dev-gitlab.corp.internal", "api_gateway"),
        ]

        for hostname, target_type in hostnames:
            matching = [n for n in fake_nodes if n.get("node_type") == target_type]
            if matching:
                ip = matching[0]["ip"]
                entries.append(f"{ip}  {hostname}  {BREADCRUMB_TAG}")

        if entries:
            existing = hosts_path.read_text()
            new_entries = [e for e in entries if e.split()[1] not in existing]
            if new_entries:
                with open(hosts_path, "a") as f:
                    f.write("\n" + "\n".join(new_entries) + "\n")
                self._planted_paths.append(str(hosts_path))

        return entries

    def cleanup(self) -> int:
        removed = 0
        targets = [
            Path.home() / ".ssh" / "known_hosts",
            Path.home() / ".aws" / "credentials",
            Path.home() / ".bash_history",
            Path("/etc/hosts"),
        ]

        for path in targets:
            if not path.exists():
                continue
            try:
                lines = path.read_text().splitlines()
                cleaned = [l for l in lines if BREADCRUMB_TAG not in l]
                if len(cleaned) < len(lines):
                    path.write_text("\n".join(cleaned) + "\n")
                    removed += len(lines) - len(cleaned)
            except PermissionError:
                pass

        self._planted_paths.clear()
        return removed

    def report_heartbeat(self) -> bool:
        try:
            payload = json.dumps({
                "agent_host": AGENT_HOST,
                "planted_paths": self._planted_paths,
                "timestamp": time.time(),
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self.server_url}/api/breadcrumbs/report",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[breadcrumb] Heartbeat failed: {e}")
            return False

    def run_once(self) -> None:
        print(f"[breadcrumb] Fetching topology from {self.server_url}...")
        nodes = self.fetch_topology()
        if not nodes:
            print("[breadcrumb] No topology available, skipping.")
            return

        print(f"[breadcrumb] Planting breadcrumbs ({len(nodes)} nodes)...")
        self.plant_ssh_known_hosts(nodes)
        self.plant_aws_credentials(nodes)
        self.plant_bash_history(nodes)
        self.plant_hosts_entry(nodes)

        print(f"[breadcrumb] Planted {len(self._planted_paths)} breadcrumb files.")
        self.report_heartbeat()

    def run(self) -> None:
        print(f"[breadcrumb] ShadowMesh Breadcrumb Agent starting")
        print(f"[breadcrumb] Server: {self.server_url}")
        print(f"[breadcrumb] Host: {AGENT_HOST}")
        print(f"[breadcrumb] Interval: {UPDATE_INTERVAL}s")

        while True:
            try:
                self.run_once()
            except KeyboardInterrupt:
                print("\n[breadcrumb] Cleaning up...")
                removed = self.cleanup()
                print(f"[breadcrumb] Removed {removed} breadcrumb entries.")
                break
            except Exception as e:
                print(f"[breadcrumb] Error: {e}")

            time.sleep(UPDATE_INTERVAL)


if __name__ == "__main__":
    agent = BreadcrumbAgent()
    agent.run()
