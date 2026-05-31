<<<<<<< HEAD
#!/usr/bin/env python3
"""
Task 13.2 - Endpoint Breadcrumb Agent
Plants fake credentials and fake server paths on real machines, pointing into
ShadowMesh's deception fabric.

When an attacker compromises a real endpoint and dumps credentials, they find
fake SSH keys / AWS credentials / bash history referencing our honeypot IPs.
They follow the breadcrumbs — and never leave our deception fabric.

Usage:
    # plant breadcrumbs and keep running:
    python agents/breadcrumb_agent.py

    # cleanup all planted entries:
    python agents/breadcrumb_agent.py --cleanup

Design:
  - Single file, stdlib only (no external deps beyond 'requests' which is
    already installed on most machines).
  - All planted lines are tagged with a unique magic comment so cleanup is
    deterministic: # shadowmesh-breadcrumb
  - APPEND-only writes — never truncates existing files.
  - /etc/hosts planting requires elevated privileges and is skipped gracefully
    when running as a non-root user.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import random
import string
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("breadcrumb_agent")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SHADOWMESH_CONFIG = {
    "server_url":       os.getenv("SHADOWMESH_URL", "http://shadowmesh:8000"),
    "fake_server_ips":  [],        # populated from topology API
    "update_interval":  3600,      # re-fetch topology hourly (seconds)
}

BREADCRUMB_TAG = "# shadowmesh-breadcrumb"

BREADCRUMB_TARGETS = [
    {"path": os.path.expanduser("~/.ssh/known_hosts"), "type": "ssh_known_hosts"},
    {"path": os.path.expanduser("~/.aws/credentials"),  "type": "aws_credentials"},
    {"path": os.path.expanduser("~/.env"),              "type": "env_file"},
    {"path": "/etc/hosts",                              "type": "hosts_entry"},
    {"path": os.path.expanduser("~/.bash_history"),     "type": "bash_history"},
]

DNS_CANARY_NAMES = [
    "finance-db.corp.internal",
    "hr-share.corp.internal",
    "ad-dc.corp.internal",
    "backup-server.corp.internal",
    "dev-gitlab.corp.internal",
    "vault.corp.internal",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_rsa_key() -> str:
    """Generate a plausible-looking fake RSA public key fragment."""
    payload = base64.b64encode(os.urandom(270)).decode()
    return f"AAAB3NzaC1yc2E{payload[:200]}="


def _fake_aws_key_id() -> str:
    return "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))


def _fake_aws_secret() -> str:
    return base64.b64encode(os.urandom(30)).decode()[:40]


def _append_tagged(path: str, lines: list[str]) -> bool:
    """
    Append lines to file only if they are not already present.
    Creates parent directories if needed.
    Returns True on success.
    """
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        existing = p.read_text(errors="replace") if p.exists() else ""

        new_lines = [l for l in lines if l not in existing]
        if not new_lines:
            logger.debug("  Already planted in %s", path)
            return True

        with p.open("a") as fh:
            fh.write("\n")
            for line in new_lines:
                fh.write(line + "\n")
        logger.info("  Planted %d line(s) → %s", len(new_lines), path)
        return True
    except PermissionError:
        logger.warning("  Permission denied: %s (skipped)", path)
        return False
    except Exception as exc:
        logger.warning("  Failed to write %s: %s", path, exc)
        return False


def _remove_tagged(path: str) -> bool:
    """Remove all lines containing BREADCRUMB_TAG from the file."""
    try:
        p = Path(path)
        if not p.exists():
            return True
        lines = p.read_text(errors="replace").splitlines(keepends=True)
        cleaned = [l for l in lines if BREADCRUMB_TAG not in l]
        if len(cleaned) == len(lines):
            return True
        p.write_text("".join(cleaned))
        logger.info("  Cleaned %d line(s) from %s", len(lines) - len(cleaned), path)
        return True
    except PermissionError:
        logger.warning("  Permission denied cleaning %s (skipped)", path)
        return False
    except Exception as exc:
        logger.warning("  Failed to clean %s: %s", path, exc)
        return False


# ---------------------------------------------------------------------------
# BreadcrumbAgent
# ---------------------------------------------------------------------------

class BreadcrumbAgent:

    def __init__(self) -> None:
        self.server_url     = SHADOWMESH_CONFIG["server_url"]
        self.update_interval = SHADOWMESH_CONFIG["update_interval"]
        self.planted_paths: list[str] = []

    # ------------------------------------------------------------------
    # Topology fetch
    # ------------------------------------------------------------------
    def fetch_topology(self) -> list[dict]:
        """GET /api/topology/current from ShadowMesh backend."""
        try:
            url = f"{self.server_url}/api/topology/current"
            req = urllib.request.urlopen(url, timeout=10)  # noqa: S310
            data = json.loads(req.read())
            nodes = data.get("nodes", [])
            logger.info("Fetched %d node(s) from ShadowMesh topology.", len(nodes))
            return nodes
        except Exception as exc:
            logger.warning("Could not fetch topology: %s — using cached IPs.", exc)
            return [{"ip": ip, "node_type": "web_server", "ports": [80, 443], "node_id": f"cached_{ip}"}
                    for ip in SHADOWMESH_CONFIG["fake_server_ips"]]

    # ------------------------------------------------------------------
    # Planting methods
    # ------------------------------------------------------------------
    def plant_ssh_known_hosts(self, fake_nodes: list[dict]) -> None:
        path = os.path.expanduser("~/.ssh/known_hosts")
        lines = []
        for node in fake_nodes:
            if node.get("node_type") in ("web_server", "api_gateway", "generic_server"):
                ip = node["ip"]
                key = _fake_rsa_key()
                lines.append(f"{ip} ssh-rsa {key} deploy@corp.internal {BREADCRUMB_TAG}")
                lines.append(f"# corp-infra-managed {BREADCRUMB_TAG}")
        _append_tagged(path, lines)
        if lines:
            self.planted_paths.append(path)

    def plant_aws_credentials(self, fake_nodes: list[dict]) -> None:
        path = os.path.expanduser("~/.aws/credentials")
        key_id  = _fake_aws_key_id()
        secret  = _fake_aws_secret()
        lines = [
            f"[corp-prod] {BREADCRUMB_TAG}",
            f"aws_access_key_id = {key_id} {BREADCRUMB_TAG}",
            f"aws_secret_access_key = {secret} {BREADCRUMB_TAG}",
            f"region = us-east-1 {BREADCRUMB_TAG}",
        ]
        _append_tagged(path, lines)
        self.planted_paths.append(path)

    def plant_env_file(self, fake_nodes: list[dict]) -> None:
        path = os.path.expanduser("~/.env")
        db_nodes = [n for n in fake_nodes if n.get("node_type") == "db_server"]
        api_nodes = [n for n in fake_nodes if n.get("node_type") in ("api_gateway", "web_server")]
        lines = []
        if db_nodes:
            ip = db_nodes[0]["ip"]
            lines.append(f"DATABASE_URL=mysql://root:Corp@dm1n2024!@{ip}:3306/production {BREADCRUMB_TAG}")
        if api_nodes:
            ip = api_nodes[0]["ip"]
            lines.append(f"INTERNAL_API_BASE=http://{ip}:8080 {BREADCRUMB_TAG}")
        lines.append(f"CORP_SECRET_KEY=sk_prod_{_fake_aws_secret()} {BREADCRUMB_TAG}")
        _append_tagged(path, lines)
        if lines:
            self.planted_paths.append(path)

    def plant_bash_history(self, fake_nodes: list[dict]) -> None:
        path = os.path.expanduser("~/.bash_history")
        db_ip  = next((n["ip"] for n in fake_nodes if n.get("node_type") == "db_server"), "172.20.0.10")
        api_ip = next((n["ip"] for n in fake_nodes if n.get("node_type") in ("api_gateway", "web_server")), "172.20.0.11")
        ts = datetime.now().strftime("%Y-%m-%d")
        lines = [
            f"# {ts} {BREADCRUMB_TAG}",
            f"ssh admin@{db_ip} {BREADCRUMB_TAG}",
            f"mysql -h {db_ip} -u root -pCorp@dm1n2024! {BREADCRUMB_TAG}",
            f"aws --profile corp-prod s3 ls s3://corp-prod-backups/ {BREADCRUMB_TAG}",
            f"curl http://{api_ip}/api/config {BREADCRUMB_TAG}",
            f"scp -r admin@{db_ip}:/var/backups/ ./local_backup/ {BREADCRUMB_TAG}",
            f"nmap -sV {db_ip} {BREADCRUMB_TAG}",
        ]
        _append_tagged(path, lines)
        self.planted_paths.append(path)

    def plant_hosts_entry(self, fake_nodes: list[dict]) -> None:
        """Requires elevated privileges — skipped gracefully otherwise."""
        path = "/etc/hosts"
        lines = []
        ips = [n["ip"] for n in fake_nodes]
        for i, hostname in enumerate(DNS_CANARY_NAMES[:len(ips)]):
            ip = ips[i % len(ips)]
            lines.append(f"{ip}  {hostname}  # corp-infra {BREADCRUMB_TAG}")
        success = _append_tagged(path, lines)
        if success and lines:
            self.planted_paths.append(path)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup(self) -> None:
        logger.info("Cleaning up all breadcrumbs tagged with: %s", BREADCRUMB_TAG)
        targets = [t["path"] for t in BREADCRUMB_TARGETS]
        for path in targets:
            _remove_tagged(path)
        logger.info("Cleanup complete.")

    # ------------------------------------------------------------------
    # Report heartbeat
    # ------------------------------------------------------------------
    def report(self) -> None:
        try:
            url = f"{self.server_url}/api/breadcrumbs/report"
            payload = json.dumps({
                "agent_host":    os.uname().nodename if hasattr(os, "uname") else os.getenv("COMPUTERNAME", "unknown"),
                "planted_paths": self.planted_paths,
                "timestamp":     time.time(),
            }).encode()
            req = urllib.request.Request(
                url,
=======
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
>>>>>>> 38d5f488fa059baa9e803a273fda1e611995d0ed
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
<<<<<<< HEAD
            urllib.request.urlopen(req, timeout=5)  # noqa: S310
            logger.info("Heartbeat sent to ShadowMesh.")
        except Exception as exc:
            logger.debug("Heartbeat failed (non-critical): %s", exc)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def plant_all(self, fake_nodes: list[dict]) -> None:
        logger.info("Planting breadcrumbs across %d target path(s)...", len(BREADCRUMB_TARGETS))
        self.plant_ssh_known_hosts(fake_nodes)
        self.plant_aws_credentials(fake_nodes)
        self.plant_env_file(fake_nodes)
        self.plant_bash_history(fake_nodes)
        self.plant_hosts_entry(fake_nodes)

    def run(self) -> None:
        logger.info("ShadowMesh Breadcrumb Agent starting (interval=%ds).", self.update_interval)
        while True:
            try:
                fake_nodes = self.fetch_topology()
                if fake_nodes:
                    self.plant_all(fake_nodes)
                    self.report()
                else:
                    logger.warning("Empty topology — skipping this cycle.")
            except Exception as exc:
                logger.error("Agent cycle error: %s", exc)
            logger.info("Sleeping %ds until next cycle...", self.update_interval)
            time.sleep(self.update_interval)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ShadowMesh Breadcrumb Agent")
    parser.add_argument("--cleanup", action="store_true", help="Remove all planted breadcrumbs and exit.")
    parser.add_argument("--once", action="store_true", help="Plant breadcrumbs once then exit.")
    parser.add_argument("--url", default=None, help="ShadowMesh server URL (overrides SHADOWMESH_URL env).")
    args = parser.parse_args()

    agent = BreadcrumbAgent()

    if args.url:
        agent.server_url = args.url

    if args.cleanup:
        agent.cleanup()
        sys.exit(0)

    if args.once:
        nodes = agent.fetch_topology()
        agent.plant_all(nodes)
        agent.report()
        sys.exit(0)

    agent.run()


if __name__ == "__main__":
    main()
=======
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
>>>>>>> 38d5f488fa059baa9e803a273fda1e611995d0ed
