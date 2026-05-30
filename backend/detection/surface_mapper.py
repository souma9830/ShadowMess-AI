"""
ShadowMesh — Task 13.3: Attack Surface Mapper
==============================================
Scans the real network segment before generating fake topology, so the
deception network mirrors the real infrastructure statistically. This makes
fake nodes indistinguishable from actual hosts.

Architecture:
  AttackSurfaceMapper(subnet, interface)
  ├── discover_hosts()                → ARP scan for live hosts
  ├── estimate_service_distribution() → Quick TCP probe on common ports
  └── generate_mirrored_topology()    → TopologySnapshot matching real ratios
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import socket
import ipaddress
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("surface_mapper")

COMMON_PORTS = [22, 80, 443, 3306, 5432, 445, 389, 3389, 8080, 8443]

PORT_TO_TYPE = {
    80: "web_server",
    443: "web_server",
    8080: "web_server",
    8443: "api_gateway",
    3306: "db_server",
    5432: "db_server",
    445: "file_server",
    389: "auth_service",
    3389: "workstation",
    22: "web_server",
}


class AttackSurfaceMapper:

    def __init__(self, subnet: str = "192.168.1.0/24", interface: str = "auto"):
        self.subnet = subnet
        self.interface = interface
        self._discovered_hosts: List[Dict] = []
        self._distribution: Dict[str, int] = {}

    async def discover_hosts(self) -> List[Dict]:
        """ARP scan to discover live hosts. Falls back to TCP ping if Scapy unavailable."""
        try:
            from scapy.all import ARP, Ether, srp
            network = ipaddress.IPv4Network(self.subnet, strict=False)
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))

            kwargs = {"timeout": 3, "verbose": False}
            if self.interface != "auto":
                kwargs["iface"] = self.interface

            answered, _ = srp(pkt, **kwargs)

            hosts = []
            for sent, received in answered:
                hosts.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                })

            self._discovered_hosts = hosts
            log.info("[surface] ARP scan found %d hosts in %s", len(hosts), self.subnet)
            return hosts

        except ImportError:
            log.warning("[surface] Scapy not available, using TCP ping fallback")
            return await self._tcp_ping_fallback()
        except Exception as e:
            log.warning("[surface] ARP scan failed: %s, using TCP fallback", e)
            return await self._tcp_ping_fallback()

    async def _tcp_ping_fallback(self) -> List[Dict]:
        """TCP connect scan on port 80/443 as fallback when Scapy unavailable."""
        network = ipaddress.IPv4Network(self.subnet, strict=False)
        hosts = []
        sample_ips = list(network.hosts())[:50]

        loop = asyncio.get_event_loop()

        async def probe(ip_str: str) -> Optional[Dict]:
            for port in [80, 443, 22]:
                try:
                    fut = loop.run_in_executor(None, self._tcp_connect, ip_str, port)
                    result = await asyncio.wait_for(fut, timeout=1.0)
                    if result:
                        return {"ip": ip_str, "mac": "unknown"}
                except (asyncio.TimeoutError, Exception):
                    continue
            return None

        tasks = [probe(str(ip)) for ip in sample_ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        hosts = [r for r in results if r and not isinstance(r, Exception)]

        self._discovered_hosts = hosts
        log.info("[surface] TCP ping found %d hosts in %s", len(hosts), self.subnet)
        return hosts

    @staticmethod
    def _tcp_connect(ip: str, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            s.close()
            return result == 0
        except Exception:
            return False

    async def estimate_service_distribution(self, live_hosts: Optional[List[Dict]] = None) -> Dict[str, int]:
        """Quick TCP SYN scan on common ports to categorize hosts."""
        hosts = live_hosts or self._discovered_hosts
        if not hosts:
            return self._default_distribution()

        distribution: Dict[str, int] = {
            "web_server": 0,
            "db_server": 0,
            "auth_service": 0,
            "file_server": 0,
            "api_gateway": 0,
            "mail_server": 0,
            "workstation": 0,
        }

        loop = asyncio.get_event_loop()

        for host in hosts[:30]:
            ip = host["ip"]
            open_ports = []

            for port in COMMON_PORTS:
                try:
                    result = await asyncio.wait_for(
                        loop.run_in_executor(None, self._tcp_connect, ip, port),
                        timeout=0.6,
                    )
                    if result:
                        open_ports.append(port)
                except (asyncio.TimeoutError, Exception):
                    continue

            if open_ports:
                node_type = PORT_TO_TYPE.get(open_ports[0], "web_server")
                distribution[node_type] = distribution.get(node_type, 0) + 1
            else:
                distribution["workstation"] += 1

        self._distribution = distribution
        log.info("[surface] Service distribution: %s", distribution)
        return distribution

    def _default_distribution(self) -> Dict[str, int]:
        return {
            "web_server": 3,
            "db_server": 2,
            "auth_service": 1,
            "file_server": 2,
            "api_gateway": 2,
            "mail_server": 1,
            "workstation": 3,
        }

    async def generate_mirrored_topology(self, target_count: int = 14) -> Dict[str, List[float]]:
        """Return node type weights that mirror the real network distribution."""
        hosts = await self.discover_hosts()
        distribution = await self.estimate_service_distribution(hosts)

        total = sum(distribution.values())
        if total == 0:
            distribution = self._default_distribution()
            total = sum(distribution.values())

        node_types = ["web_server", "db_server", "auth_service", "file_server",
                      "api_gateway", "mail_server", "workstation"]

        weights = []
        for nt in node_types:
            w = distribution.get(nt, 0) / total
            weights.append(max(w, 0.05))

        weight_sum = sum(weights)
        weights = [w / weight_sum for w in weights]

        log.info("[surface] Mirrored weights: %s", dict(zip(node_types, [f"{w:.2f}" for w in weights])))

        return {
            "weights": weights,
            "node_types": node_types,
            "discovered_hosts": len(hosts),
            "distribution": distribution,
        }

    def get_stats(self) -> Dict:
        return {
            "subnet": self.subnet,
            "discovered_hosts": len(self._discovered_hosts),
            "distribution": self._distribution,
        }


surface_mapper = AttackSurfaceMapper(
    subnet=os.getenv("FAKE_NETWORK_SUBNET", "192.168.1.0/24"),
    interface=os.getenv("NETWORK_INTERFACE", "auto"),
)
