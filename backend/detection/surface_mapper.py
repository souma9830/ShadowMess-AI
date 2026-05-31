"""
<<<<<<< HEAD
Task 13.3 - Attack Surface Mapper
Scans the real network segment (ARP + lightweight TCP probe) and generates a
fake deception topology whose node-type ratios mirror the real infrastructure.
"""

import asyncio
import ipaddress
import logging
import os
import random
import string
from typing import Dict, List, Optional, Tuple

from backend.models import NetworkNode, TopologySnapshot

logger = logging.getLogger("shadowmesh.surface_mapper")

SCAN_PORTS = [22, 80, 443, 3306, 5432, 445, 389, 3389, 8080, 8443]

PORT_TYPE_MAP: Dict[int, str] = {
    80: "web_server", 443: "web_server", 8080: "web_server", 8443: "web_server",
    3306: "db_server", 5432: "db_server",
    389: "auth_service", 636: "auth_service",
    445: "file_server",
    3389: "workstation",
    22: "generic_server",
}

PORT_DEFAULTS: Dict[str, List[int]] = {
    "web_server":     [80, 443, 8080],
    "db_server":      [3306, 5432],
    "auth_service":   [389, 636, 88],
    "file_server":    [445, 139],
    "workstation":    [3389, 22],
    "api_gateway":    [8080, 8443],
    "generic_server": [22],
}

OS_DEFAULTS: Dict[str, str] = {
    "web_server":     "Ubuntu 22.04",
    "db_server":      "Debian 11",
    "auth_service":   "Windows Server 2019",
    "file_server":    "Windows Server 2022",
    "workstation":    "Windows 11",
    "api_gateway":    "Amazon Linux 2023",
    "generic_server": "CentOS 7",
}

BANNER_DEFAULTS: Dict[str, str] = {
    "web_server":     "nginx/1.24.0",
    "db_server":      "MySQL 8.0.36",
    "auth_service":   "Microsoft Active Directory",
    "file_server":    "Samba 4.17",
    "workstation":    "Windows RDP",
    "api_gateway":    "Apache/2.4.57",
    "generic_server": "OpenSSH 8.9",
}


def _random_id(prefix: str = "node") -> str:
    suffix = "".join(random.choices(string.hexdigits[:16], k=6))
    return f"{prefix}_{suffix}"


def _deception_ips(count: int, subnet: str = "172.20.0.0/24") -> List[str]:
    net = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in list(net.hosts())[2:250]]
    return random.sample(hosts, min(count, len(hosts)))


async def _tcp_probe(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def _categorize(open_ports: List[int]) -> str:
    for port in [443, 80, 8443, 8080, 3306, 5432, 389, 445, 3389]:
        if port in open_ports:
            return PORT_TYPE_MAP[port]
    return PORT_TYPE_MAP.get(22, "generic_server")


def _arp_discover(subnet: str, interface: str) -> List[Dict[str, str]]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=2, iface=interface, verbose=False,
        )
        return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in ans]
    except Exception as exc:
        logger.debug("ARP skipped: %s", exc)
        return []


def _build_edges(nodes: List[NetworkNode]) -> List[Tuple[str, str]]:
    if len(nodes) < 2:
        return []
    edges = [(nodes[i - 1].node_id, nodes[i].node_id)
             for i in range(1, len(nodes))]
    ids = [n.node_id for n in nodes]
    for _ in range(min(len(nodes) // 2, 4)):
        a, b = random.sample(ids, 2)
        if (a, b) not in edges and (b, a) not in edges:
            edges.append((a, b))
    return edges


class AttackSurfaceMapper:
    """
    Discovers real network hosts (ARP), estimates service ratios (TCP probe),
    and generates a fake topology that mirrors those ratios.
    """

    def __init__(self, subnet: str, interface: str) -> None:
        self.subnet = subnet
        self.interface = interface

    async def discover_hosts(self) -> List[Dict[str, str]]:
        loop = asyncio.get_event_loop()
        hosts = await loop.run_in_executor(
            None, _arp_discover, self.subnet, self.interface
        )
        logger.info("Surface mapper: %d host(s) in %s", len(hosts), self.subnet)
        return hosts

    async def estimate_service_distribution(
        self, live_hosts: List[Dict[str, str]]
    ) -> Dict[str, int]:
        dist: Dict[str, int] = {}

        async def probe(host: Dict[str, str]) -> None:
            ip = host["ip"]
            results = await asyncio.gather(
                *[_tcp_probe(ip, p) for p in SCAN_PORTS], return_exceptions=True
            )
            open_ports = [SCAN_PORTS[i] for i, r in enumerate(results) if r is True]
            t = _categorize(open_ports)
            dist[t] = dist.get(t, 0) + 1

        await asyncio.gather(*[probe(h) for h in live_hosts])
        logger.info("Distribution: %s", dist)
        return dist

    async def generate_mirrored_topology(self, target_count: int = 15) -> TopologySnapshot:
        live_hosts = await self.discover_hosts()

        if live_hosts:
            distribution = await self.estimate_service_distribution(live_hosts)
        else:
            logger.info("No live hosts — using default distribution.")
            distribution = {
                "web_server": 4, "db_server": 2, "auth_service": 1,
                "file_server": 1, "workstation": 3, "generic_server": 2,
            }

        total_real = sum(distribution.values()) or 1
        fake_ips = _deception_ips(target_count + 10)
        nodes: List[NetworkNode] = []
        ip_cursor = 0

        for node_type, count in distribution.items():
            mirrored = max(1, round(count / total_real * target_count))
            for _ in range(mirrored):
                if ip_cursor >= len(fake_ips) or len(nodes) >= target_count:
                    break
                nodes.append(NetworkNode(
                    node_id=_random_id(node_type),
                    node_type=node_type,
                    ip=fake_ips[ip_cursor],
                    ports=PORT_DEFAULTS.get(node_type, [22]),
                    os=OS_DEFAULTS.get(node_type, "Linux"),
                    banner=BANNER_DEFAULTS.get(node_type, "Unknown"),
                ))
                ip_cursor += 1

        nodes = nodes[:target_count]
        logger.info("Mirrored topology: %d nodes (ratio: %s)", len(nodes), distribution)
        return TopologySnapshot(nodes=nodes, edges=_build_edges(nodes), generation=0)


_mapper: Optional[AttackSurfaceMapper] = None


def get_surface_mapper() -> AttackSurfaceMapper:
    global _mapper
    if _mapper is None:
        _mapper = AttackSurfaceMapper(
            subnet=os.getenv("FAKE_NETWORK_SUBNET", "192.168.1.0/24"),
            interface=os.getenv("NETWORK_INTERFACE", "eth0"),
        )
    return _mapper
=======
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
>>>>>>> 38d5f488fa059baa9e803a273fda1e611995d0ed
