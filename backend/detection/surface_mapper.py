"""
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
