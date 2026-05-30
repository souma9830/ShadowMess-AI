"""
ShadowMesh - Task 11.3: Projection Sensor
==========================================
Projects the existence of fake network assets at Layer 2/3 without Docker
containers.  A single sniffer thread intercepts ARP requests and TCP SYNs
destined for projected IPs, responds with crafted packets, and emits
structured deception events back to the main async event loop.

Architecture
------------
  ProjectionSensor
  ├── NodeRegistry          — thread-safe IP → ProjectedNode store
  ├── ArpResponder          — answers ARP who-has for projected IPs
  ├── TcpBannerResponder    — completes TCP handshake, sends banner, RSTs
  └── EventEmitter          — rate-limited structured event generation

Tier model
----------
  Tier-1  Docker honeypots  — full interaction, managed by ContainerManager
  Tier-2  Projected nodes   — lightweight ARP+TCP illusion, managed here

The sensor runs entirely in a daemon thread; async callers interact via
register_node() / deregister_node() / start() / stop().  Events are placed
on an asyncio.Queue and drained by the caller's event loop.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

log = logging.getLogger("projection_sensor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DECEPTION_SUBNET = "172.20.0.0/24"
_DECEPTION_SUBNET_NET = "172.20.0.0"
_DECEPTION_SUBNET_MASK = "255.255.255.0"

# Maximum banner length sent to probing clients (bytes, excluding CRLF)
_MAX_BANNER_LEN = 512

# Minimum seconds between events from the same source IP (rate limiting)
_EVENT_RATE_LIMIT_S = 1.0

# Maximum events buffered before the oldest is dropped
_EVENT_QUEUE_MAX = 1000

# Printable ASCII filter for banner sanitisation
_PRINTABLE_RE = re.compile(r"[^\x20-\x7E]")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ProjectedNode:
    """Lightweight descriptor for a single projected (Tier-2) network asset."""

    node_id:   str
    ip:        str
    mac:       str          # "aa:bb:cc:dd:ee:ff" — deterministic from node_id
    ports:     List[int]
    banner:    str          # sanitised, ≤ _MAX_BANNER_LEN chars
    os:        str
    node_type: str


@dataclass
class ProjectionEvent:
    """Structured event emitted when an attacker interacts with a projected node."""

    event_type:   str       # "arp_hit" | "port_scan" | "service_probe"
    source_ip:    str
    target_ip:    str
    target_node_id: str
    ports_hit:    List[int]
    timestamp:    float
    detail:       str


# ---------------------------------------------------------------------------
# NodeRegistry
# ---------------------------------------------------------------------------

class NodeRegistry:
    """
    Thread-safe store mapping IP address → ProjectedNode.

    All mutating operations acquire _lock; reads use a snapshot copy so
    the sniffer thread never blocks on a long-running caller.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_ip:      Dict[str, ProjectedNode] = {}
        self._by_node_id: Dict[str, str]           = {}  # node_id → ip

    # -- Mutation -----------------------------------------------------------

    def register(self, node: ProjectedNode) -> None:
        """Add or replace a projected node."""
        with self._lock:
            # Remove stale entry for same node_id if IP changed
            old_ip = self._by_node_id.get(node.node_id)
            if old_ip and old_ip != node.ip:
                self._by_ip.pop(old_ip, None)
            self._by_ip[node.ip]           = node
            self._by_node_id[node.node_id] = node.ip
        log.info("[registry] Registered projected node %s @ %s (%s)",
                 node.node_id, node.ip, node.mac)

    def deregister(self, node_id: str) -> None:
        """Remove a projected node by node_id."""
        with self._lock:
            ip = self._by_node_id.pop(node_id, None)
            if ip:
                self._by_ip.pop(ip, None)
                log.info("[registry] Deregistered projected node %s", node_id)

    def clear(self) -> None:
        """Remove all projected nodes."""
        with self._lock:
            count = len(self._by_ip)
            self._by_ip.clear()
            self._by_node_id.clear()
        log.info("[registry] Cleared %d projected node(s)", count)

    # -- Queries (snapshot copies — safe to call without holding lock) ------

    def get_by_ip(self, ip: str) -> Optional[ProjectedNode]:
        return self._by_ip.get(ip)

    def all_ips(self) -> Set[str]:
        with self._lock:
            return set(self._by_ip.keys())

    def count(self) -> int:
        return len(self._by_ip)


# ---------------------------------------------------------------------------
# MAC derivation
# ---------------------------------------------------------------------------

def _derive_mac(node_id: str) -> str:
    """
    Derive a stable, locally-administered unicast MAC from node_id.

    Bit 0 of byte 0 = 0  → unicast
    Bit 1 of byte 0 = 1  → locally administered (not a real OUI)
    """
    digest = hashlib.sha256(node_id.encode()).digest()
    b = bytearray(digest[:6])
    b[0] = (b[0] & 0xFE) | 0x02   # clear multicast bit, set local bit
    return ":".join(f"{x:02x}" for x in b)


# ---------------------------------------------------------------------------
# Banner sanitisation
# ---------------------------------------------------------------------------

def _sanitise_banner(raw: str) -> str:
    """Strip non-printable ASCII, truncate, append CRLF."""
    clean = _PRINTABLE_RE.sub("", raw)[:_MAX_BANNER_LEN]
    return clean + "\r\n"


# ---------------------------------------------------------------------------
# IP subnet check
# ---------------------------------------------------------------------------

def _in_deception_subnet(ip: str) -> bool:
    """Return True if ip is within 172.20.0.0/24."""
    try:
        packed = struct.unpack("!I", bytes(int(o) for o in ip.split(".")))[0]
        net    = struct.unpack("!I", bytes(int(o) for o in _DECEPTION_SUBNET_NET.split(".")))[0]
        mask   = struct.unpack("!I", bytes(int(o) for o in _DECEPTION_SUBNET_MASK.split(".")))[0]
        return (packed & mask) == (net & mask)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ProjectionSensor
# ---------------------------------------------------------------------------

class ProjectionSensor:
    """
    Main sensor class.  Owns the sniffer thread and exposes a clean async API.

    Usage
    -----
        sensor = ProjectionSensor(interface="eth0", event_loop=loop)
        sensor.register_node(node)
        sensor.start()
        ...
        sensor.stop()

    Events are placed on sensor.event_queue (asyncio.Queue[ProjectionEvent]).
    The caller is responsible for draining the queue and forwarding events to
    Socket.IO / the database.
    """

    def __init__(
        self,
        interface: str,
        event_loop: asyncio.AbstractEventLoop,
        *,
        on_event: Optional[Callable[[ProjectionEvent], None]] = None,
    ) -> None:
        self._interface   = interface
        self._loop        = event_loop
        self._on_event    = on_event
        self.registry     = NodeRegistry()
        self.event_queue: asyncio.Queue[ProjectionEvent] = asyncio.Queue(
            maxsize=_EVENT_QUEUE_MAX
        )

        # Rate-limit state: source_ip → last_event_time
        self._rate_state: Dict[str, float] = {}
        self._rate_lock   = threading.Lock()

        self._sniffer     = None   # scapy AsyncSniffer
        self._running     = False
        self._stop_event  = threading.Event()

        # Packet counters for diagnostics
        self._stats: Dict[str, int] = {
            "arp_requests_seen":   0,
            "arp_replies_sent":    0,
            "tcp_syns_seen":       0,
            "tcp_banners_sent":    0,
            "malformed_dropped":   0,
            "events_emitted":      0,
            "events_rate_dropped": 0,
        }

    # -----------------------------------------------------------------------
    # Public API (thread-safe, callable from async context)
    # -----------------------------------------------------------------------

    def register_node(self, node: ProjectedNode) -> None:
        """Register a projected node.  Safe to call from any thread."""
        if not _in_deception_subnet(node.ip):
            log.warning(
                "[sensor] Rejected registration of %s: IP %s outside deception subnet",
                node.node_id, node.ip,
            )
            return
        node.banner = _sanitise_banner(node.banner)
        self.registry.register(node)

    def deregister_node(self, node_id: str) -> None:
        """Deregister a projected node.  Safe to call from any thread."""
        self.registry.deregister(node_id)

    def start(self) -> None:
        """Start the sniffer thread.  No-op if already running."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        t = threading.Thread(target=self._sniffer_thread, daemon=True, name="projection-sniffer")
        t.start()
        log.info("[sensor] Started on interface '%s'", self._interface)

    def stop(self) -> None:
        """Signal the sniffer thread to stop and wait for it."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        log.info("[sensor] Stopped.  Stats: %s", self._stats)

    def stats(self) -> Dict[str, int]:
        """Return a copy of the diagnostic counters."""
        return dict(self._stats)

    # -----------------------------------------------------------------------
    # Sniffer thread
    # -----------------------------------------------------------------------

    def _sniffer_thread(self) -> None:
        """
        Runs in a daemon thread.  Imports Scapy here so the main process
        doesn't pay the Scapy import cost if the sensor is never started.
        """
        try:
            from scapy.all import AsyncSniffer, ARP, Ether, IP, TCP, sendp, send
        except ImportError:
            log.error("[sensor] Scapy not available — projection sensor disabled")
            return

        # BPF filter: only ARP or TCP traffic to the deception subnet
        bpf = f"arp or (tcp and dst net {_DECEPTION_SUBNET})"

        def _handle(pkt):
            try:
                if pkt.haslayer(ARP) and pkt[ARP].op == 1:   # who-has
                    self._handle_arp(pkt, sendp)
                elif pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:  # SYN only
                    self._handle_tcp_syn(pkt, send, sendp)
            except Exception as exc:
                self._stats["malformed_dropped"] += 1
                log.debug("[sensor] Malformed packet dropped: %s", exc)

        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=bpf,
            prn=_handle,
            store=False,
        )
        self._sniffer.start()
        self._stop_event.wait()   # block until stop() is called
        try:
            self._sniffer.stop()
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # ARP responder
    # -----------------------------------------------------------------------

    def _handle_arp(self, pkt, sendp) -> None:
        """Respond to ARP who-has for any projected IP."""
        from scapy.all import ARP, Ether

        self._stats["arp_requests_seen"] += 1
        target_ip  = pkt[ARP].pdst
        source_ip  = pkt[ARP].psrc
        source_mac = pkt[ARP].hwsrc

        node = self.registry.get_by_ip(target_ip)
        if node is None:
            return

        # Craft ARP reply: "target_ip is-at node.mac"
        reply = (
            Ether(dst=source_mac, src=node.mac) /
            ARP(
                op=2,
                hwsrc=node.mac,
                psrc=target_ip,
                hwdst=source_mac,
                pdst=source_ip,
            )
        )
        try:
            sendp(reply, iface=self._interface, verbose=False)
            self._stats["arp_replies_sent"] += 1
            log.debug("[arp] Replied %s is-at %s (to %s)", target_ip, node.mac, source_ip)
        except Exception as exc:
            log.warning("[arp] Send failed for %s: %s", target_ip, exc)
            return

        self._emit_event(ProjectionEvent(
            event_type     = "arp_hit",
            source_ip      = source_ip,
            target_ip      = target_ip,
            target_node_id = node.node_id,
            ports_hit      = [],
            timestamp      = time.time(),
            detail         = f"ARP probe: who-has {target_ip} from {source_ip}",
        ))

    # -----------------------------------------------------------------------
    # TCP banner responder
    # -----------------------------------------------------------------------

    def _handle_tcp_syn(self, pkt, send, sendp) -> None:
        """
        Complete TCP handshake for projected IPs/ports and send the banner.

        Sequence:
          attacker  →  SYN
          sensor    →  SYN-ACK
          attacker  →  ACK          (we don't wait — send banner immediately)
          sensor    →  PSH+ACK (banner)
          sensor    →  RST+ACK (close)
        """
        from scapy.all import IP, TCP, Ether

        self._stats["tcp_syns_seen"] += 1
        dst_ip   = pkt[IP].dst
        src_ip   = pkt[IP].src
        dst_port = pkt[TCP].dport
        src_port = pkt[TCP].sport
        seq      = pkt[TCP].seq

        node = self.registry.get_by_ip(dst_ip)
        if node is None:
            return
        if dst_port not in node.ports:
            return

        isn = int(hashlib.sha256(
            f"{dst_ip}{dst_port}{src_ip}{src_port}{seq}".encode()
        ).hexdigest()[:8], 16)

        base = IP(src=dst_ip, dst=src_ip) / TCP(
            sport=dst_port, dport=src_port,
            seq=isn, ack=seq + 1,
        )

        # SYN-ACK
        syn_ack = base / TCP(flags="SA", seq=isn, ack=seq + 1,
                             sport=dst_port, dport=src_port)
        # Banner (PSH+ACK)
        banner_bytes = node.banner.encode("ascii", errors="replace")
        data_pkt = (
            IP(src=dst_ip, dst=src_ip) /
            TCP(flags="PA", sport=dst_port, dport=src_port,
                seq=isn + 1, ack=seq + 1) /
            banner_bytes
        )
        # RST
        rst_pkt = (
            IP(src=dst_ip, dst=src_ip) /
            TCP(flags="RA", sport=dst_port, dport=src_port,
                seq=isn + 1 + len(banner_bytes), ack=seq + 1)
        )

        try:
            send(syn_ack,  iface=self._interface, verbose=False)
            send(data_pkt, iface=self._interface, verbose=False)
            send(rst_pkt,  iface=self._interface, verbose=False)
            self._stats["tcp_banners_sent"] += 1
            log.debug("[tcp] Banner sent to %s:%d for %s:%d",
                      src_ip, src_port, dst_ip, dst_port)
        except Exception as exc:
            log.warning("[tcp] Send failed %s:%d: %s", dst_ip, dst_port, exc)
            return

        event_type = "service_probe" if dst_port in (22, 80, 443, 3306, 5432, 389, 25) \
                     else "port_scan"

        self._emit_event(ProjectionEvent(
            event_type     = event_type,
            source_ip      = src_ip,
            target_ip      = dst_ip,
            target_node_id = node.node_id,
            ports_hit      = [dst_port],
            timestamp      = time.time(),
            detail         = (
                f"{event_type.replace('_', ' ').title()}: "
                f"{src_ip} → {dst_ip}:{dst_port} ({node.node_type})"
            ),
        ))

    # -----------------------------------------------------------------------
    # Event emission (rate-limited, thread-safe)
    # -----------------------------------------------------------------------

    def _emit_event(self, event: ProjectionEvent) -> None:
        """
        Place event on the async queue, subject to per-source-IP rate limiting.
        Drops the event (not the queue) if the source is over the rate limit.
        """
        now = event.timestamp
        with self._rate_lock:
            last = self._rate_state.get(event.source_ip, 0.0)
            if now - last < _EVENT_RATE_LIMIT_S:
                self._stats["events_rate_dropped"] += 1
                return
            self._rate_state[event.source_ip] = now

        self._stats["events_emitted"] += 1

        # Schedule queue put on the event loop from this thread
        try:
            if self._loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self._enqueue(event), self._loop
                )
        except Exception as exc:
            log.debug("[sensor] Event loop unavailable for event: %s", exc)

        if self._on_event is not None:
            try:
                self._on_event(event)
            except Exception as exc:
                log.debug("[sensor] on_event callback raised: %s", exc)

    async def _enqueue(self, event: ProjectionEvent) -> None:
        """Put event on the queue; drop oldest if full."""
        if self.event_queue.full():
            try:
                self.event_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        await self.event_queue.put(event)


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------

def make_projected_node(node_id: str, ip: str, node_type: str,
                        ports: List[int], banner: str, os: str) -> ProjectedNode:
    """Convenience constructor that derives the MAC automatically."""
    return ProjectedNode(
        node_id   = node_id,
        ip        = ip,
        mac       = _derive_mac(node_id),
        ports     = ports,
        banner    = banner,
        os        = os,
        node_type = node_type,
    )


# ---------------------------------------------------------------------------
# Module-level singleton (imported by container_manager and main)
# ---------------------------------------------------------------------------

# Initialised to None; replaced by ProjectionSensor(interface, loop) in main.py
projection_sensor: Optional[ProjectionSensor] = None
