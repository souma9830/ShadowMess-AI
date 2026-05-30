from scapy.all import Ether, IP, TCP, UDP, sniff, get_if_list
import threading
import time
import asyncio
import os
import re as _re
import subprocess
from collections import defaultdict
from backend.models import ScanEvent

SCAN_WINDOW_SECONDS = 10
SCAN_THRESHOLD_PORTS = 5   # >5 unique ports from same IP in 10s = port scan
LATERAL_THRESHOLD = 3      # >3 unique target IPs from same IP = lateral movement
MAX_TRACKED_IPS = 10000    # Global cap to prevent memory exhaustion from mass scanning


def detect_network_interface() -> str:
    """
    Resolves the correct network interface to sniff on.
    Handles NETWORK_INTERFACE=auto from .env by probing the system.
    """
    env_val = os.getenv('NETWORK_INTERFACE', 'auto')
    if env_val and env_val.lower() != 'auto':
        return env_val

    # Try ip route show default (Linux)
    try:
        out = subprocess.check_output(
            ['ip', 'route', 'show', 'default'],
            text=True, timeout=2, stderr=subprocess.DEVNULL
        )
        m = _re.search(r'dev\s+(\S+)', out)
        if m:
            iface = m.group(1)
            print(f'[Scanner] Auto-detected interface via ip route: {iface}')
            return iface
    except Exception:
        pass

    # Try scapy interface list, skip loopback and virtual interfaces
    try:
        skip_prefixes = ('lo', 'docker', 'br-', 'veth', 'virbr')
        candidates = [i for i in get_if_list() if not any(i.startswith(p) for p in skip_prefixes)]
        if candidates:
            print(f'[Scanner] Auto-detected interface via scapy: {candidates[0]}')
            return candidates[0]
    except Exception:
        pass

    print('[Scanner] WARNING: Could not auto-detect interface, falling back to lo (passive mode)')
    return 'lo'

class ReconDetector:
    def __init__(self, interface: str, callback):
        self.interface = interface
        self.callback = callback  # async function: async def on_event(scan_event: ScanEvent)
        self._port_hits: dict[str, list[tuple[int, float]]] = defaultdict(list)  # src_ip → [(port, timestamp)]
        self._target_hits: dict[str, list[tuple[str, float]]] = defaultdict(list) # src_ip → [(dst_ip, timestamp)]
        self._alerted_ips: dict[str, float] = {}  # src_ip → timestamp of last alert (time-windowed)
        self._running = False
        self._loop = None

    def _packet_handler(self, packet):
        if not (IP in packet and TCP in packet):
            return
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        dst_ip = packet[IP].dst

        # Skip loopback and Docker internal
        if src_ip.startswith('127.') or src_ip.startswith('172.17.'):
            return

        now = time.time()

        # Track port hits per source IP
        self._port_hits[src_ip].append((dst_port, now))
        # Prune old hits outside window and remove empty keys to prevent unbounded growth
        self._port_hits[src_ip] = [(p, t) for p, t in self._port_hits[src_ip] if now - t < SCAN_WINDOW_SECONDS]
        if not self._port_hits[src_ip]:
            del self._port_hits[src_ip]

        # Track lateral movement (unique targets)
        self._target_hits[src_ip].append((dst_ip, now))
        self._target_hits[src_ip] = [(d, t) for d, t in self._target_hits[src_ip] if now - t < SCAN_WINDOW_SECONDS]
        if not self._target_hits[src_ip]:
            del self._target_hits[src_ip]

        # Global cap: if tracking too many IPs, evict the oldest one
        if len(self._port_hits) > MAX_TRACKED_IPS:
            oldest_ip = min(self._port_hits.keys(),
                           key=lambda ip: min(t for _, t in self._port_hits[ip]) if self._port_hits[ip] else now)
            self._port_hits.pop(oldest_ip, None)
            self._target_hits.pop(oldest_ip, None)
            self._alerted_ips.pop(oldest_ip, None)

        unique_ports = len(set(p for p, _ in self._port_hits[src_ip]))
        unique_targets = len(set(d for d, _ in self._target_hits[src_ip]))

        # Clean old alerts outside the scan window to allow re-alerting
        self._alerted_ips = {ip: t for ip, t in self._alerted_ips.items() if now - t < SCAN_WINDOW_SECONDS}

        if unique_ports >= SCAN_THRESHOLD_PORTS and src_ip not in self._alerted_ips:
            self._alerted_ips[src_ip] = now
            scan_type = 'lateral_movement' if unique_targets >= LATERAL_THRESHOLD else 'port_scan'
            event = ScanEvent(
                source_ip=src_ip,
                scan_type=scan_type,
                ports_hit=list(set(p for p, _ in self._port_hits[src_ip])),
                timestamp=now
            )
            # Schedule the async callback safely from this sync thread
            if self._loop and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(self.callback(event), self._loop)

    def start(self, loop: asyncio.AbstractEventLoop, sio=None):
        """Start the packet sniffer.  sio is used to emit an alert if detection fails."""
        self._loop = loop
        self._running = True

        # Fix #10: Validate interface and emit a dashboard alert if detection is disabled.
        # Previously this printed a warning but the dashboard showed no indication.
        try:
            available = get_if_list()
            if self.interface not in available:
                print(f'[Scanner] Interface {self.interface!r} not available — Scapy detection DISABLED.')
                print('[Scanner] Fix NETWORK_INTERFACE in .env')
                self._running = False
                if sio and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        sio.emit('alert', {
                            'message': (
                                f'Network detection disabled: interface {self.interface!r} not found. '
                                'Check NETWORK_INTERFACE env var.'
                            ),
                            'severity': 'warning'
                        }),
                        loop
                    )
                return
        except Exception:
            pass

        def _run_sniff():
            try:
                sniff(iface=self.interface, prn=self._packet_handler,
                      store=False, stop_filter=lambda _: not self._running)
            except RuntimeError as e:
                print(f"[Scanner] Scapy sniff failed: {e}")
                print("[Scanner] If on Windows, install Npcap/WinPcap to enable sniffing. Scanner disabled.")
                self._running = False
                if sio and self._loop and self._loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        sio.emit('alert', {
                            'message': 'Network detection disabled: Npcap/WinPcap missing on Windows.',
                            'severity': 'warning'
                        }),
                        self._loop
                    )

        thread = threading.Thread(target=_run_sniff, daemon=True)
        thread.start()
        print(f'[Scapy] Detector listening on {self.interface}')


    def stop(self):
        self._running = False
