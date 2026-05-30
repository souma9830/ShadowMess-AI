import asyncio
import random
import uuid
import ipaddress
import logging
from typing import Optional
from backend.models import AttackerProfile, NetworkNode, TopologySnapshot
from backend.deception.container_manager import spawn_container
from backend.events import EVENTS

log = logging.getLogger("lure_generator")

# Fix #4: Module-level lock + allocated-IP registry to prevent concurrent lure
# spawns from picking the same IP address.  The topology snapshot passed in is a
# point-in-time copy, so without a lock two simultaneous spawns could both read
# the same occupied_ips set and independently pick the same free IP.
_lure_lock = asyncio.Lock()
_allocated_lure_ips: set[str] = set()

# Lure IP limit per subnet (configurable)
MAX_LURE_NODES_PER_TYPE = 2

# Map attacker objectives to corresponding targeted honeypot lures
OBJECTIVE_TO_LURE = {
    'credential harvesting': {
        'node_type': 'auth_service',
        'label': 'Corporate SSO / Active Directory',
        'hint': 'Spawning fake AD — attacker is hunting credentials'
    },
    'financial data': {
        'node_type': 'db_server',
        'label': 'Finance DB — Q3 payroll and transactions',
        'hint': 'Spawning fake finance DB — attacker targeting financial data'
    },
    'intellectual property': {
        'node_type': 'file_server',
        'label': 'Engineering file share — R&D documents',
        'hint': 'Spawning fake file server — attacker targeting IP'
    },
    'espionage': {
        'node_type': 'api_gateway',
        'label': 'Internal comms API — email + calendar',
        'hint': 'Spawning fake API gateway — attacker targeting comms'
    },
}


async def maybe_spawn_lure(
    profile: AttackerProfile,
    current_topology: TopologySnapshot,
    sio,
    generation: int
) -> Optional[NetworkNode]:
    """
    Analyzes the attacker's profiled objective and programmatically deploys a highly targeted
    deceptive lure server if it matches their specific intent. Deduplicates to avoid spam.

    Fix #4: Entire IP allocation + registry update is done under _lure_lock so
    concurrent calls from different profiling tasks cannot pick the same IP.
    """
    objective_lower = profile.objective.lower()

    matched_key = None
    for key in OBJECTIVE_TO_LURE.keys():
        if key in objective_lower:
            matched_key = key
            break

    if not matched_key:
        log.info("[lure] Attacker objective '%s' does not trigger adaptive lures.", profile.objective)
        return None

    lure_config = OBJECTIVE_TO_LURE[matched_key]
    node_type = lure_config['node_type']

    # Fix #4: Hold the lock for the full IP selection + registration sequence
    async with _lure_lock:
        # Deduplicate: do not spawn more than MAX_LURE_NODES_PER_TYPE of the same category
        existing_lures = [n for n in current_topology.nodes if n.node_id.startswith('lure_')]
        lure_types = [n.node_type for n in existing_lures]
        if lure_types.count(node_type) >= MAX_LURE_NODES_PER_TYPE:
            log.info("[lure] Already %d %s lures — skipping.", lure_types.count(node_type), node_type)
            return None

        # Pick a free IP — combining topology snapshot + in-flight allocations
        try:
            subnet = ipaddress.IPv4Network('172.20.0.0/24')
            upper_hosts = list(subnet.hosts())[30:]

            occupied_ips = {n.ip for n in current_topology.nodes} | _allocated_lure_ips
            available_ips = [str(h) for h in upper_hosts if str(h) not in occupied_ips]

            if not available_ips:
                log.error("[lure] Subnet upper IPs exhausted — cannot allocate lure IP.")
                return None

            lure_ip = random.choice(available_ips)
        except Exception as e:
            log.error("[lure] Subnet address parsing failed: %s", e)
            lure_ip = f"172.20.0.{random.randint(180, 240)}"

        # Reserve the IP atomically before releasing the lock
        _allocated_lure_ips.add(lure_ip)

    # Build the lure node (outside lock — no shared state mutation here)
    lure_node = NetworkNode(
        node_id=f'lure_{generation}_{uuid.uuid4().hex[:8]}',
        ip=lure_ip,
        node_type=node_type,
        ports=[443, 8443] if node_type in ['api_gateway', 'auth_service']
              else [80, 445] if node_type == 'file_server'
              else [3306, 5432],
        banner=f'Adaptive Lure — {lure_config["label"]}',
        os='Ubuntu 22.04',
        is_fake=True,
        container_id=None
    )

    log.info("[lure] Deploying %s at %s — %s", node_type, lure_ip, lure_config['hint'])

    try:
        cid = await spawn_container(lure_node)
    except Exception as spawn_err:
        # Free the IP reservation on failure
        _allocated_lure_ips.discard(lure_ip)
        log.error("[lure] Container spawn failed for %s: %s", lure_node.node_id, spawn_err)
        return None

    if cid:
        lure_node.container_id = cid

        if sio:
            try:
                await sio.emit(EVENTS['LURE_SPAWNED'], {
                    'node_id': lure_node.node_id,
                    'node_type': lure_node.node_type,
                    'label': lure_config['label'],
                    'hint': lure_config['hint'],
                    'ip': lure_node.ip
                })
                await sio.emit(EVENTS['ALERT'], {
                    'message': f"Adaptive lure deployed: {lure_config['hint']}",
                    'severity': 'info'
                })
            except Exception as sio_err:
                log.warning("[lure] Socket.IO emit failed: %s", sio_err)

        log.info("[lure] Decoy deployed — node %s at %s", lure_node.node_id, lure_node.ip)
        return lure_node

    # Spawn returned None — free the IP
    _allocated_lure_ips.discard(lure_ip)
    log.error("[lure] spawn_container returned None for %s — decoy aborted.", lure_node.node_id)
    return None
