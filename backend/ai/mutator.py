import asyncio
import re
from backend.models import AttackerAction, TopologySnapshot
from backend.ai.topology import generate_topology, mutate_topology
from backend.events import EVENTS

# Key details that signal an active server fingerprinting attempt (checking if targets are fake)
FINGERPRINT_PATTERNS = [
    'timing_probe', 'ttl_analysis', 'banner_comparison',
    'port_timing', 'os_fingerprint', 'syn_probe'
]

def detect_fingerprinting(action: AttackerAction) -> bool:
    """
    Scans incoming attacker behaviors for patterns that indicate systematic fingerprinting
    (trying to map if the servers are real honeypots or identifying exact OS flags).
    Pure function -- no I/O, no awaiting needed.
    """
    # Rule 1: Payload explicitly states hitting > 12 ports (e.g. 'hit 15 ports')
    if action.action_type == 'port_scan':
        m = re.search(r'hit\s+(\d+)\s+ports', action.detail.lower())
        if m and int(m.group(1)) > 12:
            return True

    # Rule 2: Detail string explicitly contains any of our known fingerprint patterns
    detail_lower = action.detail.lower()
    if any(pattern in detail_lower for pattern in FINGERPRINT_PATTERNS):
        return True

    # Rule 3: Detail contains explicit OS timing/detection flags
    if any(term in detail_lower for term in ['os fingerprint', 'os detection', 'ttl timing', '-o flag']):
        return True

    return False


async def trigger_mutation(sio, current_topology: TopologySnapshot) -> TopologySnapshot:
    """
    Coordinates the dynamic deception fabric reshuffle.
    1. Emits events for client-side fog animation cues.
    2. Lets the animation run while calculations execute in background.
    3. Generates the new topology generation.
    4. Publishes updates and dispatch system-wide SOC alerts.
    """
    print(f"[*] Reshuffling Deception Fabric. Mutation Triggered for Generation {current_topology.generation}...")

    # Step 1: Tell all Socket.IO clients that mutation has started (animates fog of war)
    if sio:
        try:
            await sio.emit(EVENTS['TOPOLOGY_MUTATING'], {"status": "shuffling"})
        except Exception as e:
            print(f"[ERROR] Socket.IO emit failed (TOPOLOGY_MUTATING): {e}")

    # Step 2: Let the frontend slide in the visual fog of war
    await asyncio.sleep(1.5)

    # Step 3: Run the graph reshuffle and increment the network generation counter
    try:
        new_topology = await mutate_topology(current_topology)
    except Exception as e:
        print(f"[ERROR] Topology mutation failed: {e}")
        # Notify frontend that mutation failed
        if sio:
            try:
                await sio.emit(EVENTS['ALERT'], {
                    "message": "Topology mutation failed — system error",
                    "severity": "critical"
                })
            except:
                pass
        raise

    # Step 4: Dispatch the new network structure to all SOC listeners
    if sio:
        try:
            await sio.emit(EVENTS['TOPOLOGY_UPDATE'], new_topology.model_dump())
        except Exception as e:
            print(f"[ERROR] Socket.IO emit failed (TOPOLOGY_UPDATE): {e}")

    # Step 5: Send a high-priority SOC warning notifying that the attacker's map was neutralized
    if sio:
        try:
            await sio.emit(EVENTS['ALERT'], {
                "message": "Topology reshuffled — attacker fingerprinting attempt neutralized.",
                "severity": "info"
            })
        except Exception as e:
            print(f"[ERROR] Socket.IO emit failed (ALERT): {e}")

    print(f"[+] Deception Fabric successfully mutated to Generation {new_topology.generation}.")
    return new_topology
