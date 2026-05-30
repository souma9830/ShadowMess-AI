import random
import uuid
import ipaddress
from typing import Optional
from backend.models import AttackerProfile, NetworkNode, TopologySnapshot
from backend.deception.container_manager import spawn_container
from backend.events import EVENTS

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
    """
    objective_lower = profile.objective.lower()
    
    # Substring search to identify objective matches
    matched_key = None
    for key in OBJECTIVE_TO_LURE.keys():
        if key in objective_lower:
            matched_key = key
            break
            
    if not matched_key:
        print(f"[*] Attacker objective '{profile.objective}' does not trigger adaptive lures. Deferring lure deployment.")
        return None

    lure_config = OBJECTIVE_TO_LURE[matched_key]
    node_type = lure_config['node_type']

    # Deduplicate: do not spawn more than 2 honeypot nodes of the same category in the active subnet
    existing_types = [node.node_type for node in current_topology.nodes]
    if existing_types.count(node_type) >= 2:
        print(f"[*] Subnet already has {existing_types.count(node_type)} {node_type} instances. Skipping adaptive lure deployment to prevent clutter.")
        return None

    # Pick a fresh, isolated IP address from the upper range of the bridge subnet (e.g. hosts after index 30)
    try:
        subnet = ipaddress.IPv4Network('172.20.0.0/24')
        upper_hosts = list(subnet.hosts())[30:]  # Use upper portion for decoy lures
        
        # Exclude currently occupied IPs
        occupied_ips = {n.ip for n in current_topology.nodes}
        available_ips = [str(h) for h in upper_hosts if str(h) not in occupied_ips]
        
        if not available_ips:
            print("[ERROR] Subnet upper IPs exhausted! Cannot allocate address for decoy lure.")
            return None
            
        lure_ip = random.choice(available_ips)
    except Exception as e:
        print(f"[ERROR] Subnet address parsing failed: {e}")
        # Fallback static dynamic IP allocation
        lure_ip = f"172.20.0.{random.randint(180, 240)}"

    # Construct the targeted NetworkNode model
    lure_node = NetworkNode(
        node_id=f'lure_{generation}_{uuid.uuid4().hex[:8]}',  # UUID-based, no collision risk
        ip=lure_ip,
        node_type=node_type,
        ports=[443, 8443] if node_type in ['api_gateway', 'auth_service'] else [80, 445] if node_type == 'file_server' else [3306, 5432],
        banner=f'Adaptive Lure — {lure_config["label"]}',
        os='Ubuntu 22.04',
        is_fake=True,
        container_id=None
    )

    print(f"[*] Deploying Adaptive Decoy: {lure_config['hint']} at IP {lure_ip}...")

    # Programmatically spawn the container instance via manager
    try:
        cid = await spawn_container(lure_node)
    except Exception as spawn_err:
        print(f"[ERROR] Container spawn failed for lure {lure_node.node_id}: {spawn_err}")
        return None
    
    if cid:
        lure_node.container_id = cid
        
        # Emit Socket.IO alert events
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
                print(f"[ERROR] Socket.IO emit failed (LURE_SPAWNED/ALERT): {sio_err}")
                
        print(f"[+] Adaptive Decoy deployed successfully. Node ID: {lure_node.node_id} | IP: {lure_node.ip}")
        return lure_node
        
    print("[ERROR] Failed to launch dynamic adaptive container instance. Decoy aborted.")
    return None
