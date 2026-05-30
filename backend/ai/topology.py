import networkx as nx
import random
import ipaddress
import json
import pathlib
from typing import List
from backend.models import NetworkNode, TopologySnapshot

# Resolve config path robustly
CONFIG_PATH = pathlib.Path(__file__).parent.parent.parent / "configs" / "node_templates.json"

# Fallback in case configs/node_templates.json is missing or corrupted
DEFAULT_TEMPLATES = {
    'web_server':   { 'ports': [80, 443, 8080], 'banner': 'Apache/2.4.41', 'os': 'Ubuntu 20.04' },
    'db_server':    { 'ports': [3306, 5432],    'banner': 'MySQL 8.0.28',  'os': 'CentOS 7'    },
    'auth_service': { 'ports': [389, 636, 88],  'banner': 'OpenLDAP 2.4',  'os': 'Windows Server 2019' },
    'file_server':  { 'ports': [445, 139, 21],  'banner': 'Samba 4.11',    'os': 'Windows Server 2016' },
    'api_gateway':  { 'ports': [443, 8443],     'banner': 'nginx/1.18.0',  'os': 'Ubuntu 22.04' },
    'mail_server':  { 'ports': [25, 143, 587],  'banner': 'Postfix 3.4',   'os': 'Debian 11'   },
    'workstation':  { 'ports': [135, 3389],     'banner': 'RDP',           'os': 'Windows 10'  }
}

try:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            NODE_TEMPLATES = json.load(f)
    else:
        NODE_TEMPLATES = DEFAULT_TEMPLATES
except Exception as e:
    print(f"Error loading configs/node_templates.json, using defaults: {e}")
    NODE_TEMPLATES = DEFAULT_TEMPLATES


async def generate_topology(generation: int = 0) -> TopologySnapshot:
    """
    Generates a realistic enterprise-like subnet using a Scale-Free network model (Barabási-Albert).
    Ensures realistic variations, port overlaps, banners, and OS information.
    """
    node_count = random.randint(9, 14)

    # Barabási-Albert scale-free graph matches real enterprise network structural growth
    G = nx.barabasi_albert_graph(n=node_count, m=2, seed=random.randint(0, 9999))

    node_types = list(NODE_TEMPLATES.keys())
    weights = [0.20, 0.15, 0.10, 0.15, 0.15, 0.10, 0.15]  # Enterprise category distribution

    subnet = ipaddress.IPv4Network('172.20.0.0/24')
    available_ips = list(subnet.hosts())[5:30]  # Skip first 5 (gateway), cap at 30 for base nodes
    random.shuffle(available_ips)
    # Guarantee unique IPs: cap node count to available pool size
    node_count = min(node_count, len(available_ips))

    # First TIER1_COUNT nodes are Tier-1 (Docker); the rest are Tier-2 (projected).
    # With node_count 9-14, this gives 3 full honeypots + up to 11 projected nodes.
    TIER1_COUNT = 3

    nodes: List[NetworkNode] = []
    for i, graph_node in enumerate(G.nodes()):
        node_type = random.choices(node_types, weights=weights, k=1)[0]
        template = NODE_TEMPLATES[node_type]

        # Clone ports to avoid mutation of shared static template lists
        ports = list(template['ports'])

        # Introduce realistic anomalies (random extra administration or debugging ports)
        if random.random() < 0.3:
            ports.append(random.choice([22, 8080, 9000, 10050]))

        banner_variation = template['banner']
        if random.random() < 0.25:
            if 'Apache' in banner_variation:
                banner_variation += ' (Ubuntu)'

        nodes.append(NetworkNode(
            node_id=f'node_{generation}_{i}',
            ip=str(available_ips[i]),  # Safe: node_count capped to len(available_ips)
            node_type=node_type,
            ports=sorted(set(ports)),
            banner=banner_variation,
            os=template['os'],
            is_fake=True,
            container_id=None,
            tier="tier1" if i < TIER1_COUNT else "tier2",
        ))

    edges = [(f'node_{generation}_{u}', f'node_{generation}_{v}') for u, v in G.edges()]
    
    return TopologySnapshot(nodes=nodes, edges=edges, generation=generation)


async def mutate_topology(current: TopologySnapshot) -> TopologySnapshot:
    """
    Simulates a partial reshuffle of the dynamic deception network.
    Retains roughly 40% of the existing nodes, regenerates the rest,
    and rebuilds the edge list so the graph remains connected.
    """
    generation = current.generation + 1
    
    # 1. Determine number of nodes to retain (roughly 40%)
    num_retained = max(1, round(len(current.nodes) * 0.4))
    
    # 2. Select retained nodes randomly
    retained_nodes = random.sample(current.nodes, k=num_retained)

    # Fix #6: Clear stale container_id on retained nodes.
    # spawn_topology() calls teardown_all() first, so these containers are already
    # destroyed. Keeping the old ID causes container tracking to point at dead containers.
    for node in retained_nodes:
        node.container_id = None
    
    # 3. Determine new target node count (9 to 14)
    target_count = random.randint(9, 14)
    num_new = max(0, target_count - num_retained)
    
    # 4. Generate new nodes
    subnet = ipaddress.IPv4Network('172.20.0.0/24')
    # Skipping first 5 hosts as in generate_topology
    all_pool_ips = list(subnet.hosts())[5:30]
    retained_ips = {ipaddress.IPv4Address(node.ip) for node in retained_nodes}
    available_ips = [str(ip) for ip in all_pool_ips if ip not in retained_ips]
    random.shuffle(available_ips)
    
    # Cap num_new to available IP pool size to ensure no duplicate IPs
    num_new = min(num_new, len(available_ips))
    
    node_types = list(NODE_TEMPLATES.keys())
    weights = [0.20, 0.15, 0.10, 0.15, 0.15, 0.10, 0.15]  # Enterprise category distribution
    
    new_nodes: List[NetworkNode] = []
    for i in range(num_new):
        node_type = random.choices(node_types, weights=weights, k=1)[0]
        template = NODE_TEMPLATES[node_type]
        
        ports = list(template['ports'])
        if random.random() < 0.3:
            ports.append(random.choice([22, 8080, 9000, 10050]))
            
        banner_variation = template['banner']
        if random.random() < 0.25:
            if 'Apache' in banner_variation:
                banner_variation += ' (Ubuntu)'
                
        new_nodes.append(NetworkNode(
            node_id=f'node_{generation}_{i}',
            ip=available_ips[i],
            node_type=node_type,
            ports=sorted(set(ports)),
            banner=banner_variation,
            os=template['os'],
            is_fake=True,
            container_id=None,
            tier="tier2",  # New nodes in mutation are always projected (Tier-2)
        ))
        
    all_nodes = retained_nodes + new_nodes
    total_nodes_count = len(all_nodes)
    
    # 5. Rebuild edge list so the resulting graph remains connected.
    # We can use NetworkX to build a connected Barabási-Albert graph
    G = nx.barabasi_albert_graph(n=total_nodes_count, m=2, seed=random.randint(0, 9999))
    
    # Map index in G to node_id
    node_id_map = {idx: node.node_id for idx, node in enumerate(all_nodes)}
    
    edges = [(node_id_map[u], node_id_map[v]) for u, v in G.edges()]
    
    return TopologySnapshot(nodes=all_nodes, edges=edges, generation=generation)

