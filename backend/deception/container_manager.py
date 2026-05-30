import uuid
from typing import Optional
from backend.models import NetworkNode, TopologySnapshot

# Dictionary mapping node_id -> container_id
active_containers = {}

async def spawn_container(node: NetworkNode) -> Optional[str]:
    """
    Mock implementation of container spawning.
    Generates a 12-character synthetic container ID for development.
    """
    mock_cid = uuid.uuid4().hex[:12]
    active_containers[node.node_id] = mock_cid
    print(f"[Deception Mock] programmatically spawned honeypot container {node.node_type} for ID {node.node_id} (CID: {mock_cid})")
    return mock_cid

async def teardown_all():
    """
    Mock implementation of teardown.
    """
    print(f"[Deception Mock] Tearing down all active containers: {list(active_containers.keys())}")
    active_containers.clear()

async def spawn_topology(topology: TopologySnapshot, sio):
    """
    Mock implementation of topology spawning.
    Tears down existing containers first, then spawns the new topology.
    """
    await teardown_all()
    print(f"[Deception Mock] Spawning deception topology generation {topology.generation}")
    for node in topology.nodes:
        if not node.container_id:
            cid = await spawn_container(node)
            if cid:
                node.container_id = cid
                
            # Emit event for new container
            if sio:
                try:
                    await sio.emit('container_spawned', {
                        'node_id': node.node_id,
                        'node_type': node.node_type,
                        'ip': node.ip
                    })
                except Exception as e:
                    pass
