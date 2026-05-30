import asyncio
from fastapi import APIRouter, HTTPException, Request
from collections import defaultdict
from backend.models import ScanEvent, AttackerAction, TopologySnapshot, AttackerProfile
from backend.database.neo4j_client import neo4j_client
from backend.events import EVENTS

router = APIRouter()

# Global state
state_lock = asyncio.Lock()
_event_sequence: int = 0
current_topology = TopologySnapshot(nodes=[], edges=[], generation=0)
attacker_profiles = {}
attacker_actions = defaultdict(list)

# We also need sio reference
sio = None

def set_sio(sio_instance):
    global sio
    sio = sio_instance

async def set_topology(new_topology: TopologySnapshot):
    global current_topology, _event_sequence
    async with state_lock:
        current_topology = new_topology
        _event_sequence += 1

@router.post("/detect/scan")
async def detect_scan(scan: ScanEvent):
    global _event_sequence
    if sio:
        await sio.emit(EVENTS['RECON_DETECTED'], scan.model_dump())
    
    return {"status": "deception_activated", "node_count": len(current_topology.nodes)}

@router.post("/attacker/action")
async def attacker_action(action: AttackerAction):
    global _event_sequence
    
    # 1. Log to Neo4j
    await neo4j_client.log_action(action)
    
    # 2. Append to in-memory list inside lock
    async with state_lock:
        attacker_actions[action.attacker_ip].append(action)
        _event_sequence += 1
        sequence = _event_sequence
        
    if sio:
        payload = action.model_dump()
        payload['sequence'] = sequence
        await sio.emit(EVENTS['ATTACKER_ACTION'], payload)
        
    return {"status": "logged"}

@router.get("/topology/current")
async def get_topology_current():
    return current_topology

@router.get("/attacker/profile/{attacker_ip}")
async def get_attacker_profile(attacker_ip: str):
    profile = attacker_profiles.get(attacker_ip)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile

@router.get("/neo4j/attack-path/{attacker_ip}")
async def get_attack_path(attacker_ip: str):
    path = await neo4j_client.get_attack_path(attacker_ip)
    return path

@router.post("/topology/mutate")
async def mutate_topology():
    global current_topology, _event_sequence
    
    if sio:
        await sio.emit(EVENTS['TOPOLOGY_MUTATING'], {"status": "mutating"})
        await asyncio.sleep(1.5)
        # Stub mutation logic
        async with state_lock:
            current_topology.generation += 1
            _event_sequence += 1
            payload = current_topology.model_dump()
            payload['sequence'] = _event_sequence
            
        await sio.emit(EVENTS['TOPOLOGY_UPDATE'], payload)
        
    return {"status": "mutated", "generation": current_topology.generation}
