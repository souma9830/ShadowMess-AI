import asyncio
import time
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse
from collections import defaultdict
from backend.models import ScanEvent, AttackerAction, TopologySnapshot, AttackerProfile
from backend.database.neo4j_client import neo4j_client
from backend.events import EVENTS
from backend.ai.profiler import profile_attacker
from backend.ai.topology import generate_topology
from backend.ai.mutator import trigger_mutation
from backend.ai.lure_generator import maybe_spawn_lure
from backend.mitre.mapper import mitre_mapper
from backend.alerting import slack
from backend.deception.container_manager import spawn_topology
from backend.deception.credentials import cred_manager
from backend.deception.canary import canary_manager

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
    global current_topology, _event_sequence

    # Generate a fresh deception topology on first recon
    if not current_topology.nodes:
        new_topo = await generate_topology(generation=1)
        await spawn_topology(new_topo, sio)
        async with state_lock:
            current_topology = new_topo
            _event_sequence += 1

    if sio:
        await sio.emit(EVENTS['RECON_DETECTED'], scan.model_dump())
        # Send topology immediately so the dashboard graph populates
        await sio.emit(EVENTS['TOPOLOGY_UPDATE'], current_topology.model_dump())

    # Fire Slack alert in background — never blocks the response
    asyncio.create_task(slack.alert_recon_detected(scan.source_ip, scan.scan_type))

    return {"status": "deception_activated", "node_count": len(current_topology.nodes)}


async def _run_profiling_pipeline(action: AttackerAction, actions_for_ip: list):
    global attacker_profiles, current_topology

    ip = action.attacker_ip

    # --- MITRE tagging ---
    mitre_tag = mitre_mapper.tag_action(action.action_type, action.detail)
    if mitre_tag and sio:
        await sio.emit(EVENTS['MITRE_TAG'], {
            'attacker_ip': ip,
            'technique_id': mitre_tag['technique_id'],
            'technique_name': mitre_tag['technique_name'],
            'tactic': mitre_tag['tactic'],
        })

    # --- AI Profiling (Groq or local heuristic) ---
    try:
        profile = await profile_attacker(ip, actions_for_ip)
        attacker_profiles[ip] = profile
        if sio:
            payload = profile.model_dump()
            payload['attacker_ip'] = ip  # ensure field present for frontend
            await sio.emit(EVENTS['PROFILE_UPDATE'], payload)

        # --- Slack: alert on new high-skill profile ---
        if profile.skill_level in ('Advanced', 'Nation-State APT') and profile.confidence > 0.6:
            asyncio.create_task(slack.send_slack_alert(
                message=f"High-skill attacker profiled: `{ip}` — {profile.skill_level}",
                severity='critical',
                fields={
                    'Attacker IP': ip,
                    'Objective': profile.objective,
                    'APT Resemblance': profile.apt_resemblance,
                    'Confidence': f"{int(profile.confidence * 100)}%",
                }
            ))

        # --- Adaptive lure spawning ---
        async with state_lock:
            topo_snapshot = current_topology

        lure_node = await maybe_spawn_lure(profile, topo_snapshot, sio, topo_snapshot.generation)
        if lure_node:
            async with state_lock:
                current_topology.nodes.append(lure_node)
                _event_sequence += 1
                payload = current_topology.model_dump()
                payload['sequence'] = _event_sequence
                
            if sio:
                await sio.emit(EVENTS['TOPOLOGY_UPDATE'], payload)

    except Exception as e:
        print(f"[ERROR] Profiling pipeline failed for {ip}: {e}")


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
        actions_snapshot = list(attacker_actions[action.attacker_ip])

    if sio:
        payload = action.model_dump()
        payload['sequence'] = sequence
        await sio.emit(EVENTS['ATTACKER_ACTION'], payload)

    # 3. Run MITRE + profiling + lure pipeline in background — never blocks response
    asyncio.create_task(_run_profiling_pipeline(action, actions_snapshot))

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

@router.get("/attackers")
async def get_attackers():
    sessions = []
    for ip, actions in attacker_actions.items():
        if not actions: continue
        profile = attacker_profiles.get(ip)

        # safely extract skill level from either dict or AttackerProfile object
        skill_level = 'Unknown'
        if profile:
            if isinstance(profile, dict):
                skill_level = profile.get('skill_level', 'Unknown')
            else:
                skill_level = getattr(profile, 'skill_level', 'Unknown')

        sessions.append({
            "ip": ip,
            "action_count": len(actions),
            "first_seen": actions[0].timestamp,
            "last_seen": actions[-1].timestamp,
            "skill_level": skill_level,
        })
    return sessions

@router.get("/attacker/{ip}/actions")
async def get_attacker_actions(ip: str):
    return attacker_actions.get(ip, [])[-50:]

@router.get("/neo4j/attack-path/{attacker_ip}")
async def get_attack_path(attacker_ip: str):
    path = await neo4j_client.get_attack_path(attacker_ip)
    return path

@router.get("/creds/{node_id}/{cred_id}")
async def download_credential(node_id: str, cred_id: str, request: Request):
    cred = cred_manager.get_credential(cred_id)
    if not cred or cred.node_id != node_id:
        raise HTTPException(status_code=404, detail="Credential not found")
        
    cred_manager.mark_accessed(cred_id)
    
    attacker_ip = request.headers.get("X-Forwarded-For") or request.client.host
    
    # Log the theft
    action = AttackerAction(
        attacker_ip=attacker_ip,
        action_type="credential_theft",
        target_node_id=node_id,
        detail=f"Stolen credential: {cred.filename}",
        timestamp=time.time()
    )
    
    # Process action through existing pipeline in background
    asyncio.create_task(attacker_action(action))
    
    if sio:
        try:
            await sio.emit(EVENTS['CREDENTIAL_STOLEN'], {
                "cred_id": cred.cred_id,
                "filename": cred.filename,
                "cred_type": cred.cred_type,
                "attacker_ip": attacker_ip
            })
        except Exception:
            pass
            
    try:
        if hasattr(slack, 'alert_credential_stolen'):
            asyncio.create_task(slack.alert_credential_stolen(
                attacker_ip=attacker_ip,
                filename=cred.filename,
                cred_type=cred.cred_type
            ))
    except Exception:
        pass
        
    return PlainTextResponse(
        content=cred.content,
        media_type="application/octet-stream"
    )


@router.get("/canary/{token_id}")
async def trigger_canary(token_id: str, request: Request):
    token = canary_manager.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Not found")

    attacker_ip = request.headers.get("X-Forwarded-For") or request.client.host
    canary_manager.mark_triggered(token_id, attacker_ip)

    if sio:
        try:
            await sio.emit(EVENTS['CANARY_TRIGGERED'], {
                "token_id": token.token_id,
                "label": token.label,
                "node_id": token.node_id,
                "triggered_by_ip": attacker_ip,
            })
        except Exception:
            pass

    action = AttackerAction(
        attacker_ip=attacker_ip,
        action_type="canary_trigger",
        target_node_id=token.node_id,
        detail=f"Canary accessed: {token.label}",
        timestamp=time.time(),
    )
    asyncio.create_task(attacker_action(action))

    try:
        asyncio.create_task(slack.alert_canary_triggered(attacker_ip, token.label, token.node_id))
    except Exception:
        pass

    return HTMLResponse(
        content="<html><body>403 Forbidden — Access Denied</body></html>",
        status_code=403,
    )


async def _do_mutate():
    """Background task: use Phase 3 mutator to reshuffle topology and broadcast."""
    global current_topology
    new_topology = await trigger_mutation(sio, current_topology)
    await spawn_topology(new_topology, sio)
    async with state_lock:
        current_topology = new_topology
    # Slack alert for topology mutation
    asyncio.create_task(slack.alert_topology_mutated(new_topology.generation))

@router.post("/topology/mutate")
async def mutate_topology():
    asyncio.create_task(_do_mutate())
    return {"status": "mutating", "generation": current_topology.generation}
