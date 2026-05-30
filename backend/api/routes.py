import asyncio
from fastapi import APIRouter, HTTPException
from collections import defaultdict
from backend.models import ScanEvent, AttackerAction, TopologySnapshot, AttackerProfile
from backend.database.neo4j_client import neo4j_client
from backend.events import EVENTS
from backend.ai.profiler import profile_attacker
from backend.ai.topology import generate_topology
from backend.ai.mutator import trigger_mutation, detect_fingerprinting
from backend.ai.lure_generator import maybe_spawn_lure
from backend.mitre.mapper import mitre_mapper
from backend.alerting import slack
from backend.deception.container_manager import spawn_topology
from backend.ai.anomaly_detector import anomaly_detector

router = APIRouter()

# Global state
state_lock = asyncio.Lock()
_event_sequence: int = 0
_deception_activated: bool = False  # prevents double topology generation race
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
    global current_topology, _event_sequence, _deception_activated

    # Claim the deception slot atomically to prevent double topology generation
    # when on_recon_detected (Scapy thread) and this route fire simultaneously.
    async with state_lock:
        already_active = _deception_activated
        if not already_active:
            _deception_activated = True

    if not already_active:
        try:
            new_topo = await generate_topology(generation=1)
            await spawn_topology(new_topo, sio)
            async with state_lock:
                current_topology = new_topo
                _event_sequence += 1
        except Exception as e:
            # Reset flag so the next scan event can retry topology generation
            async with state_lock:
                _deception_activated = False
            print(f"[ERROR] detect_scan: topology generation failed, flag reset: {e}")
            raise

    if sio:
        await sio.emit(EVENTS['RECON_DETECTED'], scan.model_dump())
        await sio.emit(EVENTS['TOPOLOGY_UPDATE'], current_topology.model_dump())

    # Fire Slack alert in background — never blocks the response
    asyncio.create_task(slack.alert_recon_detected(scan.source_ip, scan.scan_type))

    return {"status": "deception_activated", "node_count": len(current_topology.nodes)}


async def _run_profiling_pipeline(action: AttackerAction):
    """
    Background task: runs attacker profiling and adaptive lure
    spawning — decoupled from the hot request path.
    """
    global attacker_profiles, current_topology

    ip = action.attacker_ip
    actions_for_ip = attacker_actions.get(ip, [])

    # Rate limit Groq profiling to every 3 actions per IP
    if len(actions_for_ip) % 3 != 0:
        return

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
            # Deep copy so lure spawning works on a stable snapshot even if
            # current_topology is replaced by a mutation during the await below.
            topo_snapshot = current_topology.model_copy(deep=True)

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
    global _event_sequence, current_topology

    # 1. Tag with MITRE synchronously BEFORE saving
    mitre_tag = mitre_mapper.tag_action(action.action_type, action.detail)
    if mitre_tag:
        action.mitre_technique_id = mitre_tag['technique_id']
        action.mitre_technique_name = mitre_tag['technique_name']
        if sio:
            await sio.emit(EVENTS['MITRE_TAG'], {
                'attacker_ip': action.attacker_ip,
                'technique_id': mitre_tag['technique_id'],
                'technique_name': mitre_tag['technique_name'],
                'tactic': mitre_tag['tactic'],
            })

    # 2. ML anomaly scoring — runs against pre-training benign baseline
    score_result = anomaly_detector.score(action, attacker_actions[action.attacker_ip])
    if sio:
        await sio.emit('threat_score', {
            'attacker_ip': action.attacker_ip,
            'threat_score': score_result['threat_score'],
            'is_anomalous': score_result['is_anomalous'],
            'action_id': str(action.timestamp)
        })
        if score_result['is_anomalous'] and score_result['threat_score'] > 0.75:
            await sio.emit(EVENTS['ALERT'], {
                'message': f'High-anomaly action detected (score: {score_result["threat_score"]:.2f}) — possible APT behavior',
                'severity': 'critical'
            })

    # 3. Log to Neo4j
    await neo4j_client.log_action(action)

    # 4. Append to in-memory list inside lock
    async with state_lock:
        attacker_actions[action.attacker_ip].append(action)
        _event_sequence += 1
        sequence = _event_sequence

    if sio:
        payload = action.model_dump()
        payload['sequence'] = sequence
        await sio.emit(EVENTS['ATTACKER_ACTION'], payload)

    # 5. Check for fingerprinting and trigger mutation if detected
    if detect_fingerprinting(action):
        new_topology = await trigger_mutation(sio, current_topology)
        await spawn_topology(new_topology, sio)
        async with state_lock:
            current_topology = new_topology
            _event_sequence += 1
        asyncio.create_task(slack.alert_topology_mutated(new_topology.generation))
        return {"status": "mutated"}

    # 6. Run profiling + lure pipeline in background (rate-limited)
    asyncio.create_task(_run_profiling_pipeline(action))

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


@router.get("/dns/queries")
async def get_dns_queries():
    from backend.detection.dns_honeypot import get_instance
    honeypot = get_instance()
    return honeypot.get_query_log() if honeypot else []


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
