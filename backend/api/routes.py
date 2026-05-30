import asyncio
import ipaddress
import logging
import time
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, Response
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
from backend.deception.credentials import cred_manager
from backend.deception.canary import canary_manager
from backend.database.redis_client import redis_client
from backend.intelligence.stix_exporter import generate_stix_bundle
from backend.intelligence.pdf_report import generate_pdf_report

log = logging.getLogger("routes")
# Per-IP action list cap — prevents unbounded memory growth (Issue #5)
_ACTION_LIST_MAX = 1000
_ACTION_LIST_TRIM = 500
_MAX_TRACKED_IPS = 1000

# Groq profiling rate-limit: run every N actions per IP
_PROFILING_EVERY_N_ACTIONS = 3

router = APIRouter()

# Global state
state_lock = asyncio.Lock()
_event_sequence: int = 0
_deception_activated: bool = False  # prevents double topology generation race
_topology_spawning: bool = False
current_topology = TopologySnapshot(nodes=[], edges=[], generation=0)
attacker_profiles = {}
attacker_actions = defaultdict(list)

# We also need sio reference
sio = None

def set_sio(sio_instance):
    global sio
    sio = sio_instance

async def load_state_from_redis():
    global attacker_actions, attacker_profiles, current_topology, _event_sequence, _deception_activated
    
    actions_map, profiles_map, topology = await redis_client.load_all_state()
    
    async with state_lock:
        if topology:
            current_topology = topology
            _event_sequence = topology.generation * 1000
            if topology.nodes:
                _deception_activated = True
            
        attacker_profiles.update(profiles_map)
        for ip, actions in actions_map.items():
            # Extend in case some actions were added before load, though usually this runs on boot
            attacker_actions[ip].extend(actions)
            
    print(f"[*] Redis state hydrated: {len(attacker_profiles)} profiles, {len(actions_map)} sessions.")

async def set_topology(new_topology: TopologySnapshot):
    global current_topology, _event_sequence
    async with state_lock:
        current_topology = new_topology
        _event_sequence += 1
    await redis_client.save_topology(new_topology)

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
            await redis_client.save_topology(new_topo)
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


async def _run_profiling_pipeline(action: AttackerAction, actions_for_ip: list):
    """
    Background task: runs attacker profiling and adaptive lure
    spawning — decoupled from the hot request path.
    """
    global attacker_profiles, current_topology, _event_sequence

    ip = action.attacker_ip

    # Rate limit Groq profiling to every N actions per IP (configurable via _PROFILING_EVERY_N_ACTIONS)
    if len(actions_for_ip) % _PROFILING_EVERY_N_ACTIONS != 0:
        return

    # --- AI Profiling (Groq or local heuristic) ---
    try:
        profile = await profile_attacker(ip, actions_for_ip)
        attacker_profiles[ip] = profile
        await redis_client.save_profile(ip, profile)
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
            topo_id = id(current_topology)  # Track which topology we're working with

        lure_node = await maybe_spawn_lure(profile, topo_snapshot, sio, topo_snapshot.generation)
        if lure_node:
            async with state_lock:
                # Always append to current_topology regardless of whether it was mutated —
                # the lure container is already running and must be tracked.
                current_topology.nodes.append(lure_node)
                _event_sequence += 1
                payload = current_topology.model_dump()
                payload['sequence'] = _event_sequence
                topo_to_save = current_topology.model_copy(deep=True)

            await redis_client.save_topology(topo_to_save)

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
        await sio.emit(EVENTS['THREAT_SCORE'], {
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

    # 4. Append to in-memory list inside lock — cap to prevent memory leak (Issue #5)
    async with state_lock:
        attacker_actions[action.attacker_ip].append(action)
        if len(attacker_actions[action.attacker_ip]) > _ACTION_LIST_MAX:
            attacker_actions[action.attacker_ip] = attacker_actions[action.attacker_ip][-_ACTION_LIST_TRIM:]
            
        if len(attacker_actions) > _MAX_TRACKED_IPS:
            oldest_ip = min(attacker_actions.keys(),
                           key=lambda ip: attacker_actions[ip][0].timestamp)
            del attacker_actions[oldest_ip]
            attacker_profiles.pop(oldest_ip, None)
            
        _event_sequence += 1
        sequence = _event_sequence
        actions_snapshot = list(attacker_actions[action.attacker_ip])

    await redis_client.save_action(action.attacker_ip, action)

    # Phase 13.1: Fire SIEM integrations in background
    from backend.integrations.siem import siem
    asyncio.create_task(siem.send_all(action, attacker_profiles.get(action.attacker_ip)))

    if sio:
        payload = action.model_dump()
        payload['sequence'] = sequence
        payload['attacker_ip'] = action.attacker_ip
        await sio.emit(EVENTS['ATTACKER_ACTION'], payload)

    # 5. Check for fingerprinting and trigger mutation if detected
    # Fix #1: Update state BEFORE spawning containers to prevent stale topology reads
    global _topology_spawning
    if detect_fingerprinting(action):
        async with state_lock:
            if _topology_spawning:
                return {"status": "mutation_in_progress"}
            _topology_spawning = True
            topo_snapshot = current_topology.model_copy(deep=True)

        try:
            new_topology = await trigger_mutation(sio, topo_snapshot)
            await spawn_topology(new_topology, sio)
            async with state_lock:
                current_topology = new_topology
                _event_sequence += 1
                _topology_spawning = False
            await redis_client.save_topology(new_topology)
            asyncio.create_task(slack.alert_topology_mutated(new_topology.generation))
            return {"status": "mutated"}
        except Exception:
            async with state_lock:
                _topology_spawning = False
            raise

    # 6. Run profiling + lure pipeline in background — rate-limited, never blocks response
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
    global _event_sequence
    # Try by UUID first, then fall back to cred_type string
    # (honeypot containers embed /api/creds/{node_id}/{cred_type} in their responses)
    cred = cred_manager.get_credential(cred_id)
    if not cred or cred.node_id != node_id:
        creds_for_node = cred_manager.get_all_for_node(node_id)
        cred = next((c for c in creds_for_node if c.cred_type == cred_id), None)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    cred_manager.mark_accessed(cred.cred_id)

    # Fix #19: Validate and sanitize attacker IP — X-Forwarded-For can be spoofed/injected
    # Default to client host first, then try X-Forwarded-For override
    attacker_ip = request.client.host or "0.0.0.0"
    raw_forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if raw_forwarded:
        try:
            attacker_ip = str(ipaddress.ip_address(raw_forwarded))
        except ValueError:
            pass  # Keep request.client.host

    # Fix #2: Bypass the full attacker_action() pipeline for internal events to break
    # the potential recursion: credential_theft → mutation → spawn → credentials → theft
    action = AttackerAction(
        attacker_ip=attacker_ip,
        action_type="credential_theft",
        target_node_id=node_id,
        detail=f"Stolen credential: {cred.filename}",
        timestamp=time.time()
    )
    # Write directly — no fingerprinting check, no profiling pipeline, no mutation risk
    async with state_lock:
        attacker_actions[attacker_ip].append(action)
        if len(attacker_actions[attacker_ip]) > _ACTION_LIST_MAX:
            attacker_actions[attacker_ip] = attacker_actions[attacker_ip][-_ACTION_LIST_TRIM:]
        _event_sequence += 1
    asyncio.create_task(neo4j_client.log_action(action))
    asyncio.create_task(redis_client.save_action(attacker_ip, action))
    
    if sio:
        try:
            await sio.emit(EVENTS['CREDENTIAL_STOLEN'], {
                "cred_id": cred.cred_id,
                "filename": cred.filename,
                "cred_type": cred.cred_type,
                "attacker_ip": attacker_ip,
                "accessed_at": cred.accessed_at
            })
        except Exception as e:
            log.warning("[credential] Socket.IO emit failed: %s", e)
            
    try:
        asyncio.create_task(slack.alert_credential_stolen(
            attacker_ip=attacker_ip,
            filename=cred.filename,
            cred_type=cred.cred_type
        ))
    except Exception as e:
        log.warning("[credential] Slack alert task failed: %s", e)
        
    return PlainTextResponse(
        content=cred.content,
        media_type="application/octet-stream"
    )


@router.get("/canary/{token_id}")
async def trigger_canary(token_id: str, request: Request):
    global _event_sequence
    token = canary_manager.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Not found")

    # Fix #19: Validate attacker IP from X-Forwarded-For
    attacker_ip = request.client.host or "0.0.0.0"
    raw_forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if raw_forwarded:
        try:
            attacker_ip = str(ipaddress.ip_address(raw_forwarded))
        except ValueError:
            pass  # Keep request.client.host
    canary_manager.mark_triggered(token_id, attacker_ip)

    if sio:
        try:
            await sio.emit(EVENTS['CANARY_TRIGGERED'], {
                "token_id": token.token_id,
                "label": token.label,
                "node_id": token.node_id,
                "triggered_by_ip": attacker_ip,
            })
        except Exception as e:
            log.warning("[canary] Socket.IO emit failed: %s", e)

    # Fix #2: Bypass full pipeline for canary events (same recursion risk as credential_theft)
    action = AttackerAction(
        attacker_ip=attacker_ip,
        action_type="canary_trigger",
        target_node_id=token.node_id,
        detail=f"Canary accessed: {token.label}",
        timestamp=time.time(),
    )
    async with state_lock:
        attacker_actions[attacker_ip].append(action)
        if len(attacker_actions[attacker_ip]) > _ACTION_LIST_MAX:
            attacker_actions[attacker_ip] = attacker_actions[attacker_ip][-_ACTION_LIST_TRIM:]
        _event_sequence += 1
    asyncio.create_task(neo4j_client.log_action(action))
    asyncio.create_task(redis_client.save_action(attacker_ip, action))

    try:
        asyncio.create_task(slack.alert_canary_triggered(attacker_ip, token.label, token.node_id))
    except Exception as e:
        log.warning("[canary] Slack alert task failed: %s", e)

    return HTMLResponse(
        content="<html><body>403 Forbidden — Access Denied</body></html>",
        status_code=403,
    )


@router.get("/dns/queries")
async def get_dns_queries():
    from backend.detection.dns_honeypot import get_instance
    honeypot = get_instance()
    return honeypot.get_query_log() if honeypot else []


@router.post("/breadcrumbs/report")
async def breadcrumb_heartbeat(request: Request):
    data = await request.json()
    agent_host = data.get("agent_host", "unknown")
    planted_paths = data.get("planted_paths", [])
    timestamp = data.get("timestamp", time.time())

    try:
        await redis_client.save_breadcrumb_heartbeat(agent_host, planted_paths, timestamp)
        count = await redis_client.get_active_breadcrumb_count()
        if sio:
            await sio.emit(EVENTS['BREADCRUMB_UPDATE'], {"active_count": count})
    except Exception as e:
        log.warning("[breadcrumb] Heartbeat storage failed: %s", e)

    return {"status": "ok", "agent_host": agent_host}


async def _do_mutate():
    """Background task: use Phase 3 mutator to reshuffle topology and broadcast."""
    global current_topology, _event_sequence
    async with state_lock:
        topo_snapshot = current_topology.model_copy(deep=True)
    new_topology = await trigger_mutation(sio, topo_snapshot)
    # Fix #1: Update state BEFORE spawning containers
    async with state_lock:
        current_topology = new_topology
        _event_sequence += 1
    await redis_client.save_topology(new_topology)
    await spawn_topology(new_topology, sio)
    asyncio.create_task(slack.alert_topology_mutated(new_topology.generation))

@router.post("/topology/mutate")
async def mutate_topology():
    asyncio.create_task(_do_mutate())
    return {"status": "mutating", "generation": current_topology.generation}

@router.get("/export/stix/{attacker_ip}")
async def export_stix(attacker_ip: str):
    profile = attacker_profiles.get(attacker_ip)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    actions = attacker_actions.get(attacker_ip, [])
    bundle = generate_stix_bundle(attacker_ip, profile, actions)
    return bundle

@router.get("/export/report/{attacker_ip}")
async def export_report(attacker_ip: str):
    profile = attacker_profiles.get(attacker_ip)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    actions = attacker_actions.get(attacker_ip, [])
    pdf_bytes = generate_pdf_report(attacker_ip, profile, actions, {})
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=shadowmesh_report_{attacker_ip}.pdf"})


@router.get("/docs/{token_id}/{filename}")
async def download_decoy_doc(token_id: str, filename: str, request: Request):
    """
    Serve a generated decoy document.

    Validates the token exists, matches the stored filename, then streams
    the document bytes.  Every download fires a data_access event so the
    backend knows the attacker found and retrieved the document.
    """
    global _event_sequence
    from backend.deception.document_generator import doc_generator

    # Validate token exists in canary registry
    token = canary_manager.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Not found")

    entry = doc_generator.get_document(token_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Not found")

    # Validate filename matches stored value — prevents path traversal
    if entry.filename != filename:
        raise HTTPException(status_code=404, detail="Not found")

    # Capture attacker IP
    raw_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    try:
        attacker_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        attacker_ip = request.client.host or "unknown"

    # Fire data_access event — document download is high-value intelligence
    action = AttackerAction(
        attacker_ip    = attacker_ip,
        action_type    = "data_access",
        target_node_id = token.node_id,
        detail         = f"Decoy document downloaded: {filename}",
        timestamp      = time.time(),
    )
    async with state_lock:
        attacker_actions[attacker_ip].append(action)
        if len(attacker_actions[attacker_ip]) > _ACTION_LIST_MAX:
            attacker_actions[attacker_ip] = attacker_actions[attacker_ip][-_ACTION_LIST_TRIM:]
        _event_sequence += 1
    asyncio.create_task(neo4j_client.log_action(action))
    asyncio.create_task(redis_client.save_action(attacker_ip, action))

    if sio:
        try:
            await sio.emit(EVENTS['ATTACKER_ACTION'], {
                **action.model_dump(),
                "sequence": sequence,
            })
        except Exception as exc:
            log.warning("[docs] Socket.IO emit failed: %s", exc)

    log.info("[docs] %s downloaded %s (token %s)", attacker_ip, filename, token_id)

    return Response(
        content=entry.data,
        media_type=entry.mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

