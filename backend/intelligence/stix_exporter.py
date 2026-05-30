import json
import uuid
from typing import List, Dict, Any
from stix2 import Bundle, ThreatActor, IPv4Address, AttackPattern, Relationship, Identity
from backend.models import AttackerAction

def generate_stix_bundle(attacker_ip: str, profile: Any, actions: List[AttackerAction]) -> Dict[str, Any]:
    """
    Generates a STIX 2.1 compliant JSON bundle representing the attacker,
    their inferred profile, and the timeline of recorded actions mapped to MITRE ATT&CK.
    """
    stix_objects = []

    # 1. Identity (Who is producing this intel)
    producer = Identity(
        name="ShadowMesh Deception Fabric",
        identity_class="system",
        description="Automated Honeypot Intelligence"
    )
    stix_objects.append(producer)

    # 2. Threat Actor (The attacker)
    # Handle both dict and object for profile due to Redis hydration vs hot path
    if isinstance(profile, dict):
        skill = profile.get("skill_level", "Unknown")
        objective = profile.get("objective", "")
        tools = profile.get("tools_detected", [])
    else:
        skill = getattr(profile, "skill_level", "Unknown")
        objective = getattr(profile, "objective", "")
        tools = getattr(profile, "tools_detected", [])

    actor = ThreatActor(
        name=f"ShadowMesh Unknown Actor ({attacker_ip})",
        description=f"Inferred Objective: {objective}",
        sophistication=skill.lower(),
        aliases=[attacker_ip],
        roles=["attacker"]
    )
    stix_objects.append(actor)

    # 3. Infrastructure/IP Address
    ip_obs = IPv4Address(value=attacker_ip)
    stix_objects.append(ip_obs)

    # 4. Actions -> Attack Patterns
    for action in actions:
        if action.mitre_technique_id:
            pattern = AttackPattern(
                name=action.mitre_technique_name or "Unknown Technique",
                description=f"Observed detail: {action.detail}",
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": action.mitre_technique_id
                    }
                ]
            )
            stix_objects.append(pattern)
            
            # Relate Threat Actor -> Attack Pattern
            rel = Relationship(
                source_ref=actor.id,
                relationship_type="uses",
                target_ref=pattern.id,
                description=f"Observed at {action.timestamp}"
            )
            stix_objects.append(rel)

    # Wrap in a STIX 2.1 Bundle
    bundle = Bundle(objects=stix_objects)
    return json.loads(bundle.serialize())
