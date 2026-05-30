import os
import json
import re
from typing import List
import groq
from backend.models import AttackerAction, AttackerProfile

# Fix #8: Broad invalid-key detection catches common placeholder patterns.
# Valid Groq keys start with 'gsk_' and are at least 50 chars.
_INVALID_KEY_PATTERNS = ('your_', 'mock', 'replace', 'todo', 'example', 'changeme', 'sk-')
api_key = os.environ.get('GROQ_API_KEY', '')
is_mock_mode = (
    not api_key
    or len(api_key) < 20
    or any(p in api_key.lower() for p in _INVALID_KEY_PATTERNS)
)

if is_mock_mode:
    print("[WARNING] GROQ_API_KEY not set or invalid. ShadowMesh Attacker Profiler is running in LOCAL MOCK MODE.")
    groq_client = None
else:
    groq_client = groq.AsyncGroq(api_key=api_key)

SYSTEM_PROMPT = '''You are a threat intelligence analyst inside a cyber deception platform called ShadowMesh.
You receive a log of attacker actions inside a fake network and must profile the attacker.
Always respond ONLY with a valid JSON object — no markdown, no explanation, no backticks.
JSON schema:
{
  "skill_level": "Script Kiddie" | "Intermediate" | "Advanced" | "Nation-State APT",
  "objective": "string (one sentence — what are they after?)",
  "apt_resemblance": "string (e.g. 'APT29', 'Lazarus Group', 'FIN7', 'Unknown')",
  "tools_detected": ["string", "string"],
  "confidence": float (0.0 to 1.0),
  "summary": "string (2 sentences max — behavioral summary for the SOC)"
}'''


def generate_local_profile(attacker_ip: str, actions: List[AttackerAction]) -> AttackerProfile:
    """
    Generates a high-fidelity local behavioral threat profile.
    Used as a fallback when Groq is unavailable or the API key is not configured.
    """
    action_types = [a.action_type for a in actions]
    details_str = " ".join([a.detail.lower() for a in actions])

    # Rule-based heuristics for realistic local profiling
    if any(x in details_str for x in ['mimikatz', 'credential_theft', 'env_file', 'aws_key']):
        skill_level = "Advanced"
        objective = "Exfiltrating production cloud credentials and harvesting secrets."
        apt_resemblance = "FIN7"
        tools = ["mimikatz", "curl", "hydra"]
        confidence = 0.85
        summary = "Attacker exhibits advanced targeted behavior, focused on credential access and cloud environment takeover. Immediate quarantine recommended."
    elif any(x in details_str for x in ['os fingerprint', 'ttl timing', 'timing_probe', 'syn_probe']):
        skill_level = "Intermediate"
        objective = "Performing systematic active OS fingerprinting and network mapping."
        apt_resemblance = "Unknown"
        tools = ["nmap", "zmap"]
        confidence = 0.75
        summary = "Attacker is systematically enumerating system parameters to bypass the active deception fabric. Likely preparing for targeted exploits."
    elif 'command_exec' in action_types or 'lateral_move' in action_types:
        skill_level = "Advanced"
        objective = "Establishing persistence and moving laterally to adjacent backend service nodes."
        apt_resemblance = "APT29 (Cozy Bear)"
        tools = ["ssh", "powershell", "nmap"]
        confidence = 0.80
        summary = "Lateral movement and interactive shell executions detected. Attacker behavior aligns closely with state-sponsored APT enumeration methodologies."
    elif 'login_attempt' in action_types:
        skill_level = "Intermediate"
        objective = "Conducting automated SSH or database authentication brute-force attacks."
        apt_resemblance = "Unknown"
        tools = ["hydra", "medusa"]
        confidence = 0.70
        summary = "Repetitive auth authentication failures suggest a targeted brute-force campaign. Monitoring for successful session establishment."
    else:
        skill_level = "Script Kiddie"
        objective = "Broad-spectrum subnet port scanning and reconnaissance."
        apt_resemblance = "Unknown"
        tools = ["nmap"]
        confidence = 0.60
        summary = "Basic recon port scan observed. Attacker is scanning for open ports without selective service targeting."

    return AttackerProfile(
        attacker_ip=attacker_ip,
        skill_level=skill_level,
        objective=objective,
        apt_resemblance=apt_resemblance,
        tools_detected=tools,
        confidence=confidence,
        summary=summary
    )


async def profile_attacker(attacker_ip: str, actions: List[AttackerAction]) -> AttackerProfile:
    """
    Profiles the attacker based on logs of their interactions in the honeypots.
    Utilizes Groq Llama-3.3-70b-versatile or falls back to local rule-based heuristic generation.
    """
    # Cap input actions list to prevent DOS or high processing overhead
    actions = actions[-100:]

    if len(actions) < 2:
        # Not enough data yet — return a low-confidence placeholder
        return AttackerProfile(
            attacker_ip=attacker_ip,
            skill_level='Unknown',
            objective='Reconnaissance in progress',
            apt_resemblance='Unknown',
            tools_detected=[],
            confidence=0.1,
            summary='Insufficient data for profiling. Monitoring continues.'
        )

    if is_mock_mode:
        return generate_local_profile(attacker_ip, actions)

    # Build a concise action log for the LLM prompt
    action_log = '\n'.join([
        f'[{a.action_type}] → {a.target_node_id}: {a.detail} (MITRE: {a.mitre_technique_id or "untagged"})'
        for a in actions[-20:]  # Limit to last 20 actions
    ])

    # Sanitize attacker_ip to prevent prompt injection (strip newlines and non-IP chars)
    safe_ip = re.sub(r'[^0-9a-fA-F:.\-]', '', attacker_ip)[:45]

    user_msg = f'''Attacker IP: {safe_ip}
Total actions observed: {len(actions)}
Recent action log:
{action_log}
Profile this attacker.'''

    try:
        response = await groq_client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': user_msg}
            ],
            max_tokens=400,
            temperature=0.3,
        )

        raw = response.choices[0].message.content.strip()

        # Fix #20: Guard against oversized LLM response BEFORE json.loads()
        # to prevent memory exhaustion from a malicious or runaway response.
        if len(raw) > 4096:
            raise ValueError(f"LLM response too large ({len(raw)} chars) — rejecting")

        # Strip any accidental markdown fences
        if raw.startswith('```'):
            parts = raw.split('```')
            if len(parts) >= 3:
                raw = parts[1]
            else:
                raw = parts[0]
            if raw.startswith('json'):
                raw = raw[4:]

        raw = raw.strip()
        data = json.loads(raw)
        
        # Safely extract tools_detected as a list
        tools_detected = data.get('tools_detected', [])
        if not isinstance(tools_detected, list):
            tools_detected = [str(tools_detected)]

        # Allowed skill levels per spec
        VALID_SKILL_LEVELS = {'Script Kiddie', 'Intermediate', 'Advanced', 'Nation-State APT', 'Unknown'}
        raw_skill = data.get('skill_level', 'Unknown')
        skill_level = raw_skill if raw_skill in VALID_SKILL_LEVELS else 'Unknown'

        # Clamp confidence strictly to [0.0, 1.0]
        raw_conf = float(data.get('confidence', 0.5))
        confidence = max(0.0, min(1.0, raw_conf))

        return AttackerProfile(
            attacker_ip=attacker_ip,
            skill_level=skill_level,
            objective=data.get('objective', 'Unknown'),
            apt_resemblance=data.get('apt_resemblance', 'Unknown'),
            tools_detected=tools_detected,
            confidence=confidence,
            summary=data.get('summary', 'AI profiling successful.')
        )

    except Exception as e:
        print(f"[ERROR] Groq API profiling failed: {e}. Falling back to local heuristic rules.")
        # Wrap json.loads failure / timeout / API exception in local fallback
        try:
            return generate_local_profile(attacker_ip, actions)
        except Exception as local_err:
            return AttackerProfile(
                attacker_ip=attacker_ip,
                skill_level='Unknown',
                objective='AI profiling failed',
                apt_resemblance='Unknown',
                tools_detected=[],
                confidence=0.0,
                summary=f'AI profiling error — raw response logged. Local fallback failed: {local_err}'
            )
