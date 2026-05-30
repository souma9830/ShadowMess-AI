"""
ShadowMesh — Task 12.4: STIX 2.1 Threat Intelligence Export
============================================================
Converts attacker sessions into industry-standard STIX 2.1 bundles with:
  - ThreatActor (sophistication-mapped from profile)
  - Tool objects (from tools_detected)
  - AttackPattern objects (from MITRE technique IDs)
  - Indicator (attacker IP)
  - Relationships (uses, attributed-to)
  - Report (intelligence summary)

Also generates human-readable HTML threat reports.
"""

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from stix2 import (
    AttackPattern,
    Bundle,
    Identity,
    Indicator,
    IPv4Address,
    Relationship,
    Report,
    ThreatActor,
    Tool,
)

from backend.models import AttackerAction, AttackerProfile

_SOPHISTICATION_MAP = {
    "script kiddie": "minimal",
    "intermediate": "intermediate",
    "advanced": "advanced",
    "nation-state apt": "strategic",
    "unknown": "minimal",
}

_PRODUCER = Identity(
    name="ShadowMesh Deception Fabric",
    identity_class="system",
    description="Automated Honeypot Intelligence Platform",
)


class STIXExporter:

    def __init__(self):
        self.producer = _PRODUCER

    def profile_to_stix_bundle(
        self,
        profile: Any,
        actions: List[AttackerAction],
    ) -> Dict[str, Any]:
        if isinstance(profile, dict):
            ip = profile.get("attacker_ip", "0.0.0.0")
            skill = profile.get("skill_level", "Unknown")
            objective = profile.get("objective", "")
            apt = profile.get("apt_resemblance", "Unknown Threat Actor")
            tools = profile.get("tools_detected", [])
            confidence_val = profile.get("confidence", 0.5)
            summary = profile.get("summary", "")
        else:
            ip = getattr(profile, "attacker_ip", "0.0.0.0")
            skill = getattr(profile, "skill_level", "Unknown")
            objective = getattr(profile, "objective", "")
            apt = getattr(profile, "apt_resemblance", "Unknown Threat Actor")
            tools = getattr(profile, "tools_detected", [])
            confidence_val = getattr(profile, "confidence", 0.5)
            summary = getattr(profile, "summary", "")

        objects = [self.producer]

        actor = self._create_threat_actor(ip, skill, objective, apt)
        objects.append(actor)

        indicator = self._create_indicator(ip)
        objects.append(indicator)

        rel_attr = Relationship(
            source_ref=actor.id,
            relationship_type="attributed-to",
            target_ref=indicator.id,
            description=f"Threat actor observed from {ip}",
        )
        objects.append(rel_attr)

        tool_objects = self._create_tools(tools)
        for tool in tool_objects:
            objects.append(tool)
            rel = Relationship(
                source_ref=actor.id,
                relationship_type="uses",
                target_ref=tool.id,
            )
            objects.append(rel)

        seen_techniques = set()
        pattern_objects = []
        for action in actions:
            if action.mitre_technique_id and action.mitre_technique_id not in seen_techniques:
                seen_techniques.add(action.mitre_technique_id)
                pattern = self._create_attack_pattern(action)
                pattern_objects.append(pattern)
                objects.append(pattern)
                rel = Relationship(
                    source_ref=actor.id,
                    relationship_type="uses",
                    target_ref=pattern.id,
                    description=f"Observed: {action.detail}",
                )
                objects.append(rel)

        report = self._create_report(
            ip, objective, confidence_val, tools, seen_techniques, actions, summary,
            actor, tool_objects, pattern_objects, indicator,
        )
        objects.append(report)

        bundle = Bundle(objects=objects)
        return json.loads(bundle.serialize())

    def _create_threat_actor(self, ip: str, skill: str, objective: str, apt: str) -> ThreatActor:
        name = apt if apt and apt != "Unknown Threat Actor" else f"Unknown Threat Actor ({ip})"
        sophistication = _SOPHISTICATION_MAP.get(skill.lower(), "minimal")

        return ThreatActor(
            name=name,
            description=f"Inferred Objective: {objective}",
            sophistication=sophistication,
            goals=[objective] if objective else [],
            aliases=[ip],
            roles=["attacker"],
        )

    def _create_indicator(self, ip: str) -> Indicator:
        return Indicator(
            name=f"Attacker IP: {ip}",
            description=f"Network traffic indicator for attacker source IP {ip}",
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def _create_tools(self, tools: List[str]) -> List[Tool]:
        result = []
        for tool_name in tools:
            t = Tool(
                name=tool_name,
                description=f"Tool detected in attacker session: {tool_name}",
            )
            result.append(t)
        return result

    def _create_attack_pattern(self, action: AttackerAction) -> AttackPattern:
        technique_id = action.mitre_technique_id or "unknown"
        technique_name = action.mitre_technique_name or "Unknown Technique"
        url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"

        return AttackPattern(
            name=technique_name,
            description=f"Observed: {action.detail}",
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": url,
                }
            ],
        )

    def _create_report(
        self, ip, objective, confidence, tools, techniques, actions, summary,
        actor, tool_objects, pattern_objects, indicator,
    ) -> Report:
        object_refs = [actor.id, indicator.id]
        object_refs.extend(t.id for t in tool_objects)
        object_refs.extend(p.id for p in pattern_objects)

        duration = ""
        if actions:
            timestamps = [a.timestamp for a in actions]
            start = min(timestamps)
            end = max(timestamps)
            duration_sec = end - start
            duration = f"{int(duration_sec // 60)} minutes" if duration_sec > 60 else f"{int(duration_sec)} seconds"

        description = (
            f"Threat Intelligence Report for {ip}\n\n"
            f"Summary: {summary}\n"
            f"Objective: {objective}\n"
            f"Confidence: {int(confidence * 100)}%\n"
            f"Tools: {', '.join(tools) if tools else 'None detected'}\n"
            f"Techniques: {', '.join(techniques) if techniques else 'None mapped'}\n"
            f"Actions: {len(actions)}\n"
            f"Session Duration: {duration or 'N/A'}\n"
        )

        return Report(
            name=f"ShadowMesh Threat Report — {ip}",
            description=description,
            published=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            object_refs=object_refs,
            report_types=["threat-report"],
        )

    def generate_html_report(
        self,
        attacker_ip: str,
        profile: Any,
        actions: List[AttackerAction],
    ) -> str:
        if isinstance(profile, dict):
            skill = profile.get("skill_level", "Unknown")
            objective = profile.get("objective", "")
            apt = profile.get("apt_resemblance", "Unknown")
            tools = profile.get("tools_detected", [])
            confidence = profile.get("confidence", 0.0)
            summary = profile.get("summary", "")
        else:
            skill = getattr(profile, "skill_level", "Unknown")
            objective = getattr(profile, "objective", "")
            apt = getattr(profile, "apt_resemblance", "Unknown")
            tools = getattr(profile, "tools_detected", [])
            confidence = getattr(profile, "confidence", 0.0)
            summary = getattr(profile, "summary", "")

        techniques = {}
        for a in actions:
            if a.mitre_technique_id:
                techniques[a.mitre_technique_id] = a.mitre_technique_name or "Unknown"

        action_types = {}
        for a in actions:
            action_types[a.action_type] = action_types.get(a.action_type, 0) + 1

        cloud_actions = [a for a in actions if "cloud" in a.action_type or "aws" in a.detail.lower()]
        ad_actions = [a for a in actions if "ldap" in a.action_type or "ad" in a.action_type or "enumerat" in a.detail.lower()]
        cred_actions = [a for a in actions if "credential" in a.action_type]
        canary_actions = [a for a in actions if "canary" in a.action_type]

        duration = ""
        if actions:
            timestamps = [a.timestamp for a in actions]
            dur_sec = max(timestamps) - min(timestamps)
            duration = f"{int(dur_sec // 60)}m {int(dur_sec % 60)}s"

        timeline_rows = ""
        for a in actions[-50:]:
            ts = datetime.fromtimestamp(a.timestamp, tz=timezone.utc).strftime("%H:%M:%S")
            mitre = a.mitre_technique_id or "-"
            timeline_rows += f"<tr><td>{ts}</td><td>{a.action_type}</td><td>{a.target_node_id}</td><td>{a.detail[:80]}</td><td>{mitre}</td></tr>\n"

        mitre_rows = ""
        for tid, tname in techniques.items():
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            mitre_rows += f'<tr><td><a href="{url}">{tid}</a></td><td>{tname}</td></tr>\n'

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ShadowMesh Threat Report — {attacker_ip}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2em; background: #0d1117; color: #c9d1d9; }}
h1 {{ color: #58a6ff; }} h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 0.3em; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; }}
th {{ background: #161b22; color: #58a6ff; }}
tr:nth-child(even) {{ background: #161b22; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; }}
.critical {{ background: #da3633; color: white; }}
.high {{ background: #d29922; color: black; }}
.medium {{ background: #388bfd; color: white; }}
a {{ color: #58a6ff; }}
</style></head><body>
<h1>ShadowMesh Threat Intelligence Report</h1>
<h2>Threat Assessment</h2>
<table>
<tr><th>Attacker IP</th><td>{attacker_ip}</td></tr>
<tr><th>Skill Level</th><td>{skill}</td></tr>
<tr><th>APT Resemblance</th><td>{apt}</td></tr>
<tr><th>Objective</th><td>{objective}</td></tr>
<tr><th>Confidence</th><td>{int(confidence * 100)}%</td></tr>
<tr><th>Session Duration</th><td>{duration or 'N/A'}</td></tr>
<tr><th>Total Actions</th><td>{len(actions)}</td></tr>
<tr><th>Tools Detected</th><td>{', '.join(tools) if tools else 'None'}</td></tr>
</table>
<p>{summary}</p>

<h2>MITRE ATT&CK Summary</h2>
<table><tr><th>Technique ID</th><th>Name</th></tr>
{mitre_rows if mitre_rows else '<tr><td colspan="2">No techniques mapped</td></tr>'}
</table>

<h2>Activity Breakdown</h2>
<table><tr><th>Category</th><th>Count</th></tr>
<tr><td>Cloud Activity</td><td>{len(cloud_actions)}</td></tr>
<tr><td>AD Enumeration</td><td>{len(ad_actions)}</td></tr>
<tr><td>Credential Theft</td><td>{len(cred_actions)}</td></tr>
<tr><td>Canary Triggers</td><td>{len(canary_actions)}</td></tr>
</table>

<h2>Session Timeline (last 50)</h2>
<table><tr><th>Time</th><th>Type</th><th>Target</th><th>Detail</th><th>MITRE</th></tr>
{timeline_rows if timeline_rows else '<tr><td colspan="5">No actions recorded</td></tr>'}
</table>

<h2>Recommended Actions</h2>
<ul>
<li>Block source IP <strong>{attacker_ip}</strong> at perimeter firewall</li>
<li>Rotate any credentials that may have been exposed</li>
<li>Review access logs for lateral movement from this IP</li>
<li>Update IDS/IPS signatures for detected techniques</li>
<li>Share STIX bundle with threat intelligence partners</li>
</ul>

<p style="color:#8b949e;font-size:0.85em;margin-top:3em;">Generated by ShadowMesh Deception Fabric — {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
</body></html>"""


# Backward-compatible function (used by existing routes.py)
def generate_stix_bundle(attacker_ip: str, profile: Any, actions: List[AttackerAction]) -> Dict[str, Any]:
    if isinstance(profile, dict):
        profile_with_ip = dict(profile)
        profile_with_ip.setdefault("attacker_ip", attacker_ip)
    else:
        profile_with_ip = profile
    exporter = STIXExporter()
    return exporter.profile_to_stix_bundle(profile_with_ip, actions)
