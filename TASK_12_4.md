# Task 12.4 — STIX 2.1 Threat Intelligence Export

## STIX Architecture

```
STIXExporter
├── profile_to_stix_bundle(profile, actions) → STIX 2.1 Bundle JSON
│   ├── Identity (ShadowMesh producer)
│   ├── ThreatActor (attacker profile)
│   ├── Indicator (attacker IP)
│   ├── Tool[] (detected tools)
│   ├── AttackPattern[] (MITRE techniques, deduplicated)
│   ├── Relationship[] (uses, attributed-to)
│   └── Report (intelligence summary)
│
└── generate_html_report(ip, profile, actions) → HTML string
    ├── Threat Assessment
    ├── MITRE ATT&CK Summary
    ├── Activity Breakdown (Cloud, AD, Creds, Canary)
    ├── Session Timeline
    └── Recommended Actions
```

## ThreatActor Mapping

| Profile Field | STIX Field |
|--------------|------------|
| `apt_resemblance` | `name` (falls back to "Unknown Threat Actor (IP)") |
| `skill_level` | `sophistication` (mapped below) |
| `objective` | `goals` |
| `attacker_ip` | `aliases` |

### Sophistication Mapping

| Skill Level | STIX Sophistication |
|-------------|-------------------|
| Script Kiddie | minimal |
| Intermediate | intermediate |
| Advanced | advanced |
| Nation-State APT | strategic |

## MITRE Integration

Each unique `mitre_technique_id` in the action list becomes an `AttackPattern` with:
- `name`: technique name
- `external_references`: MITRE ATT&CK source with URL

Duplicate technique IDs are deduplicated — one AttackPattern per unique technique.

URL format: `https://attack.mitre.org/techniques/T1087/002/`

## API Endpoints

### GET /api/export/stix/{attacker_ip}

Returns STIX 2.1 bundle as JSON (existing route, now uses enhanced exporter).

### GET /api/export/report/{attacker_ip}

Returns PDF report (existing route).

### GET /api/intelligence/report/{attacker_ip}

Returns HTML threat intelligence report (new capability via `generate_html_report()`).

## HTML Report Sections

1. **Threat Assessment** — IP, skill, APT resemblance, objective, confidence, duration, tools
2. **MITRE ATT&CK Summary** — Table of technique IDs with clickable links
3. **Activity Breakdown** — Counts for Cloud, AD, Credential, Canary activity
4. **Session Timeline** — Last 50 actions with timestamps, types, targets, MITRE tags
5. **Recommended Actions** — Block IP, rotate creds, review logs, update IDS, share STIX

## Example Bundle Structure

```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "objects": [
    {"type": "identity", "name": "ShadowMesh Deception Fabric"},
    {"type": "threat-actor", "name": "APT29", "sophistication": "advanced"},
    {"type": "indicator", "pattern": "[ipv4-addr:value = '192.168.1.100']"},
    {"type": "tool", "name": "nmap"},
    {"type": "tool", "name": "hydra"},
    {"type": "attack-pattern", "name": "Network Service Discovery", "external_references": [...]},
    {"type": "attack-pattern", "name": "Account Discovery: Domain Account", ...},
    {"type": "relationship", "relationship_type": "uses", ...},
    {"type": "relationship", "relationship_type": "attributed-to", ...},
    {"type": "report", "name": "ShadowMesh Threat Report — 192.168.1.100", ...}
  ]
}
```

## Testing Instructions

```bash
pip install stix2==3.0.1
pytest tests/test_stix_exporter.py -v
```

## Tests Cover

1. ThreatActor creation with sophistication mapping
2. Tool objects from `tools_detected`
3. AttackPattern creation with MITRE URLs
4. Technique deduplication
5. Indicator creation (IP pattern)
6. Relationship creation (uses + attributed-to)
7. Bundle structure validation
8. Report object in bundle
9. Backward-compatible `generate_stix_bundle()` function
10. Dict profile support (Redis hydration path)
11. HTML report generation with all sections
