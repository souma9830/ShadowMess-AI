# Task 12.1D — AD Intelligence Detection & Alerting

## Detection Logic

`ADIntelligenceDetector` analyzes LDAP queries in real-time and triggers on three patterns:

| Detection | Trigger Pattern | Severity |
|-----------|----------------|----------|
| Domain Admin Enumeration | Query contains "Domain Admins" | high |
| Service Account Discovery | Query contains "svc_" or "service account" | high |
| Password Discovery | Query contains "password" + ("description" or wildcard) | critical |

The `analyze_query(attacker_ip, query)` method runs all three detectors and returns the highest-severity match (or `None` for benign queries).

## MITRE ATT&CK Mappings

| Detection Type | Technique ID | Technique Name | Tactic |
|---------------|-------------|----------------|--------|
| domain_admin_discovery | T1087.002 | Account Discovery: Domain Account | Discovery |
| service_account_discovery | T1087.002 | Account Discovery: Domain Account | Discovery |
| credential_exposure_discovery | T1552 | Unsecured Credentials | Credential Access |

## Alert Flow

```
Attacker Query → ADIntelligenceDetector.analyze_query()
    ├── detect_domain_admin_enumeration()
    ├── detect_service_account_discovery()
    └── detect_password_discovery()
         │
         ▼ (if match found)
    ├── _emit_event()        → Socket.IO "ad_enumeration"
    ├── _generate_alert()    → Internal alert log + Socket.IO "alert"
    ├── _send_slack()        → Slack webhook (wrapped in try/except)
    └── _update_profile()    → Attacker profile enrichment
```

## Socket.IO Events

### AD_ENUMERATION

Event name: `ad_enumeration`

Payload:
```json
{
  "attacker_ip": "10.0.0.5",
  "query": "(memberOf=Domain Admins)",
  "severity": "high",
  "event_type": "domain_admin_discovery",
  "mitre": "T1087.002",
  "timestamp": 1717200000.0
}
```

### ALERT

Event name: `alert`

Payload:
```json
{
  "message": "Attacker enumerated Domain Admins — possible privilege escalation planning",
  "severity": "high"
}
```

## Profile Enrichment

When a detection fires, the attacker's profile is updated:

| Detection | Objective Added | Confidence Increase |
|-----------|----------------|-------------------|
| Domain Admin enumeration | "Privilege Escalation" | +0.2 |
| Service account discovery | "Privilege Escalation" | +0.2 |
| Password discovery | "Credential Access" | +0.2 |

- `techniques_observed` list accumulates unique MITRE IDs
- `confidence` is capped at 1.0
- Multiple detections compound the confidence score

## Slack Integration

Uses the existing `slack.send_slack_alert()` async function. Messages:

- **High**: `"High Alert: Attacker enumerated Domain Admins — possible privilege escalation planning (from 10.0.0.5)"`
- **Critical**: `"Critical Alert: Attacker located credentials embedded in AD descriptions (from 10.0.0.5)"`

All Slack calls are wrapped in try/except — failures are logged but never break the request flow.

## Testing Instructions

```bash
pytest tests/test_ad_intelligence.py -v
```

Tests cover:
1. Domain Admin detection trigger
2. Service account detection trigger
3. Password discovery trigger
4. Socket.IO event emission
5. MITRE technique mapping correctness
6. Alert generation and storage
7. Slack notification dispatch
8. Slack failure graceful handling
9. Profile objective update
10. Profile confidence accumulation
11. No false positives on normal queries
12. Critical severity priority over high

## End-to-End Flow

```
Attacker queries: (memberOf=Domain Admins)
    ↓
ADIntelligenceDetector.analyze_query()
    ↓
Detection: domain_admin_discovery (severity=high, mitre=T1087.002)
    ↓
Socket.IO: "ad_enumeration" event emitted
    ↓
Alert: stored in _alert_log + "alert" event emitted
    ↓
Profile: objectives += "Privilege Escalation", confidence += 0.2
    ↓
Slack: "High Alert: Attacker enumerated Domain Admins..."
    ↓
SUCCESS
```
