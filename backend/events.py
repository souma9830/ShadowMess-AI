# Single source of truth for all Socket.IO event names.
# These must match exactly between the backend and the frontend.
#
# Fix #16: Audited all emissions across the codebase.
#   - 'container_spawned' was emitted in container_manager.py but not defined here — added.
#   - 'CONTAINER_KILLED' was defined but never emitted — kept as reserved for future use.
#   - 'STATUS' is only emitted on connect, documented as such.

EVENTS = {
    # Backend -> Frontend Alerts & Telemetry
    'RECON_DETECTED':     'recon_detected',       # Attacker port scan detected
    'TOPOLOGY_UPDATE':    'topology_update',       # New fake topology generated
    'TOPOLOGY_MUTATING':  'topology_mutating',     # Topology about to reshuffle (animate fog)
    'ATTACKER_ACTION':    'attacker_action',       # Attacker interacted with a fake node
    'PROFILE_UPDATE':     'profile_update',        # Groq attacker profile updated
    'MITRE_TAG':          'mitre_tag',             # New MITRE technique detected
    'ALERT':              'alert',                 # High-priority alert
    'CONTAINER_SPAWNED':  'container_spawned',     # New fake Docker container online (Fix #16: was emitted as literal)
    'CONTAINER_KILLED':   'container_killed',      # Fake container torn down (reserved — not yet emitted)
    'STATUS':             'status',                # General status update (emitted on connect only)
    'CANARY_TRIGGERED':   'canary_triggered',      # Attacker accessed a canary token URL
    'CREDENTIAL_STOLEN':  'credential_stolen',     # Attacker accessed fake credential file
    'LURE_SPAWNED':       'lure_spawned',          # Adaptive lure: new targeted fake service spun up
    'THREAT_SCORE':       'threat_score',          # ML anomaly score for attacker action
    'DNS_QUERY':          'dns_query',             # DNS query logged by honeypot
    'AD_ENUMERATION':     'ad_enumeration',        # AD enumeration detected (Task 12.1D)
    'CLOUD_CREDENTIAL_USED': 'cloud_credential_used', # Cloud credential used by attacker (Task 12.2)
    'CLOUD_ACCOUNT_DISCOVERY': 'cloud_account_discovery', # Cloud account enumeration (Task 12.2)
    'CLOUD_API_ACCESS':   'cloud_api_access',      # Generic cloud API access (Task 12.2)

    # Projection Sensor events (Tier-2 projected nodes — Task 11.3)
    'PROJECTION_ARP_HIT':      'projection_arp_hit',      # ARP probe hit a projected IP
    'PROJECTION_PORT_SCAN':    'projection_port_scan',    # TCP SYN to projected IP/port
    'PROJECTION_SERVICE_PROBE':'projection_service_probe',# Known-service port probed on projected node

    # Frontend -> Backend Interactivity (Demo triggers)
    'TRIGGER_SCAN':       'trigger_scan',          # Manual scan simulation for demo
    'TRIGGER_LOGIN':      'trigger_login',         # Manual login attempt simulation
    'TRIGGER_MUTATE':     'trigger_mutate',        # Manual topology mutation
}
