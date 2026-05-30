# Single source of truth for all Socket.IO event names.
# These must match exactly between the backend and the frontend.

EVENTS = {
    # Backend -> Frontend Alerts & Telemetry
    'RECON_DETECTED':     'recon_detected',       # Attacker port scan detected
    'TOPOLOGY_UPDATE':    'topology_update',       # New fake topology generated
    'TOPOLOGY_MUTATING':  'topology_mutating',     # Topology about to reshuffle (animate fog)
    'ATTACKER_ACTION':    'attacker_action',       # Attacker interacted with a fake node
    'PROFILE_UPDATE':     'profile_update',        # Groq attacker profile updated
    'MITRE_TAG':          'mitre_tag',             # New MITRE technique detected
    'ALERT':              'alert',                 # High-priority alert
    'CONTAINER_SPAWNED':  'container_spawned',     # New fake Docker container online
    'CONTAINER_KILLED':   'container_killed',      # Fake container torn down
    'STATUS':             'status',                # General status update
    'CANARY_TRIGGERED':   'canary_triggered',      # Attacker accessed a canary token URL
    'CREDENTIAL_STOLEN':  'credential_stolen',     # Attacker accessed fake credential file
    'LURE_SPAWNED':       'lure_spawned',          # Adaptive lure: new targeted fake service spun up
    'THREAT_SCORE':       'threat_score',          # ML anomaly score for attacker action
    'DNS_QUERY':          'dns_query',             # DNS query logged by honeypot

    # Frontend -> Backend Interactivity (Demo triggers)
    'TRIGGER_SCAN':       'trigger_scan',          # Manual scan simulation for demo
    'TRIGGER_LOGIN':      'trigger_login',         # Manual login attempt simulation
    'TRIGGER_MUTATE':     'trigger_mutate',        # Manual topology mutation
}
