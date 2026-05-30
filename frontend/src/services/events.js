export const EVENTS = {
    // Backend → Frontend
    RECON_DETECTED:     'recon_detected',
    TOPOLOGY_UPDATE:    'topology_update',
    TOPOLOGY_MUTATING:  'topology_mutating',
    ATTACKER_ACTION:    'attacker_action',
    PROFILE_UPDATE:     'profile_update',
    MITRE_TAG:          'mitre_tag',
    ALERT:              'alert',
    CONTAINER_SPAWNED:  'container_spawned',
    CONTAINER_KILLED:   'container_killed',
    STATUS:             'status',
    CANARY_TRIGGERED:   'canary_triggered',
    CREDENTIAL_STOLEN:  'credential_stolen',
    LURE_SPAWNED:       'lure_spawned',
    THREAT_SCORE:       'threat_score',
    DNS_QUERY:          'dns_query',
    BREADCRUMB_UPDATE:  'breadcrumb_update',
    
    // Frontend → Backend
    TRIGGER_SCAN:       'trigger_scan',
    TRIGGER_LOGIN:      'trigger_login',
    TRIGGER_MUTATE:     'trigger_mutate',
};
