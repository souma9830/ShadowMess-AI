import pathlib
from typing import Optional, Dict, Any
from mitreattack.stix20 import MitreAttackData

# Resolve STIX file path
MITRE_JSON_PATH = pathlib.Path(__file__).parent / "enterprise-attack.json"

class MitreMapper:
    # Fallback dictionary mapping core actions to realistic standard techniques
    ACTION_MAP = {
        'port_scan':        ('T1046', 'Network Service Discovery'),
        'login_attempt':    ('T1110', 'Brute Force'),
        'command_exec':     ('T1059', 'Command and Scripting Interpreter'),
        'data_access':      ('T1005', 'Data from Local System'),
        'lateral_move':     ('T1021', 'Remote Services'),
        'file_access':      ('T1083', 'File and Directory Discovery'),
        'credential_theft':  ('T1552', 'Unsecured Credentials'),  # Consistent with detail-based rule
        'canary_trigger':   ('T1005', 'Data from Local System'),
    }

    def __init__(self):
        self._technique_cache: Dict[str, Dict[str, str]] = {}  # technique_id -> { name, tactic, description }
        self._is_initialized = False
        self._initialize_mapper()

    def _initialize_mapper(self):
        """
        Safely loads the MITRE STIX JSON file and indexes all active enterprise techniques.
        """
        try:
            if not MITRE_JSON_PATH.exists():
                print(f"[ERROR] MITRE database not found at {MITRE_JSON_PATH}. Run scripts/download_mitre.py first.")
                return

            print(f"[*] Initializing MITRE ATT&CK Mapper from cached dataset...")
            # Instantiate STIX parser
            self.attack_data = MitreAttackData(str(MITRE_JSON_PATH))
            self._build_cache()
            self._is_initialized = True
            print(f"[+] MITRE ATT&CK Mapper successfully loaded! {len(self._technique_cache)} techniques indexed.")
        except Exception as e:
            print(f"[ERROR] Failed to parse MITRE STIX database: {e}")
            self._is_initialized = False

    def _build_cache(self):
        """
        Caches technique metadata for lightning-fast sub-millisecond query lookups.
        """
        techniques = self.attack_data.get_techniques(remove_revoked_deprecated=True)
        for t in techniques:
            # Safely extract technique ID (e.g. T1046)
            external_refs = t.get('external_references', [{}])
            tid = ""
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    tid = ref.get('external_id', '')
                    break
            
            if not tid:
                continue

            name = t.get('name', 'Unknown Technique')
            
            # Extract tactical phase (e.g. discovery, credential-access)
            kill_chain = t.get('kill_chain_phases', [])
            tactic = kill_chain[0]['phase_name'] if kill_chain else 'unknown'
            
            # Format description snippet
            desc = t.get('description', '')
            desc_short = (desc[:117] + '...') if len(desc) > 120 else desc

            self._technique_cache[tid] = {
                'name': name,
                'tactic': tactic,
                'description': desc_short
            }

    def tag_action(self, action_type: str, detail: str) -> Optional[Dict[str, Any]]:
        """
        Heuristically maps an observed attacker action to its corresponding MITRE ATT&CK technique.
        Returns a dict containing { technique_id, technique_name, tactic } or None.
        """
        # Check detail strings for keyword signals to make the classification context-aware
        detail_lower = detail.lower()
        
        if 'ssh' in detail_lower or 'rdp' in detail_lower:
            tid, default_name = 'T1021', 'Remote Services'
        elif 'password' in detail_lower or 'auth' in detail_lower or 'login' in detail_lower:
            tid, default_name = 'T1110', 'Brute Force'
        elif 'nmap' in detail_lower or 'scan' in detail_lower or 'fingerprint' in detail_lower:
            tid, default_name = 'T1046', 'Network Service Discovery'
        elif 'env_file' in detail_lower or 'aws_key' in detail_lower or 'credentials' in detail_lower:
            tid, default_name = 'T1552', 'Unsecured Credentials'
        else:
            result = self.ACTION_MAP.get(action_type)
            if not result:
                # Catch-all: default to system network discovery if type is scan, else interpreter
                if 'scan' in action_type:
                    tid, default_name = 'T1046', 'Network Service Discovery'
                else:
                    tid, default_name = 'T1059', 'Command and Scripting Interpreter'
            else:
                tid, default_name = result

        # Check our dynamic cache for complete details
        if self._is_initialized and tid in self._technique_cache:
            cached = self._technique_cache[tid]
            return {
                'technique_id': tid,
                'technique_name': cached['name'],
                'tactic': cached['tactic']
            }
        
        # Fallback metadata if initialization failed or technique is custom
        return {
            'technique_id': tid,
            'technique_name': default_name,
            'tactic': 'discovery' if tid == 'T1046' else 'credential-access' if tid == 'T1552' else 'execution'
        }

# Singleton instance - loaded once at application launch
mitre_mapper = MitreMapper()
