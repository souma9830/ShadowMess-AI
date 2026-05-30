from pydantic import BaseModel
from typing import List, Tuple, Optional

class ScanEvent(BaseModel):
    source_ip: str
    scan_type: str  # 'port_scan' | 'service_probe' | 'fingerprint_attempt'
    ports_hit: List[int]
    timestamp: float

class NetworkNode(BaseModel):
    node_id: str
    ip: str
    node_type: str  # 'web_server' | 'db_server' | 'auth_service' | 'file_server' | 'api_gateway' | 'mail_server' | 'workstation'
    ports: List[int]
    banner: str
    os: str
    is_fake: bool = True
    container_id: Optional[str] = None

class AttackerAction(BaseModel):
    attacker_ip: str
    action_type: str  # 'port_scan' | 'login_attempt' | 'command_exec' | 'data_access' | 'lateral_move' | 'credential_theft' | 'canary_trigger'
    target_node_id: str
    detail: str
    timestamp: float
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None

class AttackerProfile(BaseModel):
    attacker_ip: str
    skill_level: str   # 'Script Kiddie' | 'Intermediate' | 'Advanced' | 'Nation-State APT'
    objective: str
    apt_resemblance: str
    tools_detected: List[str]
    confidence: float
    summary: str

class TopologySnapshot(BaseModel):
    nodes: List[NetworkNode]
    edges: List[Tuple[str, str]]
    generation: int

class FakeCredential(BaseModel):
    cred_id: str           # e.g. 'cred_node_0_3_env'
    node_id: str           # which fake container it lives in
    cred_type: str         # 'env_file' | 'aws_key' | 'ssh_key' | 'db_password'
    filename: str          # e.g. '.env', 'credentials.csv', 'id_rsa'
    content: str           # the fake credential content served to the attacker
    accessed: bool = False
    accessed_at: Optional[float] = None

class CanaryToken(BaseModel):
    token_id: str          # unique UUID
    node_id: str           # which fake container it's planted in
    token_url: str         # the fake URL that triggers on access
    token_type: str        # 'document' | 'url' | 'email'
    label: str             # e.g. 'Q3_Financial_Report.pdf'
    triggered: bool = False
    triggered_at: Optional[float] = None
    triggered_by_ip: Optional[str] = None
