import uuid
import time
import random
from typing import Dict, List, Optional
from backend.models import FakeCredential

CREDENTIAL_TEMPLATES = {
    "env_file": {
        "filename": ".env",
        "content": "DB_HOST=172.20.0.12\nDB_PORT=3306\nDB_USER=prod_admin\nDB_PASSWORD=Sup3rS3cur3!2024\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=EXAMPLEKEY\nJWT_SECRET=hs256-prod-secret-do-not-share\n"
    },
    "aws_key": {
        "filename": "credentials.csv",
        "content": "User Name,Access key ID,Secret access key\nprod_deploy,AKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    },
    "ssh_key": {
        "filename": "id_rsa",
        "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAy8DbvCG... (FAKE KEY) ...1n2m3o4p5q6r7s8t9u0\n-----END RSA PRIVATE KEY-----\n"
    },
    "db_password": {
        "filename": "db_credentials.txt",
        "content": "Production Database Credentials:\nHost: db.internal.shadowmesh.local\nPort: 5432\nUser: postgres_admin\nPass: psql_prod_P@ssw0rd2025\n"
    }
}

class CredentialManager:
    def __init__(self):
        self._credentials: Dict[str, FakeCredential] = {}

    def generate_for_node(self, node_id: str) -> List[FakeCredential]:
        # Randomly choose 2 credential types
        selected_types = random.sample(list(CREDENTIAL_TEMPLATES.keys()), k=min(2, len(CREDENTIAL_TEMPLATES)))
        
        generated_creds = []
        for cred_type in selected_types:
            template = CREDENTIAL_TEMPLATES[cred_type]
            cred_id = str(uuid.uuid4())
            cred = FakeCredential(
                cred_id=cred_id,
                node_id=node_id,
                cred_type=cred_type,
                filename=template["filename"],
                content=template["content"]
            )
            self._credentials[cred_id] = cred
            generated_creds.append(cred)
            
        return generated_creds

    def get_credential(self, cred_id: str) -> Optional[FakeCredential]:
        return self._credentials.get(cred_id)

    def mark_accessed(self, cred_id: str) -> Optional[FakeCredential]:
        cred = self._credentials.get(cred_id)
        if cred:
            cred.accessed = True
            cred.accessed_at = time.time()
        return cred

    def get_all_for_node(self, node_id: str) -> List[FakeCredential]:
        return [cred for cred in self._credentials.values() if cred.node_id == node_id]

# Singleton
cred_manager = CredentialManager()
