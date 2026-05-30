import uuid
import time
import random
from typing import Dict, List, Optional
from backend.models import CanaryToken

_TOKEN_TYPES = [
    {
        "type": "document",
        "label": "Q3_Financial_Report.pdf",
        "description": "embedded in fake file server",
    },
    {
        "type": "url",
        "label": "Internal Wiki — Credentials Page",
        "description": "linked in fake HTTP response",
    },
]


class CanaryManager:
    def __init__(self):
        self._tokens: Dict[str, CanaryToken] = {}

    def generate_for_node(self, node_id: str, count: int = 2) -> List[CanaryToken]:
        selected = random.sample(_TOKEN_TYPES, k=min(count, len(_TOKEN_TYPES)))
        result = []
        for t in selected:
            token_id = uuid.uuid4().hex
            token = CanaryToken(
                token_id=token_id,
                node_id=node_id,
                token_url=f"/api/canary/{token_id}",
                token_type=t["type"],
                label=t["label"],
            )
            self._tokens[token_id] = token
            result.append(token)
        return result

    def get_token(self, token_id: str) -> Optional[CanaryToken]:
        return self._tokens.get(token_id)

    def mark_triggered(self, token_id: str, triggered_by_ip: str) -> Optional[CanaryToken]:
        token = self._tokens.get(token_id)
        if token and not token.triggered:
            token.triggered = True
            token.triggered_at = time.time()
            token.triggered_by_ip = triggered_by_ip
        return token

    def clear_for_node(self, node_id: str) -> None:
        self._tokens = {tid: t for tid, t in self._tokens.items() if t.node_id != node_id}

    def get_all_for_node(self, node_id: str) -> List[CanaryToken]:
        return [t for t in self._tokens.values() if t.node_id == node_id]


canary_manager = CanaryManager()
