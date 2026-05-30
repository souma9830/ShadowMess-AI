"""
ShadowMesh — RDP Session State
================================
Tracks per-connection state for a single attacker RDP session.
Kept separate from protocol handling so future versions can persist
sessions to Redis or replay recorded desktop streams.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RDPSession:
    """Mutable state for one attacker connection."""

    attacker_ip: str
    node_id: str
    connected_at: float = field(default_factory=time.time)

    # Captured during negotiation
    username: Optional[str] = None
    domain: Optional[str] = None
    password: Optional[str] = None          # Classic RDP only; NLA yields hash
    ntlm_hash: Optional[str] = None         # NLA/NTLM negotiate blob (hex)
    client_hostname: Optional[str] = None
    client_build: Optional[str] = None      # RDP client version string
    requested_width: int = 1024
    requested_height: int = 768
    color_depth: int = 24

    # Interaction tracking
    keystrokes: list[str] = field(default_factory=list)
    interaction_count: int = 0
    disconnected_at: Optional[float] = None

    @property
    def duration(self) -> float:
        end = self.disconnected_at or time.time()
        return round(end - self.connected_at, 3)

    def record_keystroke(self, key: str) -> None:
        self.keystrokes.append(key)
        self.interaction_count += 1

    def close(self) -> None:
        if self.disconnected_at is None:
            self.disconnected_at = time.time()
