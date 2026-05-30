"""
ShadowMesh — Task 12.3: Reinforcement Learning Topology Optimizer
=================================================================
Q-learning agent that learns which network topology configurations maximize
attacker engagement and intelligence collection over time.

Architecture:
  RLTopologyOptimizer (singleton)
  ├── State: 6-dimensional vector discretized into 2880 bins
  ├── Actions: 8 topology configurations
  ├── Q-table: numpy array (2880 × 8)
  ├── Reward: engagement + MITRE tags + credential access + dwell time
  └── Persistence: disk (.npy) + Redis (JSON)

  TopologyEnv (gymnasium.Env)
  └── For simulation/testing — wraps the optimizer for standard RL interfaces
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
from typing import Any, Dict, List, Optional

import numpy as np

log = logging.getLogger("rl_topology")

Q_TABLE_PATH = pathlib.Path(__file__).parent / "q_table.npy"

_SKILL_MAP = {
    "script kiddie": 0,
    "intermediate": 1,
    "advanced": 2,
    "nation-state apt": 3,
    "unknown": 0,
}

_BINS = {
    "skill": 4,
    "actions": 5,
    "generation": 3,
    "duration": 4,
    "nodes_hit": 4,
    "cred_attempts": 3,
}

_BIN_EDGES = {
    "actions": [0, 5, 15, 30, 50],
    "generation": [0, 3, 7],
    "duration": [0, 5, 20, 60],
    "nodes_hit": [0, 3, 8, 15],
    "cred_attempts": [0, 1, 5],
}

TOTAL_STATES = 4 * 5 * 3 * 4 * 4 * 3  # 2880
NUM_ACTIONS = 8

TOPOLOGY_CONFIGS = {
    0: {
        "name": "hub-and-spoke",
        "weights": [0.10, 0.10, 0.40, 0.10, 0.10, 0.10, 0.10],
        "graph_type": "star",
    },
    1: {
        "name": "mesh",
        "weights": [0.15, 0.15, 0.15, 0.15, 0.15, 0.15, 0.10],
        "graph_type": "dense",
    },
    2: {
        "name": "layered",
        "weights": [0.25, 0.15, 0.15, 0.10, 0.20, 0.05, 0.10],
        "graph_type": "barabasi",
    },
    3: {
        "name": "star",
        "weights": [0.10, 0.30, 0.10, 0.20, 0.10, 0.10, 0.10],
        "graph_type": "star",
    },
    4: {
        "name": "random",
        "weights": [0.20, 0.15, 0.10, 0.15, 0.15, 0.10, 0.15],
        "graph_type": "barabasi",
    },
    5: {
        "name": "financial-heavy",
        "weights": [0.10, 0.30, 0.05, 0.10, 0.30, 0.05, 0.10],
        "graph_type": "barabasi",
    },
    6: {
        "name": "dev-heavy",
        "weights": [0.10, 0.10, 0.05, 0.25, 0.30, 0.05, 0.15],
        "graph_type": "barabasi",
    },
    7: {
        "name": "admin-heavy",
        "weights": [0.10, 0.10, 0.30, 0.15, 0.10, 0.05, 0.20],
        "graph_type": "barabasi",
    },
}


def _digitize(value: float, edges: List[float]) -> int:
    for i, edge in enumerate(edges):
        if value <= edge:
            return i
    return len(edges)


def discretize_state(
    skill_level: int,
    actions_taken: int,
    generation: int,
    duration_minutes: float,
    unique_nodes_hit: int,
    credential_attempts: int,
) -> int:
    s0 = min(skill_level, 3)
    s1 = _digitize(actions_taken, _BIN_EDGES["actions"])
    s2 = _digitize(generation, _BIN_EDGES["generation"])
    s3 = _digitize(duration_minutes, _BIN_EDGES["duration"])
    s4 = _digitize(unique_nodes_hit, _BIN_EDGES["nodes_hit"])
    s5 = _digitize(credential_attempts, _BIN_EDGES["cred_attempts"])

    index = (
        s0 * (5 * 3 * 4 * 4 * 3)
        + s1 * (3 * 4 * 4 * 3)
        + s2 * (4 * 4 * 3)
        + s3 * (4 * 3)
        + s4 * 3
        + s5
    )
    return min(index, TOTAL_STATES - 1)


def compute_reward(actions: List[Any], session_duration_seconds: float) -> float:
    if not actions:
        return 0.0

    unique_actions = len(set(
        (a.action_type, a.target_node_id) if hasattr(a, "action_type") else (str(a), "")
        for a in actions
    ))

    mitre_tags = sum(
        1 for a in actions
        if hasattr(a, "mitre_technique_id") and a.mitre_technique_id
    )
    unique_mitre = len(set(
        a.mitre_technique_id for a in actions
        if hasattr(a, "mitre_technique_id") and a.mitre_technique_id
    ))

    high_value = sum(
        1 for a in actions
        if hasattr(a, "action_type") and a.action_type in ("credential_theft", "canary_trigger")
    )

    reward = 0.0
    reward += unique_actions * 1.0
    reward += unique_mitre * 2.0
    reward += high_value * 3.0

    if session_duration_seconds < 60:
        reward -= 1.0

    reward += (session_duration_seconds / 60.0) * 0.5

    return reward


class RLTopologyOptimizer:

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.9,
        epsilon: float = 0.3,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.05,
    ):
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.q_table = np.zeros((TOTAL_STATES, NUM_ACTIONS), dtype=np.float64)
        self._sessions: Dict[str, Dict] = {}
        self._total_updates = 0
        self._rng = np.random.default_rng(42)

    def choose_topology(self, profile: Any = None, session_stats: Optional[Dict] = None) -> int:
        if profile is None:
            return 4

        if isinstance(profile, dict):
            skill = profile.get("skill_level", "Unknown")
        else:
            skill = getattr(profile, "skill_level", "Unknown")

        stats = session_stats or {}
        state = discretize_state(
            skill_level=_SKILL_MAP.get(skill.lower(), 0),
            actions_taken=stats.get("actions_taken", 0),
            generation=stats.get("generation", 0),
            duration_minutes=stats.get("duration_minutes", 0),
            unique_nodes_hit=stats.get("unique_nodes_hit", 0),
            credential_attempts=stats.get("credential_attempts", 0),
        )

        if self._rng.random() < self.epsilon:
            action = int(self._rng.integers(0, NUM_ACTIONS))
        else:
            action = int(np.argmax(self.q_table[state]))

        return action

    def get_topology_config(self, action: int) -> Dict:
        return TOPOLOGY_CONFIGS.get(action, TOPOLOGY_CONFIGS[4])

    def start_session(self, attacker_ip: str, state: int, action: int) -> None:
        self._sessions[attacker_ip] = {
            "state": state,
            "action": action,
        }

    def end_session(self, attacker_ip: str, actions: List[Any], session_duration: float) -> Optional[float]:
        session = self._sessions.pop(attacker_ip, None)
        if session is None:
            return None

        reward = compute_reward(actions, session_duration)
        state = session["state"]
        action = session["action"]

        self.update(state, action, reward, state)

        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

        return reward

    def update(self, state: int, action: int, reward: float, next_state: int) -> None:
        current_q = self.q_table[state, action]
        max_next_q = np.max(self.q_table[next_state])
        new_q = current_q + self.lr * (reward + self.gamma * max_next_q - current_q)
        self.q_table[state, action] = new_q
        self._total_updates += 1

    def save(self, path: Optional[str] = None) -> None:
        save_path = path or str(Q_TABLE_PATH)
        try:
            np.save(save_path, self.q_table)
            log.info("[rl] Q-table saved to %s (%d updates)", save_path, self._total_updates)
        except Exception as e:
            log.warning("[rl] Failed to save Q-table: %s", e)

    def load(self, path: Optional[str] = None) -> bool:
        load_path = path or str(Q_TABLE_PATH)
        try:
            if os.path.exists(load_path):
                self.q_table = np.load(load_path)
                log.info("[rl] Q-table loaded from %s", load_path)
                return True
        except Exception as e:
            log.warning("[rl] Failed to load Q-table: %s", e)
        return False

    def to_json(self) -> str:
        return json.dumps(self.q_table.tolist())

    def from_json(self, data: str) -> None:
        self.q_table = np.array(json.loads(data), dtype=np.float64)

    def get_stats(self) -> Dict:
        return {
            "total_updates": self._total_updates,
            "epsilon": round(self.epsilon, 4),
            "active_sessions": len(self._sessions),
            "non_zero_states": int(np.count_nonzero(self.q_table.sum(axis=1))),
            "q_table_shape": list(self.q_table.shape),
        }


rl_optimizer = RLTopologyOptimizer()


# ---------------------------------------------------------------------------
# Gymnasium Environment (for simulation and testing)
# ---------------------------------------------------------------------------

try:
    import gymnasium as gym

    class TopologyEnv(gym.Env):
        metadata = {"render_modes": []}

        def __init__(self):
            super().__init__()
            self.observation_space = gym.spaces.Box(
                low=0, high=200, shape=(6,), dtype=np.float32
            )
            self.action_space = gym.spaces.Discrete(NUM_ACTIONS)
            self._state = np.zeros(6, dtype=np.float32)

        def reset(self, seed=None, options=None):
            super().reset(seed=seed)
            self._state = np.zeros(6, dtype=np.float32)
            return self._state.copy(), {}

        def step(self, action):
            reward = 0.0
            terminated = True
            truncated = False
            info = {"action": action, "config": TOPOLOGY_CONFIGS[action]["name"]}
            return self._state.copy(), reward, terminated, truncated, info

except ImportError:
    TopologyEnv = None
