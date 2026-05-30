import re
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, List
from backend.models import AttackerAction

FEATURE_NAMES = [
    'timing_delta_ms',      # ms since last action — low = automated/bursty
    'port_entropy',         # Shannon entropy of ports in detail string — high = broad sweep
    'unique_ports_5s',      # unique ports hit across all actions in last 5 seconds
    'login_rate_60s',       # login_attempt count in last 60 seconds
    'command_diversity',    # number of distinct action_types seen so far
    'lateral_spread',       # unique target node IDs in last 60 seconds
    'action_type_encoded',  # port_scan=0, login=1, command=2, data=3, lateral=4, cred=5, canary=6
]

ACTION_TYPE_MAP = {
    'port_scan': 0, 'login_attempt': 1, 'command_exec': 2,
    'data_access': 3, 'lateral_move': 4, 'credential_theft': 5, 'canary_trigger': 6
}


def generate_benign_training_data(n_samples: int = 2000) -> np.ndarray:
    """
    Generates synthetic normal network traffic feature vectors.
    Uses a fixed seed so training is fully reproducible across restarts.
    """
    rng = np.random.default_rng(42)

    timing_delta   = rng.uniform(200, 5000, n_samples)          # human/scheduled — not bursty
    port_entropy   = rng.uniform(0.1, 0.4, n_samples)           # low — known services only
    unique_ports   = rng.integers(1, 4, n_samples).astype(float)
    login_rate     = rng.integers(0, 3, n_samples).astype(float)
    cmd_diversity  = rng.integers(1, 5, n_samples).astype(float)
    lateral        = rng.integers(1, 3, n_samples).astype(float)
    # Biased toward command_exec(2) and data_access(3) — typical legitimate traffic
    action_encoded = rng.choice([2, 2, 3, 3, 0, 1, 4], size=n_samples).astype(float)

    X = np.column_stack([timing_delta, port_entropy, unique_ports,
                         login_rate, cmd_diversity, lateral, action_encoded])

    # Add small Gaussian noise to prevent overfitting to exact grid values
    X += rng.normal(0, 0.05, X.shape)
    return X.astype(np.float32)


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,   # expect ~5% of traffic to be anomalous
            random_state=42,
            n_jobs=-1             # use all available CPUs for training
        )
        self._trained = False
        self._last_action_time: Dict[str, float] = {}  # ip → last action timestamp

    def train(self):
        """Fit the model on synthetic benign data. Runs in ~0.3s."""
        X_train = generate_benign_training_data(2000)
        self.model.fit(X_train)
        self._trained = True
        print('[OK] IsolationForest trained on 2000 synthetic benign samples')

    def featurize(self, action: AttackerAction, history: List[AttackerAction]) -> np.ndarray:
        """Extract the 7-feature vector for a single attacker action."""
        ip = action.attacker_ip
        now = action.timestamp

        # timing_delta_ms — gap since last action from this IP
        last_time = self._last_action_time.get(ip, now)
        timing_delta = min((now - last_time) * 1000, 30000)
        self._last_action_time[ip] = now

        # port_entropy — Shannon entropy of port numbers found in detail string
        port_nums = [
            int(p) for p in re.findall(r'\b\d{2,5}\b', action.detail)
            if int(p) < 65536
        ]
        if port_nums:
            counts = np.bincount(port_nums, minlength=65536)
            counts = counts[counts > 0].astype(float)
            p = counts / counts.sum()
            port_entropy = float(-np.sum(p * np.log2(p + 1e-9)))
        else:
            port_entropy = 0.0

        # unique_ports_5s — distinct ports mentioned across all recent actions
        recent_5s = [a for a in history if now - a.timestamp < 5]
        unique_ports_5s = len({
            p for a in recent_5s
            for p in re.findall(r'\b\d{2,5}\b', a.detail)
            if int(p) < 65536
        })

        # login_rate_60s
        login_rate = sum(
            1 for a in history
            if now - a.timestamp < 60 and a.action_type == 'login_attempt'
        )

        # command_diversity — distinct action types seen across all history
        command_diversity = len({a.action_type for a in history})

        # lateral_spread — distinct target nodes in last 60s
        lateral_spread = len({
            a.target_node_id for a in history
            if now - a.timestamp < 60
        })

        action_encoded = ACTION_TYPE_MAP.get(action.action_type, 2)

        return np.array([[
            timing_delta, port_entropy, unique_ports_5s,
            login_rate, command_diversity, lateral_spread, action_encoded
        ]], dtype=np.float32)

    def score(self, action: AttackerAction, history: List[AttackerAction]) -> dict:
        """
        Score an action against the trained benign baseline.
        Returns threat_score ∈ [0, 1] (higher = more anomalous) and is_anomalous flag.
        """
        if not self._trained:
            return {'threat_score': 0.5, 'is_anomalous': False, 'confidence': 0.0}

        features = self.featurize(action, history)
        raw_score  = self.model.decision_function(features)[0]  # negative → more anomalous
        prediction = self.model.predict(features)[0]            # -1 = anomaly, 1 = normal

        # Shift and clip raw score to [0, 1] — higher means more anomalous
        threat_score = float(np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0))

        return {
            'threat_score': round(threat_score, 3),
            'is_anomalous': bool(prediction == -1),
            'features': dict(zip(FEATURE_NAMES, features[0].tolist()))
        }


# Module-level singleton — trained once at startup via lifespan
anomaly_detector = AnomalyDetector()
