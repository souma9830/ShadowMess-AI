import os
import re
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from typing import Dict, List
from backend.models import AttackerAction

# Optional real benign baseline for deployment calibration (see _load_real_baseline).
BENIGN_BASELINE_PATH = Path(__file__).resolve().parents[2] / "kaggle_artifacts" / "real_benign_dataset.csv"

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
    Generate synthetic benign feature vectors that match the distribution the live
    featurizer actually produces for legitimate traffic.

    Crucially this includes realistic edge cases the earlier generator omitted and
    which caused train/serve skew: first-contact actions (timing_delta ~ 0), and
    non-network actions such as command/data access that touch zero ports
    (port_entropy = 0, unique_ports_5s = 0). Modeling benign traffic as a mixture
    over action types — rather than forcing every sample into a single narrow band —
    keeps legitimate first actions and shell commands inside the normal manifold.

    Uses a fixed seed so training is fully reproducible across restarts.
    """
    rng = np.random.default_rng(42)

    # Benign action-type mixture (matches ACTION_TYPE_MAP encodings); legitimate
    # traffic is mostly commands/data access, some logins, occasional service checks.
    action_encoded = rng.choice(
        [2, 2, 2, 3, 3, 1, 0, 4],          # command, data, login, (rare) scan/lateral
        size=n_samples,
    ).astype(float)

    # timing_delta_ms — legitimate gaps span from first-contact (~0) up to minutes;
    # include a sizeable fraction near zero so first actions are treated as normal.
    timing_delta = np.where(
        rng.random(n_samples) < 0.15,
        rng.uniform(0, 200, n_samples),            # first-contact / quick follow-up
        rng.uniform(200, 8000, n_samples),         # human/scheduled pace
    )

    # Port-derived features depend on whether the action touches the network.
    # Command/data actions (encodings 2,3) legitimately touch no ports.
    touches_ports = np.isin(action_encoded, [0, 1, 4])
    port_entropy = np.where(
        touches_ports, rng.uniform(0.0, 0.5, n_samples), 0.0
    )
    unique_ports = np.where(
        touches_ports,
        rng.integers(1, 4, n_samples).astype(float),
        0.0,
    )

    login_rate    = rng.integers(0, 3, n_samples).astype(float)
    cmd_diversity = rng.integers(1, 6, n_samples).astype(float)
    lateral       = rng.integers(1, 3, n_samples).astype(float)

    X = np.column_stack([timing_delta, port_entropy, unique_ports,
                         login_rate, cmd_diversity, lateral, action_encoded])

    # Small Gaussian noise to avoid overfitting exact grid values.
    X += rng.normal(0, 0.05, X.shape)
    X = np.clip(X, 0, None)
    return X.astype(np.float32)


# Number of benign samples used to fit the detector. Imported from the central
# config so the live backend and the dataset/export scripts share one constant.
# This is the TRAINING set size — distinct from the evaluation datasets in
# kaggle_artifacts/ (see configs/constants.py for the full note).
try:
    from configs.constants import (
        ANOMALY_TRAIN_SAMPLES as TRAIN_SAMPLES,
        ANOMALY_NU,
        ANOMALY_EXPLAIN_TOP_K,
    )
except Exception:  # pragma: no cover - fallback if config import path differs
    TRAIN_SAMPLES = 2000
    ANOMALY_NU = 0.05
    ANOMALY_EXPLAIN_TOP_K = 3

# Bumped whenever the detector algorithm, features, or training distribution
# change, so persisted/loaded models and emitted scores carry provenance.
MODEL_VERSION = "2.0-ocsvm"


class AnomalyDetector:
    """
    One-Class SVM novelty detector over the 7-feature behavioral vector.

    One-Class SVM was selected over IsolationForest, Local Outlier Factor, and
    Elliptic Envelope after a 5-fold cross-validated benchmark on the labeled
    behavioral dataset (see scripts/benchmark_detectors.py): it reaches
    ROC-AUC ~0.92 / F1 ~0.89 versus IsolationForest's ROC-AUC ~0.88 / F1 ~0.79,
    is statistically tied with LOF, and — unlike LOF — yields a compact
    support-vector model suited to real-time, single-action scoring without
    retaining the training set in memory.
    """

    def __init__(self):
        # nu ≈ expected outlier fraction (~5%); RBF kernel with scale gamma.
        self.model = OneClassSVM(nu=ANOMALY_NU, kernel='rbf', gamma='scale')
        self.scaler = StandardScaler()
        self._df_scale = 1.0   # spread of benign decision_function, for [0,1] mapping
        self._trained = False
        self._last_action_time: Dict[str, float] = {}  # ip → last action timestamp
        self.metadata: Dict = {}  # provenance: version, train size, fit time

    def _load_real_baseline(self) -> np.ndarray:
        """
        Load a captured REAL benign baseline if one is available, for deployment
        calibration. Real benign traffic (e.g. human-pace inter-action timing that
        extends to tens of seconds) is not well covered by the synthetic generator
        alone; measuring against real benign showed a synthetic-only model raises
        false positives on legitimate traffic. Operators can drop a baseline CSV
        (the seven feature columns) at BENIGN_BASELINE_PATH — produced by
        scripts/capture_benign.py against their own environment — and it is blended
        into training. Returns an (n, 7) array or an empty array if unavailable.
        """
        path = os.environ.get("SHADOWMESH_BENIGN_BASELINE", str(BENIGN_BASELINE_PATH))
        try:
            if Path(path).exists():
                df = pd.read_csv(path)
                if set(FEATURE_NAMES).issubset(df.columns):
                    return df[FEATURE_NAMES].values.astype(np.float32)
        except Exception as e:  # pragma: no cover
            print(f"[warn] could not load real benign baseline: {e}")
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)

    def train(self):
        """
        Fit the scaler and One-Class SVM. Trains on synthetic benign samples,
        blended with a captured REAL benign baseline when available — real
        calibration sharply reduces false positives on genuine traffic
        (measured: synthetic-only mislabels real benign; blended ~3-4% FPR).
        """
        synthetic = generate_benign_training_data(TRAIN_SAMPLES)
        real = self._load_real_baseline()
        if len(real):
            X_train = np.vstack([real, synthetic])
            source = f"{len(real)} real + {len(synthetic)} synthetic"
        else:
            X_train = synthetic
            source = f"{len(synthetic)} synthetic"

        Xs = self.scaler.fit_transform(X_train)
        self.model.fit(Xs)
        # Calibrate the threat-score mapping from the benign decision-function spread
        df = self.model.decision_function(Xs)
        self._df_scale = float(np.std(df)) or 1.0
        self._trained = True
        self.metadata = {
            'model_version': MODEL_VERSION,
            'algorithm': 'OneClassSVM(rbf)',
            'nu': ANOMALY_NU,
            'train_samples': int(len(X_train)),
            'real_baseline_samples': int(len(real)),
            'n_features': len(FEATURE_NAMES),
        }
        print(f'[OK] One-Class SVM ({MODEL_VERSION}) trained on {source} benign samples')

    def _explain(self, features: np.ndarray) -> List[dict]:
        """
        Explain a score by the features that deviate most from the benign baseline.

        Uses the scaler's stored benign mean/scale to compute a per-feature
        standardized deviation (z-score). SOC analysts get "which behaviors made
        this anomalous" instead of a bare number. Returns the top-K by |z|.
        """
        if not self._trained:
            return []
        mean = self.scaler.mean_
        scale = self.scaler.scale_
        z = (features[0] - mean) / scale
        order = np.argsort(-np.abs(z))[:ANOMALY_EXPLAIN_TOP_K]
        return [
            {
                'feature': FEATURE_NAMES[i],
                'value': round(float(features[0][i]), 3),
                'baseline_mean': round(float(mean[i]), 3),
                'deviation_sigma': round(float(z[i]), 2),
            }
            for i in order
        ]

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
        Xs = self.scaler.transform(features)
        raw_score  = self.model.decision_function(Xs)[0]  # >0 → inlier, <0 → outlier
        prediction = self.model.predict(Xs)[0]            # -1 = anomaly, 1 = normal

        # Map the signed distance to [0, 1] with a logistic squash calibrated on the
        # benign spread: 0.5 at the boundary, →1 deep in anomaly territory.
        threat_score = float(1.0 / (1.0 + np.exp(raw_score / self._df_scale)))

        return {
            'threat_score': round(threat_score, 3),
            'is_anomalous': bool(prediction == -1),
            'features': dict(zip(FEATURE_NAMES, features[0].tolist())),
            'explanation': self._explain(features),
            'model_version': MODEL_VERSION,
        }


# Module-level singleton — trained once at startup via lifespan
anomaly_detector = AnomalyDetector()
