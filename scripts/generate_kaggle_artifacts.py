"""
generate_kaggle_artifacts.py
============================
Generates all three Kaggle upload artifacts for ShadowMesh:

  1. shadowmesh_behavioral_dataset.csv
       7-feature labeled dataset (benign + 8 attack phases)
       Compatible with NSL-KDD style benchmarking.

  2. oneclass_svm_model.pkl
       Production One-Class SVM detector (+ feature scaler), trained on the
       canonical 2,000-sample benign baseline via the live AnomalyDetector.
       Evaluated out-of-sample on the dataset below.

  3. q_table.npy  +  q_table_readable.csv
       Q-learning topology optimizer after 50,000 simulated RL episodes.
       CSV version maps every (state_bin - best_action - topology_name)
       for human-readable exploration on Kaggle.

Run:
    pip install scikit-learn numpy pandas joblib
    python scripts/generate_kaggle_artifacts.py

Output: ./kaggle_artifacts/
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is importable
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

OUTPUT_DIR = PROJECT_ROOT / "kaggle_artifacts"
OUTPUT_DIR.mkdir(exist_ok=True)

print("\n" + "=" * 60)
print("  ShadowMesh — Kaggle Artifact Generator")
print("=" * 60)

# ---------------------------------------------------------------------------
# 1. DATASET — Synthetic Behavioral Anomaly Logs
# ---------------------------------------------------------------------------
print("\n[1/3] Generating behavioral dataset...")

FEATURE_NAMES = [
    'timing_delta_ms',
    'port_entropy',
    'unique_ports_5s',
    'login_rate_60s',
    'command_diversity',
    'lateral_spread',
    'action_type_encoded',
]

rng = np.random.default_rng(42)

# ── BENIGN (label=0) ───────────────────────────────────────────────────────
# NOTE: this is the EVALUATION dataset's benign portion (5,000 rows), kept
# separate from the detector's 2,000-sample TRAINING set. Uses the same
# production benign generator so the feature distribution matches the live system.
N_BENIGN = 5000

from backend.ai.anomaly_detector import generate_benign_training_data
benign = generate_benign_training_data(N_BENIGN).astype(float)

benign_df = pd.DataFrame(benign, columns=FEATURE_NAMES)
benign_df['label'] = 0
benign_df['attack_phase'] = 'benign'

# ── ATTACK PHASES (label=1) ────────────────────────────────────────────────
N_ATTACK = 500  # per phase

def attack_phase(name, timing_range, entropy_range, ports_range,
                 login_range, diversity_range, lateral_range, action_type, n=N_ATTACK):
    arr = np.column_stack([
        rng.uniform(*timing_range,   n),
        rng.uniform(*entropy_range,  n),
        rng.integers(*ports_range,   n).astype(float),
        rng.integers(*login_range,   n).astype(float),
        rng.integers(*diversity_range, n).astype(float),
        rng.integers(*lateral_range, n).astype(float),
        np.full(n, action_type, dtype=float),
    ])
    arr += rng.normal(0, 0.05, arr.shape)
    arr = np.clip(arr, 0, None)
    df = pd.DataFrame(arr, columns=FEATURE_NAMES)
    df['label'] = 1
    df['attack_phase'] = name
    return df

attack_phases = [
    # Phase 1 — Port Scan (automated, burst, high entropy, many ports)
    attack_phase('port_scan',
        timing_range=(5, 80),       entropy_range=(2.5, 4.5),
        ports_range=(15, 50),       login_range=(0, 1),
        diversity_range=(1, 3),     lateral_range=(3, 10),
        action_type=0),

    # Phase 2 — Initial Access (web exploit — medium timing, command exec)
    attack_phase('initial_access',
        timing_range=(200, 800),    entropy_range=(0.3, 1.2),
        ports_range=(1, 5),         login_range=(0, 2),
        diversity_range=(2, 4),     lateral_range=(1, 3),
        action_type=2),

    # Phase 3 — Brute Force (rapid logins, repetitive, low entropy)
    attack_phase('brute_force',
        timing_range=(10, 200),     entropy_range=(0.1, 0.5),
        ports_range=(1, 3),         login_range=(8, 30),
        diversity_range=(1, 2),     lateral_range=(1, 2),
        action_type=1),

    # Phase 4 — Credential Theft (targeted, low timing variance)
    attack_phase('credential_theft',
        timing_range=(100, 600),    entropy_range=(0.2, 0.8),
        ports_range=(1, 4),         login_range=(0, 3),
        diversity_range=(3, 6),     lateral_range=(1, 3),
        action_type=5),

    # Phase 5 — Defense Evasion (intermittent, command exec, low ports)
    attack_phase('defense_evasion',
        timing_range=(500, 3000),   entropy_range=(0.1, 0.5),
        ports_range=(1, 3),         login_range=(0, 1),
        diversity_range=(2, 5),     lateral_range=(1, 2),
        action_type=2),

    # Phase 6 — Lateral Movement (rapid, many targets, diverse actions)
    attack_phase('lateral_movement',
        timing_range=(30, 300),     entropy_range=(1.0, 3.0),
        ports_range=(5, 20),        login_range=(2, 8),
        diversity_range=(4, 7),     lateral_range=(5, 15),
        action_type=4),

    # Phase 7 — Data Exfiltration (large data access, medium timing)
    attack_phase('data_exfiltration',
        timing_range=(200, 1500),   entropy_range=(0.3, 1.5),
        ports_range=(1, 6),         login_range=(0, 2),
        diversity_range=(2, 5),     lateral_range=(1, 4),
        action_type=3),

    # Phase 8 — Impact / Ransomware (burst, all action types, high diversity)
    attack_phase('ransomware_impact',
        timing_range=(5, 100),      entropy_range=(1.5, 4.0),
        ports_range=(10, 40),       login_range=(0, 5),
        diversity_range=(5, 7),     lateral_range=(3, 12),
        action_type=2),
]

full_df = pd.concat([benign_df] + attack_phases, ignore_index=True)
full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)

# Round for clean CSV
for col in FEATURE_NAMES:
    full_df[col] = full_df[col].round(4)

dataset_path = OUTPUT_DIR / "shadowmesh_behavioral_dataset.csv"
full_df.to_csv(dataset_path, index=False)

benign_count = (full_df['label'] == 0).sum()
attack_count = (full_df['label'] == 1).sum()
print(f"    [OK] {len(full_df):,} rows — {benign_count:,} benign / {attack_count:,} attack")
print(f"    [OK] Saved: {dataset_path}")

# ---------------------------------------------------------------------------
# 2. MODEL — the production One-Class SVM detector
# ---------------------------------------------------------------------------
# CANONICAL TRAINING STORY: the detector is trained on the production benign
# baseline (TRAIN_SAMPLES, default 2,000) via the SAME AnomalyDetector the live
# backend uses — NOT on the 5,000 benign rows of the evaluation dataset. The
# 5,000/4,000 split in this file is the *evaluation* dataset, kept separate from
# the training set so reported metrics are out-of-sample.
print("\n[2/3] Training production One-Class SVM detector...")

from backend.ai.anomaly_detector import AnomalyDetector, TRAIN_SAMPLES, FEATURE_NAMES as PROD_FEATURES

detector = AnomalyDetector()
detector.train()  # fits scaler + OC-SVM on TRAIN_SAMPLES synthetic benign samples
print(f"    [OK] Trained on {TRAIN_SAMPLES} production benign samples (One-Class SVM)")

# Evaluate on the released dataset (out-of-sample w.r.t. the training set)
X_eval_benign = full_df[full_df['label'] == 0][FEATURE_NAMES].values.astype(np.float32)
X_attack = full_df[full_df['label'] == 1][FEATURE_NAMES].values.astype(np.float32)

def _predict(X):
    return detector.model.predict(detector.scaler.transform(X))

benign_correct = (_predict(X_eval_benign) == 1).mean()
attack_detected = (_predict(X_attack) == -1).mean()

model_path = OUTPUT_DIR / "oneclass_svm_model.pkl"
joblib.dump({'model': detector.model, 'scaler': detector.scaler}, model_path)

print(f"    [OK] Benign correctly classified : {benign_correct:.1%}")
print(f"    [OK] Attack actions detected     : {attack_detected:.1%}")
print(f"    [OK] Saved: {model_path}")

# ---------------------------------------------------------------------------
# 3. Q-TABLE — 50,000 simulated RL training episodes
# ---------------------------------------------------------------------------
print("\n[3/3] Training Q-learning topology optimizer (50,000 episodes)...")

# Inline the RL code so this script has no import dependency on the backend
TOTAL_STATES = 2880
NUM_ACTIONS  = 8

TOPOLOGY_CONFIGS = {
    0: "hub-and-spoke",
    1: "mesh",
    2: "layered",
    3: "star",
    4: "random",
    5: "financial-heavy",
    6: "dev-heavy",
    7: "admin-heavy",
}

BIN_EDGES = {
    "actions":      [0, 5, 15, 30, 50],
    "generation":   [0, 3, 7],
    "duration":     [0, 5, 20, 60],
    "nodes_hit":    [0, 3, 8, 15],
    "cred_attempts":[0, 1, 5],
}

SKILL_MAP = {0: "script_kiddie", 1: "intermediate", 2: "advanced", 3: "nation_state_apt"}

def digitize(value, edges):
    for i, e in enumerate(edges):
        if value <= e:
            return i
    return len(edges)

def state_index(skill, actions, generation, duration, nodes_hit, cred_attempts):
    s0 = min(skill, 3)
    s1 = digitize(actions,      BIN_EDGES["actions"])
    s2 = digitize(generation,   BIN_EDGES["generation"])
    s3 = digitize(duration,     BIN_EDGES["duration"])
    s4 = digitize(nodes_hit,    BIN_EDGES["nodes_hit"])
    s5 = digitize(cred_attempts,BIN_EDGES["cred_attempts"])
    idx = s0*(5*3*4*4*3) + s1*(3*4*4*3) + s2*(4*4*3) + s3*(4*3) + s4*3 + s5
    return min(idx, TOTAL_STATES - 1)

def simulate_episode(rng_ep, skill):
    """
    Simulate one attacker session given a skill level.
    Returns (state, action, reward, next_state).
    """
    actions_taken   = int(rng_ep.integers(1, 60))
    generation      = int(rng_ep.integers(0, 10))
    duration_min    = float(rng_ep.uniform(0, 90))
    nodes_hit       = int(rng_ep.integers(0, 20))
    cred_attempts   = int(rng_ep.integers(0, 10))

    state = state_index(skill, actions_taken, generation, duration_min, nodes_hit, cred_attempts)

    # Reward depends on engagement quality — more skilled attackers engage more
    unique_actions = rng_ep.integers(1, max(2, actions_taken))
    unique_mitre   = rng_ep.integers(0, max(2, unique_actions // 2))
    high_value     = rng_ep.integers(0, max(2, cred_attempts + 1))

    reward  = float(unique_actions) * 1.0
    reward += float(unique_mitre)   * 2.0
    reward += float(high_value)     * 3.0
    if duration_min * 60 < 60:
        reward -= 1.0
    reward += (duration_min) * 0.5

    # Nation-state and advanced attackers yield more reward when engaged longer
    reward *= (1.0 + skill * 0.3)

    # Next state after engagement (simplified: more actions, higher generation)
    next_actions = min(actions_taken + int(rng_ep.integers(1, 10)), 60)
    next_gen     = min(generation + int(rng_ep.integers(0, 2)), 10)
    next_state   = state_index(skill, next_actions, next_gen, duration_min, nodes_hit, cred_attempts)

    return state, next_state, reward

# Q-learning hyperparameters
lr           = 0.1
gamma        = 0.9
epsilon      = 0.5
epsilon_min  = 0.05
epsilon_decay= 0.9998
N_EPISODES   = 50_000

q_table  = np.zeros((TOTAL_STATES, NUM_ACTIONS), dtype=np.float64)
rng_rl   = np.random.default_rng(42)
rewards_log = []

for ep in range(N_EPISODES):
    skill = int(rng_rl.integers(0, 4))
    state, next_state, reward = simulate_episode(rng_rl, skill)

    if rng_rl.random() < epsilon:
        action = int(rng_rl.integers(0, NUM_ACTIONS))
    else:
        action = int(np.argmax(q_table[state]))

    # Q-update
    current_q  = q_table[state, action]
    max_next_q = np.max(q_table[next_state])
    q_table[state, action] = current_q + lr * (reward + gamma * max_next_q - current_q)

    epsilon = max(epsilon_min, epsilon * epsilon_decay)
    rewards_log.append(reward)

    if (ep + 1) % 10_000 == 0:
        print(f"    Episode {ep+1:,} / {N_EPISODES:,} -- eps={epsilon:.4f}  avg_reward={np.mean(rewards_log[-1000:]):.2f}")

# Save .npy
qtable_path = OUTPUT_DIR / "q_table.npy"
np.save(qtable_path, q_table)
print(f"    [OK] Saved: {qtable_path}")

# Save human-readable CSV: one row per state with best action and topology name
print("    Building readable Q-table CSV...")
rows = []
for s in range(TOTAL_STATES):
    q_row    = q_table[s]
    best_act = int(np.argmax(q_row))
    rows.append({
        "state_bin":        s,
        "best_action":      best_act,
        "topology_name":    TOPOLOGY_CONFIGS[best_act],
        "q_value_best":     round(float(q_row[best_act]), 4),
        "q_spread":         round(float(q_row.max() - q_row.min()), 4),
        "non_zero_actions": int(np.count_nonzero(q_row)),
        **{f"q_action_{i}": round(float(q_row[i]), 4) for i in range(NUM_ACTIONS)},
    })

qtable_csv_path = OUTPUT_DIR / "q_table_readable.csv"
pd.DataFrame(rows).to_csv(qtable_csv_path, index=False)
print(f"    [OK] Saved: {qtable_csv_path}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("  All artifacts saved to: kaggle_artifacts/")
print("=" * 60)
print(f"  shadowmesh_behavioral_dataset.csv  — {len(full_df):,} rows, 7 features + label")
print(f"  oneclass_svm_model.pkl             — benign accuracy {benign_correct:.1%}, attack recall {attack_detected:.1%}")
print(f"  q_table.npy                        — {TOTAL_STATES} states × {NUM_ACTIONS} actions")
print(f"  q_table_readable.csv               — {TOTAL_STATES} rows, human-readable topology preferences")
print("\n  Upload to Kaggle:")
print("  1. Go to kaggle.com - Datasets - New Dataset")
print("  2. Upload the 4 files from kaggle_artifacts/")
print("  3. Title: 'ShadowMesh — Cyber Deception Behavioral Dataset'")
print("=" * 60 + "\n")
