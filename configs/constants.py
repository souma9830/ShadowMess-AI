"""
configs/constants.py
=====================
Single source of truth for all tunable parameters across the ShadowMesh
backend.  Previously these were scattered as magic numbers in several files;
centralising them makes them self-documenting and easy to tune without
reading source code.

Fix #14 — Magic Numbers Everywhere
"""

# ---------------------------------------------------------------------------
# Detection thresholds (backend/detection/scanner.py)
# ---------------------------------------------------------------------------

# Number of unique destination ports from one source IP within SCAN_WINDOW_SECONDS
# that constitute a port scan.  5 is a conservative threshold — a normal host
# rarely probes more than 4 services in 10 seconds.
SCAN_THRESHOLD_PORTS: int = 5

# Number of unique destination IPs from one source IP within SCAN_WINDOW_SECONDS
# that constitutes lateral movement.  3 unique targets is enough signal.
LATERAL_THRESHOLD: int = 3

# Rolling time window (seconds) over which port/target hits are counted.
SCAN_WINDOW_SECONDS: int = 10

# ---------------------------------------------------------------------------
# Profiling pipeline (backend/api/routes.py)
# ---------------------------------------------------------------------------

# Run Groq/local AI profiling every N actions per IP.  Profiling is expensive
# (LLM call), so we rate-limit it.  Every 3 actions is a good balance between
# responsiveness and API cost.
PROFILING_EVERY_N_ACTIONS: int = 3

# ---------------------------------------------------------------------------
# Lure generator (backend/ai/lure_generator.py)
# ---------------------------------------------------------------------------

# Maximum number of lure containers of the same node_type allowed in the
# active subnet at one time.  2 prevents clutter while still allowing a
# primary + backup for high-value lure types.
MAX_LURE_NODES_PER_TYPE: int = 2

# ---------------------------------------------------------------------------
# Memory management (backend/api/routes.py)
# ---------------------------------------------------------------------------

# Hard cap on in-memory attacker actions per source IP.  Prevents unbounded
# growth when a single IP fires thousands of actions (e.g. automated scanner).
ACTION_LIST_MAX: int = 1000

# After trimming, keep the most recent N actions per IP so profiling still has
# a meaningful recent-history window.
ACTION_LIST_TRIM: int = 500

# ---------------------------------------------------------------------------
# Anomaly detector (backend/ai/anomaly_detector.py)
# ---------------------------------------------------------------------------

# Number of synthetic benign samples the One-Class SVM is trained on at startup.
# This is the CANONICAL training-set size. Note it is distinct from the
# *evaluation* datasets shipped in kaggle_artifacts/ (5,000-benign behavioral
# dataset and 3,000-benign real-attack dataset) — those are held-out test data,
# not training data.
ANOMALY_TRAIN_SAMPLES: int = 2000

# One-Class SVM nu — upper bound on the fraction of training points treated as
# outliers / lower bound on support-vector fraction. ~0.05 ≈ expect 5% noise.
ANOMALY_NU: float = 0.05

# threat_score (0..1) at/above which an action is escalated to a CRITICAL alert.
# Separate from the model's own inlier/outlier boundary so SOC teams can tune
# alert volume without retraining.
ANOMALY_ALERT_THRESHOLD: float = 0.75

# Number of top contributing features to include in a score explanation.
ANOMALY_EXPLAIN_TOP_K: int = 3

# ---------------------------------------------------------------------------
# Redis TTLs (backend/database/redis_client.py)
# ---------------------------------------------------------------------------

# How long to keep attacker session data in Redis (seconds).
# 24 hours is enough to survive an overnight incident investigation.
TTL_SESSION_SECONDS: int = 86_400  # 24 h
