# Task 12.3 — Reinforcement Learning Topology Optimizer

## Architecture

```
RLTopologyOptimizer (singleton: rl_optimizer)
├── State Space: 6 dimensions → 2880 discretized bins
│   ├── skill_level (4 bins: Script Kiddie/Intermediate/Advanced/APT)
│   ├── actions_taken (5 bins: 0/5/15/30/50+)
│   ├── topology_generation (3 bins: 0/3/7+)
│   ├── session_duration_minutes (4 bins: 0/5/20/60+)
│   ├── unique_nodes_hit (4 bins: 0/3/8/15+)
│   └── credential_attempts (3 bins: 0/1/5+)
│
├── Action Space: 8 topology configurations
│   ├── 0: hub-and-spoke (central auth, many leaves)
│   ├── 1: mesh (dense connections)
│   ├── 2: layered (DMZ → internal → core)
│   ├── 3: star (central DB server)
│   ├── 4: random Barabasi-Albert (default/fallback)
│   ├── 5: financial-heavy (more DB + API nodes)
│   ├── 6: dev-heavy (more API + file servers)
│   └── 7: admin-heavy (more auth + windows nodes)
│
├── Q-Table: numpy array (2880 × 8, float64, ~23KB)
│
├── Learning: Q-learning with epsilon-greedy exploration
│   ├── learning_rate: 0.1
│   ├── discount_factor: 0.9
│   ├── epsilon: 0.3 (decays to 0.05)
│   └── epsilon_decay: 0.995 per session
│
└── Persistence: disk (.npy) + Redis (JSON)
```

## Reward Formula

```
reward = (unique_actions × 1.0)
       + (unique_mitre_techniques × 2.0)
       + (credential_theft + canary_triggers × 3.0)
       + (session_minutes × 0.5)
       - (1.0 if session < 60 seconds)
```

## Session Lifecycle

1. Attacker detected → profile generated
2. `rl_optimizer.choose_topology(profile, stats)` → action (0-7)
3. `rl_optimizer.start_session(ip, state, action)` → records decision
4. Attacker interacts → actions accumulate
5. Session ends → `rl_optimizer.end_session(ip, actions, duration)` → computes reward → Q-update
6. Q-table saved to disk on backend shutdown

## Integration Points

- **Startup** (`main.py` lifespan): `rl_optimizer.load()` — restores Q-table from disk
- **Shutdown** (`main.py` lifespan): `rl_optimizer.save()` — persists Q-table
- **Topology generation**: `rl_optimizer.choose_topology()` returns config index
- **Each config** maps to node type weights + graph structure for `generate_topology()`

## Fallback Behavior

The optimizer returns action=4 (random Barabasi-Albert) when:
- No attacker profile available yet
- Cold start (all Q-values are 0 → random exploration)
- Any error in the RL path

Existing system behavior is 100% preserved. The RL layer is purely additive.

## API

```python
from backend.ai.rl_topology import rl_optimizer

# Choose topology config for an attacker
action = rl_optimizer.choose_topology(profile, session_stats)
config = rl_optimizer.get_topology_config(action)
# config = {"name": "financial-heavy", "weights": [...], "graph_type": "barabasi"}

# Track session for reward
rl_optimizer.start_session("10.0.0.5", state=42, action=5)
# ... attacker interacts ...
reward = rl_optimizer.end_session("10.0.0.5", actions_list, duration_seconds)

# Persistence
rl_optimizer.save()       # disk
rl_optimizer.load()       # disk
json_str = rl_optimizer.to_json()   # Redis-compatible
rl_optimizer.from_json(json_str)

# Stats
rl_optimizer.get_stats()
# {"total_updates": 47, "epsilon": 0.28, "active_sessions": 1, "non_zero_states": 12}
```

## Testing

```bash
pytest tests/test_rl_topology.py -v
```

27 tests covering:
- State discretization (boundary conditions, full range)
- Reward computation (MITRE bonus, credential bonus, dwell time, short session penalty)
- Epsilon-greedy exploration vs exploitation
- Q-learning convergence
- Disk and JSON persistence roundtrips
- Session lifecycle (start → end → Q-update → epsilon decay)
- All 8 topology configs valid (weights sum to 1.0)
- Dict and Pydantic profile support
- Stats reporting
