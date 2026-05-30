import pytest
import time
import tempfile
import os
import numpy as np
from backend.ai.rl_topology import (
    RLTopologyOptimizer,
    discretize_state,
    compute_reward,
    TOTAL_STATES,
    NUM_ACTIONS,
    TOPOLOGY_CONFIGS,
    _SKILL_MAP,
)
from backend.models import AttackerAction, AttackerProfile


@pytest.fixture
def optimizer():
    return RLTopologyOptimizer(epsilon=0.3)


@pytest.fixture
def profile():
    return AttackerProfile(
        attacker_ip="10.0.0.5",
        skill_level="Advanced",
        objective="Credential harvesting",
        apt_resemblance="APT29",
        tools_detected=["nmap", "hydra"],
        confidence=0.8,
        summary="Advanced attacker.",
    )


@pytest.fixture
def actions():
    base = time.time() - 300
    return [
        AttackerAction(attacker_ip="10.0.0.5", action_type="port_scan",
                       target_node_id="node-1", detail="SYN scan", timestamp=base,
                       mitre_technique_id="T1046", mitre_technique_name="Network Service Discovery"),
        AttackerAction(attacker_ip="10.0.0.5", action_type="login_attempt",
                       target_node_id="node-2", detail="SSH brute force", timestamp=base + 60,
                       mitre_technique_id="T1110", mitre_technique_name="Brute Force"),
        AttackerAction(attacker_ip="10.0.0.5", action_type="credential_theft",
                       target_node_id="node-3", detail="Stole .env", timestamp=base + 120,
                       mitre_technique_id="T1552.001", mitre_technique_name="Credentials In Files"),
        AttackerAction(attacker_ip="10.0.0.5", action_type="canary_trigger",
                       target_node_id="node-4", detail="Canary accessed", timestamp=base + 180),
        AttackerAction(attacker_ip="10.0.0.5", action_type="data_access",
                       target_node_id="node-1", detail="Read /etc/passwd", timestamp=base + 240),
    ]


class TestStateDiscretization:

    def test_zero_state(self):
        state = discretize_state(0, 0, 0, 0, 0, 0)
        assert state == 0

    def test_max_state(self):
        state = discretize_state(3, 100, 20, 200, 50, 30)
        assert state == TOTAL_STATES - 1

    def test_skill_levels(self):
        s0 = discretize_state(0, 10, 1, 5, 3, 0)
        s1 = discretize_state(1, 10, 1, 5, 3, 0)
        s2 = discretize_state(2, 10, 1, 5, 3, 0)
        s3 = discretize_state(3, 10, 1, 5, 3, 0)
        assert s0 < s1 < s2 < s3

    def test_all_states_in_range(self):
        for skill in range(4):
            for actions in [0, 3, 10, 25, 50]:
                for gen in [0, 2, 8]:
                    for dur in [0, 3, 15, 90]:
                        for nodes in [0, 2, 5, 20]:
                            for creds in [0, 1, 10]:
                                s = discretize_state(skill, actions, gen, dur, nodes, creds)
                                assert 0 <= s < TOTAL_STATES


class TestRewardComputation:

    def test_empty_actions(self):
        assert compute_reward([], 0) == 0.0

    def test_basic_reward(self, actions):
        reward = compute_reward(actions, 300)
        assert reward > 0

    def test_mitre_bonus(self, actions):
        reward_with_mitre = compute_reward(actions, 300)
        no_mitre = [AttackerAction(attacker_ip="10.0.0.5", action_type="port_scan",
                                   target_node_id="node-1", detail="scan", timestamp=time.time())]
        reward_without = compute_reward(no_mitre, 300)
        assert reward_with_mitre > reward_without

    def test_credential_bonus(self, actions):
        reward = compute_reward(actions, 300)
        # actions has 2 high-value (credential_theft + canary_trigger) = +6.0
        assert reward >= 6.0

    def test_short_session_penalty(self):
        short_actions = [AttackerAction(attacker_ip="10.0.0.5", action_type="port_scan",
                                        target_node_id="n1", detail="scan", timestamp=time.time())]
        reward = compute_reward(short_actions, 30)
        # Should have -1.0 penalty for <60s session
        assert reward < compute_reward(short_actions, 120)

    def test_dwell_time_bonus(self, actions):
        short = compute_reward(actions, 60)
        long = compute_reward(actions, 600)
        assert long > short


class TestEpsilonGreedy:

    def test_exploration_rate(self, optimizer, profile):
        optimizer.epsilon = 1.0
        choices = set()
        for _ in range(100):
            choices.add(optimizer.choose_topology(profile, {"actions_taken": 5}))
        assert len(choices) > 1

    def test_exploitation(self, optimizer, profile):
        optimizer.epsilon = 0.0
        state = discretize_state(2, 5, 0, 0, 0, 0)
        optimizer.q_table[state, 7] = 100.0
        action = optimizer.choose_topology(profile, {"actions_taken": 5})
        assert action == 7

    def test_no_profile_returns_default(self, optimizer):
        action = optimizer.choose_topology(None)
        assert action == 4


class TestQLearningUpdate:

    def test_update_increases_value(self, optimizer):
        state = 100
        action = 3
        assert optimizer.q_table[state, action] == 0.0
        optimizer.update(state, action, 10.0, state)
        assert optimizer.q_table[state, action] > 0.0

    def test_convergence(self, optimizer):
        state = 50
        action = 2
        for _ in range(100):
            optimizer.update(state, action, 5.0, state)
        q_val = optimizer.q_table[state, action]
        # Should converge toward reward / (1 - gamma) = 5 / 0.1 = 50
        assert q_val > 20.0

    def test_update_counter(self, optimizer):
        assert optimizer._total_updates == 0
        optimizer.update(0, 0, 1.0, 0)
        optimizer.update(0, 1, 2.0, 0)
        assert optimizer._total_updates == 2


class TestPersistence:

    def test_save_load_disk(self, optimizer):
        optimizer.q_table[100, 3] = 42.0
        optimizer.q_table[200, 7] = -5.0

        with tempfile.NamedTemporaryFile(suffix=".npy", delete=False) as f:
            path = f.name

        try:
            optimizer.save(path)
            new_opt = RLTopologyOptimizer()
            assert new_opt.q_table[100, 3] == 0.0
            new_opt.load(path)
            assert new_opt.q_table[100, 3] == 42.0
            assert new_opt.q_table[200, 7] == -5.0
        finally:
            os.unlink(path)

    def test_json_roundtrip(self, optimizer):
        optimizer.q_table[50, 2] = 7.5
        json_str = optimizer.to_json()
        new_opt = RLTopologyOptimizer()
        new_opt.from_json(json_str)
        assert new_opt.q_table[50, 2] == 7.5

    def test_load_nonexistent_returns_false(self, optimizer):
        result = optimizer.load("/nonexistent/path/q_table.npy")
        assert result is False


class TestSessionLifecycle:

    def test_start_end_session(self, optimizer, actions):
        optimizer.start_session("10.0.0.5", state=100, action=3)
        reward = optimizer.end_session("10.0.0.5", actions, 300.0)
        assert reward is not None
        assert reward > 0
        assert optimizer.q_table[100, 3] > 0

    def test_end_unknown_session(self, optimizer, actions):
        reward = optimizer.end_session("unknown_ip", actions, 300.0)
        assert reward is None

    def test_epsilon_decays(self, optimizer, actions):
        initial_eps = optimizer.epsilon
        optimizer.start_session("10.0.0.5", state=0, action=0)
        optimizer.end_session("10.0.0.5", actions, 300.0)
        assert optimizer.epsilon < initial_eps


class TestTopologyConfigs:

    def test_all_configs_exist(self):
        for i in range(NUM_ACTIONS):
            assert i in TOPOLOGY_CONFIGS
            config = TOPOLOGY_CONFIGS[i]
            assert "name" in config
            assert "weights" in config
            assert "graph_type" in config

    def test_weights_sum_to_one(self):
        for i, config in TOPOLOGY_CONFIGS.items():
            total = sum(config["weights"])
            assert abs(total - 1.0) < 0.01, f"Config {i} weights sum to {total}"

    def test_get_config(self, optimizer):
        config = optimizer.get_topology_config(5)
        assert config["name"] == "financial-heavy"
        assert config["graph_type"] == "barabasi"


class TestDictProfileSupport:

    def test_dict_profile(self, optimizer):
        profile_dict = {
            "skill_level": "Intermediate",
            "objective": "Data exfiltration",
        }
        action = optimizer.choose_topology(profile_dict, {"actions_taken": 10})
        assert 0 <= action < NUM_ACTIONS


class TestStats:

    def test_get_stats(self, optimizer):
        stats = optimizer.get_stats()
        assert stats["total_updates"] == 0
        assert stats["epsilon"] == 0.3
        assert stats["active_sessions"] == 0
        assert stats["q_table_shape"] == [TOTAL_STATES, NUM_ACTIONS]
