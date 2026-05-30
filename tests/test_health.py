"""
test_health.py — Task 4.4 Verification Suite
============================================
Tests for Neo4j Client health, seeding logic, and FastAPI /health endpoint.

All Neo4j connections and driver interactions are mocked so the suite
can run instantly without needing a running Neo4j database.

Covers:
  1. Neo4j healthy check behavior
  2. Neo4j unavailable (exception) handling
  3. Seed data insertion on empty database
  4. Seed data duplicate prevention (skips if count > 0)
  5. Health endpoint response validity
  6. MITRE status inclusion in health check
  7. Active container count inclusion in health check

Usage:
    python tests/test_health.py
"""

import os
import sys
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.neo4j_client import Neo4jClient
from backend.main import health
from backend.mitre.mapper import mitre_mapper
from backend.deception.container_manager import active_containers

# Terminal styling
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
_results = []


def _record(test_id: str, passed: bool, detail: str = "") -> None:
    _results.append((test_id, passed, detail))
    status = PASS if passed else FAIL
    print(f"  {status} {test_id}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Test 1: Neo4j healthy behavior
# ---------------------------------------------------------------------------
def test_neo4j_healthy():
    """When Neo4j is responsive, health_check returns True."""
    client = Neo4jClient()
    
    # Mock driver & session
    mock_session = AsyncMock()
    mock_session.run = AsyncMock()
    
    mock_driver = MagicMock()
    # Mock async context manager for driver.session()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    client.driver = mock_driver

    try:
        result = asyncio.run(client.health_check())
        _record("1. Neo4j healthy check returns True", result is True, f"result={result}")
    except Exception as e:
        _record("1. Neo4j healthy check returns True", False, str(e))


# ---------------------------------------------------------------------------
# Test 2: Neo4j unavailable behavior
# ---------------------------------------------------------------------------
def test_neo4j_unavailable():
    """When Neo4j driver throws an exception, health_check returns False (no crash)."""
    client = Neo4jClient()
    
    mock_driver = MagicMock()
    # Make driver.session() throw an exception immediately
    mock_driver.session.side_effect = Exception("Bolt connection error: host unreachable")
    client.driver = mock_driver

    try:
        result = asyncio.run(client.health_check())
        _record("2. Neo4j unavailable check returns False", result is False, f"result={result}")
    except Exception as e:
        _record("2. Neo4j unavailable check returns False", False, f"Crashed: {e}")


# ---------------------------------------------------------------------------
# Test 3: Seed data insertion
# ---------------------------------------------------------------------------
def test_seed_data_insertion():
    """When Neo4j Node count is 0, seed_demo_data inserts records."""
    client = Neo4jClient()
    
    # Mock records returned by count query
    mock_record = MagicMock()
    mock_record.__getitem__.side_effect = lambda key: 0 if key == "c" else None
    
    mock_result = AsyncMock()
    mock_result.single.return_value = mock_record

    mock_session = AsyncMock()
    # Mock execution sequence: first query returns count=0, second performs seed
    mock_session.run.side_effect = [mock_result, AsyncMock()]
    
    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    client.driver = mock_driver

    try:
        asyncio.run(client.seed_demo_data())
        
        # Verify run was called twice
        call_count = mock_session.run.call_count
        first_query = mock_session.run.call_args_list[0][0][0]
        second_query = mock_session.run.call_args_list[1][0][0]
        
        ok = (
            call_count == 2
            and "count(n)" in first_query
            and "MERGE (a:Attacker" in second_query
        )
        _record("3. Seed data insertion executed", ok, f"calls={call_count}")
    except Exception as e:
        _record("3. Seed data insertion executed", False, str(e))


# ---------------------------------------------------------------------------
# Test 4: Seed data duplicate prevention
# ---------------------------------------------------------------------------
def test_seed_duplicate_prevention():
    """When Neo4j Node count is > 0, seed_demo_data exits immediately without creating duplicates."""
    client = Neo4jClient()
    
    mock_record = MagicMock()
    mock_record.__getitem__.side_effect = lambda key: 5 if key == "c" else None
    
    mock_result = AsyncMock()
    mock_result.single.return_value = mock_record

    mock_session = AsyncMock()
    mock_session.run.return_value = mock_result
    
    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    client.driver = mock_driver

    try:
        asyncio.run(client.seed_demo_data())
        
        # Verify run was only called once (just the count query)
        call_count = mock_session.run.call_count
        first_query = mock_session.run.call_args[0][0]
        
        ok = call_count == 1 and "count(n)" in first_query
        _record("4. Seed data duplicate prevention (skips insert)", ok, f"calls={call_count}")
    except Exception as e:
        _record("4. Seed data duplicate prevention (skips insert)", False, str(e))


# ---------------------------------------------------------------------------
# Test 5: Health endpoint response
# ---------------------------------------------------------------------------
def test_health_endpoint():
    """Health endpoint returns valid status, including Neo4j, MITRE, and active containers."""
    # Let's mock the global active_containers, mitre_mapper, and neo4j_client
    active_containers.clear()
    active_containers["node_0_1"] = "cid_123"
    
    with patch("backend.main.neo4j_client.health_check", new_callable=AsyncMock) as mock_health:
        mock_health.return_value = True
        
        try:
            res = asyncio.run(health())
            
            # Check structure
            status_ok = res.get("status") == "ok"
            neo4j_ok = res.get("neo4j") is True
            _record("5. Health endpoint response status & neo4j matches", status_ok and neo4j_ok, f"response={res}")
        except Exception as e:
            _record("5. Health endpoint response status & neo4j matches", False, str(e))
            
    active_containers.clear()


# ---------------------------------------------------------------------------
# Test 6: MITRE status included
# ---------------------------------------------------------------------------
def test_mitre_status_included():
    """Health check response contains the initialized status of the MITRE mapper."""
    # Set the state of mitre_mapper to True and verify
    mitre_mapper._is_initialized = True
    
    with patch("backend.main.neo4j_client.health_check", new_callable=AsyncMock) as mock_health:
        mock_health.return_value = True
        
        try:
            res = asyncio.run(health())
            mitre_ok = "mitre_loaded" in res and res["mitre_loaded"] is True
            
            # Now set to False and verify
            mitre_mapper._is_initialized = False
            res_false = asyncio.run(health())
            mitre_false = "mitre_loaded" in res_false and res_false["mitre_loaded"] is False
            
            _record("6. MITRE status included in health check", mitre_ok and mitre_false, f"loaded_true={res.get('mitre_loaded')} | loaded_false={res_false.get('mitre_loaded')}")
        except Exception as e:
            _record("6. MITRE status included in health check", False, str(e))
            
    # Reset
    mitre_mapper._is_initialized = True


# ---------------------------------------------------------------------------
# Test 7: Active container count included
# ---------------------------------------------------------------------------
def test_container_count_included():
    """Health check response dynamically includes accurate count of currently active containers."""
    active_containers.clear()
    
    with patch("backend.main.neo4j_client.health_check", new_callable=AsyncMock) as mock_health:
        mock_health.return_value = True
        
        try:
            # 0 active
            res_0 = asyncio.run(health())
            cnt_0 = res_0.get("active_containers") == 0
            
            # 3 active
            active_containers["node_0_1"] = "cid_111"
            active_containers["node_0_2"] = "cid_222"
            active_containers["node_0_3"] = "cid_333"
            
            res_3 = asyncio.run(health())
            cnt_3 = res_3.get("active_containers") == 3
            
            _record("7. Active container count included in health check", cnt_0 and cnt_3, f"count_0={res_0.get('active_containers')} | count_3={res_3.get('active_containers')}")
        except Exception as e:
            _record("7. Active container count included in health check", False, str(e))
            
    active_containers.clear()


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def _print_summary():
    total = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = total - passed
    print("\n" + "=" * 60)
    print(f"Total: {total} | PASS: {passed} | FAIL: {failed}")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("═══ TASK 4.4 — Neo4j & API Health Verification Suite ═══")
    print("═" * 60)

    test_neo4j_healthy()
    test_neo4j_unavailable()
    test_seed_data_insertion()
    test_seed_duplicate_prevention()
    test_health_endpoint()
    test_mitre_status_included()
    test_container_count_included()

    sys.exit(_print_summary())
