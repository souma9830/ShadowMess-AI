import os
import asyncio
from dotenv import load_dotenv
from neo4j import AsyncGraphDatabase
from backend.models import AttackerAction

load_dotenv()  # Must be before os.getenv calls

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "shadowmesh")

_neo4j_available = False

def is_neo4j_available() -> bool:
    return _neo4j_available

class Neo4jClient:
    def __init__(self):
        self.driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    async def close(self):
        await self.driver.close()

    async def init_schema(self):
        async with self.driver.session() as session:
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Attacker) REQUIRE a.ip IS UNIQUE")
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Node) REQUIRE n.node_id IS UNIQUE")
            await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (c:Credential) REQUIRE c.credential_id IS UNIQUE")
            await session.run("CREATE INDEX IF NOT EXISTS FOR (a:AttackerAction) ON (a.timestamp)")

    async def health_check(self) -> bool:
        global _neo4j_available
        try:
            async with self.driver.session() as session:
                await session.run("RETURN 1 AS n")
            _neo4j_available = True
            return True
        except Exception as e:
            _neo4j_available = False
            return False

    async def seed_demo_data(self):
        import time
        current_epoch = time.time()
        async with self.driver.session() as session:
            # Check current node count
            result = await session.run("MATCH (n:Node) RETURN count(n) AS c")
            record = await result.single()
            if record and record["c"] > 0:
                return
            
            # Seed demo data, using MERGE to prevent duplicates
            await session.run("""
                MERGE (a:Attacker {ip: '192.168.1.100'})
                MERGE (n:Node {node_id: 'node_demo', node_type: 'web_server'})
                MERGE (a)-[r:PERFORMED {action_type: 'port_scan'}]->(n)
                ON CREATE SET r.timestamp = $timestamp
            """, timestamp=current_epoch)

    async def connect_with_retry(self, max_attempts=10, delay=3.0) -> bool:
        global _neo4j_available
        for attempt in range(max_attempts):
            try:
                async with self.driver.session() as session:
                    await session.run("RETURN 1")
                await self.init_schema()
                healthy = await self.health_check()
                if healthy:
                    await self.seed_demo_data()
                _neo4j_available = True
                print(f"✅ Neo4j connected (attempt {attempt+1})")
                return True
            except Exception as e:
                print(f"⏳ Neo4j not ready ({attempt+1}/{max_attempts}): {e}")
                await asyncio.sleep(delay)
        print("\u274c Neo4j unavailable — memory-only mode")
        _neo4j_available = False
        return False

    async def create_attacker(self, ip: str) -> None:
        if not _neo4j_available: return
        async with self.driver.session() as session:
            await session.run("""
                MERGE (a:Attacker {ip: $ip})
                ON CREATE SET a.first_seen = datetime(), a.action_count = 0
                ON MATCH SET a.action_count = a.action_count + 1
            """, ip=ip)

    async def log_action(self, action: AttackerAction) -> None:
        if not _neo4j_available: return
        async with self.driver.session() as session:
            await session.run("""
                MERGE (a:Attacker {ip: $attacker_ip})
                MERGE (n:Node {node_id: $target_node_id})
                CREATE (a)-[:PERFORMED {
                    action_type: $action_type,
                    detail: $detail,
                    timestamp: $timestamp,
                    mitre_id: $mitre_id,
                    mitre_name: $mitre_name
                }]->(n)
            """, 
            attacker_ip=action.attacker_ip,
            target_node_id=action.target_node_id,
            action_type=action.action_type,
            detail=action.detail,
            timestamp=action.timestamp,
            mitre_id=action.mitre_technique_id or "",
            mitre_name=action.mitre_technique_name or "")

    async def get_attack_path(self, attacker_ip: str) -> list[dict]:
        if not _neo4j_available: return []
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH p = (a:Attacker {ip: $ip})-[:PERFORMED*]->(n:Node)
                RETURN [node in nodes(p) | {
                    id: coalesce(node.node_id, node.ip), ip: node.ip, labels: labels(node)
                }] AS path_nodes,
                [rel in relationships(p) | {
                    type: type(rel), action: rel.action_type,
                    timestamp: rel.timestamp, mitre_id: rel.mitre_id
                }] AS path_rels
                LIMIT 1
            """, ip=attacker_ip)
            record = await result.single()
            if record:
                return {
                    "nodes": record["path_nodes"],
                    "relationships": record["path_rels"]
                }
            return []

    async def get_all_actions(self, attacker_ip: str) -> list[dict]:
        if not _neo4j_available: return []
        async with self.driver.session() as session:
            result = await session.run("""
                MATCH (a:Attacker {ip: $ip})-[r:PERFORMED]->(n:Node)
                RETURN r, n ORDER BY r.timestamp
            """, ip=attacker_ip)
            records = await result.data()
            return records

neo4j_client = Neo4jClient()
