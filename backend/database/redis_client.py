import os
import redis.asyncio as redis
from typing import Dict, List, Tuple, Optional
from backend.models import AttackerAction, AttackerProfile, TopologySnapshot

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
TTL_SESSION = 86400  # 24 hours

class RedisClient:
    def __init__(self):
        self._conn = None

    async def _get_conn(self):
        """Lazy connection initialization to prevent connection pool leak."""
        if self._conn is None:
            self._conn = redis.from_url(REDIS_URL, decode_responses=True)
        return self._conn
    async def health_check(self) -> bool:
        """Fix #17: Verify Redis connection at startup instead of failing silently on first op."""
        try:
            conn = await self._get_conn()
            await conn.ping()
            return True
        except Exception as e:
            print(f"[Redis] Health check failed: {e}")
            return False

    async def save_action(self, ip: str, action: AttackerAction):
        try:
            conn = await self._get_conn()
            key = f"session:actions:{ip}"
            await conn.rpush(key, action.model_dump_json())
            await conn.ltrim(key, -1000, -1)
            await conn.expire(key, TTL_SESSION)
        except Exception as e:
            print(f"[Redis] Failed to save action for {ip}: {e}")

    async def save_profile(self, ip: str, profile: AttackerProfile):
        try:
            conn = await self._get_conn()
            await conn.set(
                f"session:profile:{ip}",
                profile.model_dump_json(),
                ex=TTL_SESSION
            )
        except Exception as e:
            print(f"[Redis] Failed to save profile for {ip}: {e}")

    async def save_topology(self, topology: TopologySnapshot):
        try:
            conn = await self._get_conn()
            await conn.set(
                "system:topology",
                topology.model_dump_json(),
                ex=TTL_SESSION
            )
        except Exception as e:
            print(f"[Redis] Failed to save topology: {e}")

    async def load_all_state(self) -> Tuple[Dict[str, List[AttackerAction]], Dict[str, AttackerProfile], Optional[TopologySnapshot]]:
        actions_map = {}
        profiles_map = {}
        topology = None

        try:
            conn = await self._get_conn()
            action_keys = await conn.keys("session:actions:*")
            for key in action_keys:
                ip = key.split(":")[-1]
                raw_actions = await conn.lrange(key, 0, -1)
                actions_map[ip] = [AttackerAction.model_validate_json(a) for a in raw_actions]

            profile_keys = await conn.keys("session:profile:*")
            for key in profile_keys:
                ip = key.split(":")[-1]
                raw_profile = await conn.get(key)
                if raw_profile:
                    profiles_map[ip] = AttackerProfile.model_validate_json(raw_profile)

            raw_topo = await conn.get("system:topology")
            if raw_topo:
                topology = TopologySnapshot.model_validate_json(raw_topo)

        except Exception as e:
            print(f"[Redis] Failed to load state: {e}")

        return actions_map, profiles_map, topology

    async def close(self):
        """Properly close Redis connection pool."""
        if self._conn is not None:
            try:
                await self._conn.aclose()
            except Exception:
                try:
                    await self._conn.close()
                except Exception as e:
                    print(f"[Redis] Error closing connection: {e}")

redis_client = RedisClient()
