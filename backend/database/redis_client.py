import os
import redis.asyncio as redis
from typing import Dict, List, Tuple, Optional
from backend.models import AttackerAction, AttackerProfile, TopologySnapshot

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
TTL_SESSION = 86400  # 24 hours

# Global Redis connection pool
redis_conn = redis.from_url(REDIS_URL, decode_responses=True)

class RedisClient:
    async def save_action(self, ip: str, action: AttackerAction):
        try:
            key = f"session:actions:{ip}"
            await redis_conn.rpush(key, action.model_dump_json())
            await redis_conn.ltrim(key, -1000, -1)
            await redis_conn.expire(key, TTL_SESSION)
        except Exception as e:
            print(f"[Redis] Failed to save action for {ip}: {e}")

    async def save_profile(self, ip: str, profile: AttackerProfile):
        try:
            await redis_conn.set(
                f"session:profile:{ip}",
                profile.model_dump_json(),
                ex=TTL_SESSION
            )
        except Exception as e:
            print(f"[Redis] Failed to save profile for {ip}: {e}")

    async def save_topology(self, topology: TopologySnapshot):
        try:
            await redis_conn.set(
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
            action_keys = await redis_conn.keys("session:actions:*")
            for key in action_keys:
                ip = key.split(":")[-1]
                raw_actions = await redis_conn.lrange(key, 0, -1)
                actions_map[ip] = [AttackerAction.model_validate_json(a) for a in raw_actions]

            profile_keys = await redis_conn.keys("session:profile:*")
            for key in profile_keys:
                ip = key.split(":")[-1]
                raw_profile = await redis_conn.get(key)
                if raw_profile:
                    profiles_map[ip] = AttackerProfile.model_validate_json(raw_profile)

            raw_topo = await redis_conn.get("system:topology")
            if raw_topo:
                topology = TopologySnapshot.model_validate_json(raw_topo)

        except Exception as e:
            print(f"[Redis] Failed to load state: {e}")
            
        return actions_map, profiles_map, topology

    async def close(self):
        await redis_conn.close()

redis_client = RedisClient()
