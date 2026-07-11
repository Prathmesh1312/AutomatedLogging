import json
import logging
from typing import Optional, Dict, Any
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError, TimeoutError

logger = logging.getLogger("BSES.StateStore")

class StateStore:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self.client: Optional[aioredis.Redis] = None
        self.redis_online = False
        
        # High-performance local in-memory fallback cache
        # Used if Redis is unavailable or for local hot-caching
        self._fallback_db: Dict[str, str] = {}

    async def connect(self):
        try:
            self.client = aioredis.from_url(
                self.redis_url, 
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
                retry_on_timeout=True
            )
            # Test connection
            await self.client.ping()
            self.redis_online = True
            logger.info("Successfully connected to Redis state store.")
        except (ConnectionError, TimeoutError, Exception) as e:
            logger.warning(f"Could not connect to Redis at {self.redis_url}: {e}. Falling back to in-memory state tracking.")
            self.redis_online = False
            self.client = None

    async def _execute(self, func_name: str, *args, **kwargs) -> Any:
        """Helper to run a Redis command with fallback handling on network error."""
        if not self.redis_online or not self.client:
            return self._execute_fallback(func_name, *args, **kwargs)

        try:
            # Dynamically execute redis client command
            redis_func = getattr(self.client, func_name)
            return await redis_func(*args, **kwargs)
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"Redis link failure on '{func_name}': {e}. Transitioning to in-memory fallback.")
            self.redis_online = False
            self.client = None
            return self._execute_fallback(func_name, *args, **kwargs)

    def _execute_fallback(self, func_name: str, *args, **kwargs) -> Any:
        """Executes equivalent logic locally in memory."""
        # Simple implementation for key operations: get, set, delete, keys, hset, hget
        if func_name == "get":
            return self._fallback_db.get(args[0])
        elif func_name == "set":
            self._fallback_db[args[0]] = str(args[1])
            return True
        elif func_name == "delete" or func_name == "delete":
            for k in args:
                self._fallback_db.pop(k, None)
            return True
        elif func_name == "keys":
            pattern = args[0].replace("*", "")
            return [k for k in self._fallback_db.keys() if pattern in k]
        elif func_name == "hset":
            key = args[0]
            field = args[1]
            value = args[2]
            hkey = f"_hash:{key}"
            if hkey not in self._fallback_db:
                self._fallback_db[hkey] = "{}"
            hdict = json.loads(self._fallback_db[hkey])
            hdict[field] = str(value)
            self._fallback_db[hkey] = json.dumps(hdict)
            return 1
        elif func_name == "hget":
            key = args[0]
            field = args[1]
            hkey = f"_hash:{key}"
            hstr = self._fallback_db.get(hkey)
            if not hstr:
                return None
            return json.loads(hstr).get(field)
        elif func_name == "hgetall":
            key = args[0]
            hkey = f"_hash:{key}"
            hstr = self._fallback_db.get(hkey)
            if not hstr:
                return {}
            return json.loads(hstr)
        return None

    # --- Session State API ---

    async def save_session(self, session_id: str, session_data: Dict[str, Any], expiry: int = 3600):
        key = f"session:{session_id}"
        val = json.dumps(session_data)
        await self._execute("set", key, val, ex=expiry)

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        key = f"session:{session_id}"
        val = await self._execute("get", key)
        return json.loads(val) if val else None

    async def delete_session(self, session_id: str):
        key = f"session:{session_id}"
        await self._execute("delete", key)

    # --- Markov Chain Models API ---

    async def save_markov_chain(self, persona: str, chain: Dict[str, Any]):
        key = f"markov:{persona}"
        val = json.dumps(chain)
        await self._execute("set", key, val)

    async def get_markov_chain(self, persona: str) -> Optional[Dict[str, Any]]:
        key = f"markov:{persona}"
        val = await self._execute("get", key)
        return json.loads(val) if val else None

    # --- Device & Profile Storage API ---

    async def register_device(self, device_id: str, device_profile: Dict[str, Any]):
        key = f"device:{device_id}"
        val = json.dumps(device_profile)
        await self._execute("set", key, val)

    async def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        key = f"device:{device_id}"
        val = await self._execute("get", key)
        return json.loads(val) if val else None

    # --- IP Address Assignments ---

    async def map_ip_to_entity(self, ip: str, entity_id: str):
        key = f"ip_map:{ip}"
        await self._execute("set", key, entity_id)

    async def get_entity_by_ip(self, ip: str) -> Optional[str]:
        key = f"ip_map:{ip}"
        return await self._execute("get", key)

    # --- Impossible Travel Logs ---

    async def update_user_location(self, username: str, location_data: Dict[str, Any]):
        """
        location_data: {
          "city": "Mumbai",
          "country": "IN",
          "lat": 19.076,
          "lon": 72.877,
          "timestamp": "2026-07-11T09:18:52Z"
        }
        """
        key = f"travel:{username}"
        val = json.dumps(location_data)
        await self._execute("set", key, val)

    async def get_user_location(self, username: str) -> Optional[Dict[str, Any]]:
        key = f"travel:{username}"
        val = await self._execute("get", key)
        return json.loads(val) if val else None

    async def close(self):
        if self.client:
            await self.client.close()
            logger.info("Closed Redis state store connection.")
