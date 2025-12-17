import asyncio
import time
from typing import Optional

logger = None


class AuthCache:
    """Thread-safe cache for authentication results.

    This cache is optional and can be safely disabled by setting cache_enabled=False.
    """

    def __init__(self, ttl: int = 300) -> None:

        self._cache: dict[str, tuple[object, float]] = {}
        self._ttl = ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[object]:
        async with self._lock:
            if key not in self._cache:
                return None

            value, expiry = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                return None

            return value

    async def set(self, key: str, value: object) -> None:
        async with self._lock:
            expiry = time.time() + self._ttl
            self._cache[key] = (value, expiry)

    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()

    async def cleanup_expired(self) -> None:
        async with self._lock:
            now = time.time()
            expired_keys = [
                key for key, (_, expiry) in self._cache.items() if now > expiry
            ]
            for key in expired_keys:
                del self._cache[key]

    def _get_stats(self) -> dict[str, int]:
        return {
            "size": len(self._cache),
            "ttl": self._ttl,
        }

