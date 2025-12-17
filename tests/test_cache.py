import asyncio

import pytest

from fastapi_ldap.cache import AuthCache

class TestAuthCache:
    @pytest.mark.asyncio
    async def test_get_set(self):
        cache = AuthCache(ttl=60)
        await cache.set("key1", "value1")
        result = await cache.get("key1")
        assert result == "value1"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self):
        cache = AuthCache(ttl=60)
        result = await cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_expiration(self):
        cache = AuthCache(ttl=0.1)
        await cache.set("key1", "value1")
        result = await cache.get("key1")
        assert result == "value1"

        await asyncio.sleep(0.2)
        result = await cache.get("key1")
        assert result is None

    @pytest.mark.asyncio
    async def test_clear(self):
        cache = AuthCache(ttl=60)
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.clear()
        assert await cache.get("key1") is None
        assert await cache.get("key2") is None

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        cache = AuthCache(ttl=0.1)
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")

        await asyncio.sleep(0.2)

        await cache.set("key3", "value3")

        await cache.cleanup_expired()

        assert await cache.get("key1") is None
        assert await cache.get("key2") is None
        assert await cache.get("key3") == "value3"

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        cache = AuthCache(ttl=60)

        async def set_value(key: str, value: str):
            await cache.set(key, value)

        async def get_value(key: str):
            return await cache.get(key)

        await asyncio.gather(
            set_value("key1", "value1"),
            set_value("key2", "value2"),
            set_value("key3", "value3"),
        )

        results = await asyncio.gather(
            get_value("key1"),
            get_value("key2"),
            get_value("key3"),
        )

        assert results == ["value1", "value2", "value3"]

    @pytest.mark.asyncio
    async def test_overwrite_value(self):
        cache = AuthCache(ttl=60)
        await cache.set("key1", "value1")
        await cache.set("key1", "value2")
        result = await cache.get("key1")
        assert result == "value2"

    @pytest.mark.asyncio
    async def test_different_value_types(self):
        cache = AuthCache(ttl=60)
        await cache.set("str", "string")
        await cache.set("int", 42)
        await cache.set("list", [1, 2, 3])
        await cache.set("dict", {"key": "value"})

        assert await cache.get("str") == "string"
        assert await cache.get("int") == 42
        assert await cache.get("list") == [1, 2, 3]
        assert await cache.get("dict") == {"key": "value"}

    def test_stats(self):
        cache = AuthCache(ttl=300)
        stats = cache._get_stats()
        assert "size" in stats
        assert "ttl" in stats
        assert stats["ttl"] == 300

