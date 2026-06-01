import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPBasicCredentials

from fastapi_ldap.auth import LDAPAuth, get_current_user, require_groups, require_roles
from fastapi_ldap.cache import AuthCache
from fastapi_ldap.client import LDAPClient
from fastapi_ldap.exceptions import LDAPConnectionError
from fastapi_ldap.models import LDAPUser

class TestLDAPAuth:
    @pytest.mark.asyncio
    async def test_lifespan_initialization(self, ldap_settings):
        auth = LDAPAuth(ldap_settings)
        mock_app = Mock()

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.initialize = AsyncMock()
        mock_client.close = AsyncMock()

        with patch("fastapi_ldap.auth.LDAPClient", return_value=mock_client), patch(
            "fastapi_ldap.health.set_client"
        ) as mock_set_client:
            async with auth.lifespan(mock_app):
                mock_client.initialize.assert_called_once()
                mock_set_client.assert_called_once()

            mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_lifespan_with_cache(self, ldap_settings):
        ldap_settings.cache_enabled = True
        ldap_settings.cache_ttl = 300
        auth = LDAPAuth(ldap_settings)
        mock_app = Mock()

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.initialize = AsyncMock()

        with patch("fastapi_ldap.auth.LDAPClient", return_value=mock_client), patch(
            "fastapi_ldap.auth.AuthCache"
        ) as mock_cache_class:
            mock_cache = AsyncMock(spec=AuthCache)
            mock_cache_class.return_value = mock_cache

            async with auth.lifespan(mock_app):
                mock_cache_class.assert_called_once_with(ttl=300)

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, ldap_settings):
        auth = LDAPAuth(ldap_settings)
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(
            return_value={
                "dn": "cn=testuser,dc=example,dc=com",
                "uid": "testuser",
                "mail": "test@example.com",
                "cn": "Test User",
            }
        )
        mock_client.get_user_groups = AsyncMock(return_value=["admins", "users"])

        auth._client = mock_client

        user = await auth.authenticate_user("testuser", "password")

        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.display_name == "Test User"
        assert "admins" in user.groups
        assert "users" in user.groups

    @pytest.mark.asyncio
    async def test_authenticate_user_with_cache(self, ldap_settings):
        ldap_settings.cache_enabled = True
        auth = LDAPAuth(ldap_settings)
        mock_client = AsyncMock(spec=LDAPClient)
        mock_cache = AsyncMock(spec=AuthCache)

        mock_cache.get = AsyncMock(return_value=None)
        mock_client.authenticate = AsyncMock(
            return_value={
                "dn": "cn=testuser,dc=example,dc=com",
                "uid": "testuser",
            }
        )
        mock_client.get_user_groups = AsyncMock(return_value=["admins"])

        auth._client = mock_client
        auth._cache = mock_cache

        user = await auth.authenticate_user("testuser", "password")

        assert user is not None
        mock_cache.set.assert_called_once()

        cached_user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["admins"]),
        )
        mock_cache.get = AsyncMock(return_value=cached_user)

        user2 = await auth.authenticate_user("testuser", "password")

        assert user2 == cached_user
        assert mock_client.authenticate.call_count == 1

    @pytest.mark.asyncio
    async def test_authenticate_user_failure(self, ldap_settings):
        auth = LDAPAuth(ldap_settings)
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(return_value=None)

        auth._client = mock_client

        user = await auth.authenticate_user("testuser", "wrongpassword")

        assert user is None

    @pytest.mark.asyncio
    async def test_authenticate_user_client_not_initialized(self, ldap_settings):
        auth = LDAPAuth(ldap_settings)
        auth._client = None

        with pytest.raises(LDAPConnectionError):
            await auth.authenticate_user("testuser", "password")

class TestGetCurrentUser:
    @pytest.mark.asyncio
    async def test_get_current_user_success(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="password")

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(
            return_value={
                "dn": "cn=testuser,dc=example,dc=com",
                "uid": "testuser",
                "mail": "test@example.com",
            }
        )
        mock_client.get_user_groups = AsyncMock(return_value=["users"])

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", None
        ), patch("fastapi_ldap.auth._settings", ldap_settings):
            user = await get_current_user(credentials)

            assert user.username == "testuser"
            assert user.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_get_current_user_authentication_failed(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="wrongpass")

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(return_value=None)

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", None
        ), patch("fastapi_ldap.auth._settings", ldap_settings):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)

            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_current_user_401_not_logged_as_unexpected(
        self, ldap_settings, caplog
    ):
        credentials = HTTPBasicCredentials(username="testuser", password="wrongpass")

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(return_value=None)

        caplog.set_level(logging.ERROR)

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", None
        ), patch("fastapi_ldap.auth._settings", ldap_settings):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)

            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Unexpected authentication error" not in caplog.text

    @pytest.mark.asyncio
    async def test_get_current_user_client_not_initialized(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="password")

        with patch("fastapi_ldap.auth._client", None):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)

            assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_get_current_user_connection_error(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="password")

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(side_effect=LDAPConnectionError("Connection failed"))

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", None
        ), patch("fastapi_ldap.auth._settings", ldap_settings):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)

            assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_get_current_user_unexpected_error(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="password")

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(side_effect=Exception("Unexpected error"))

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", None
        ), patch("fastapi_ldap.auth._settings", ldap_settings):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(credentials)

            # Should fail closed - return 401, not leak error details
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

class TestRequireGroups:
    @pytest.mark.asyncio
    async def test_require_groups_success(self, ldap_settings):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["admins", "users"]),
        )

        group_check = require_groups("admins")
        result = await group_check(user=user)

        assert result == user

    @pytest.mark.asyncio
    async def test_require_groups_failure(self, ldap_settings):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["users"]),
        )

        group_check = require_groups("admins")
        with pytest.raises(HTTPException) as exc_info:
            await group_check(user=user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_groups_multiple(self, ldap_settings):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["users"]),
        )

        group_check = require_groups("admins", "users")
        result = await group_check(user=user)
        assert result == user

        user2 = LDAPUser(
            dn="cn=testuser2,dc=example,dc=com",
            username="testuser2",
            groups=frozenset(["guests"]),
        )
        with pytest.raises(HTTPException):
            await group_check(user=user2)

class TestRequireRoles:
    @pytest.mark.asyncio
    async def test_require_roles(self, ldap_settings):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["data-reader"]),
        )

        role_check = require_roles("data-reader")
        result = await role_check(user=user)

        assert result == user

        role_check2 = require_roles("data-reader", "data-writer")
        result2 = await role_check2(user=user)
        assert result2 == user

class TestLDAPAuthAdditional:
    @pytest.mark.asyncio
    async def test_lifespan_cleanup_with_client(self, ldap_settings):
        auth = LDAPAuth(ldap_settings)
        mock_app = Mock()

        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.initialize = AsyncMock()
        mock_client.close = AsyncMock()

        with patch("fastapi_ldap.auth.LDAPClient", return_value=mock_client), patch(
            "fastapi_ldap.auth._client", mock_client
        ), patch("fastapi_ldap.health.set_client"):
            async with auth.lifespan(mock_app):
                pass

            mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_user_with_list_uid(self, ldap_settings):
        auth = LDAPAuth(ldap_settings)
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(
            return_value={
                "dn": "uid=testuser,dc=example,dc=com",
                "uid": ["testuser"],
                "mail": "test@example.com",
                "cn": "Test User",
            }
        )
        mock_client.get_user_groups = AsyncMock(return_value=["users"])

        auth._client = mock_client
        auth._cache = None

        user = await auth.authenticate_user("testuser", "password")
        assert user is not None
        assert "users" in user.groups
        assert user.username in ("testuser", ["testuser"])

    @pytest.mark.asyncio
    async def test_authenticate_user_fallback_username(self, ldap_settings):
        auth = LDAPAuth(ldap_settings)
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(
            return_value={
                "dn": "uid=testuser,dc=example,dc=com",
                "mail": "test@example.com",
                "cn": "Test User",
            }
        )
        mock_client.get_user_groups = AsyncMock(return_value=[])

        auth._client = mock_client
        auth._cache = None

        user = await auth.authenticate_user("testuser", "password")
        assert user is not None
        assert user.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_current_user_cache_hit_with_client(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="password")
        cached_user = LDAPUser(
            dn="uid=testuser,dc=example,dc=com",
            username="testuser",
            email="test@example.com",
            groups=frozenset(["users"]),
        )

        mock_client = AsyncMock(spec=LDAPClient)
        mock_cache = AsyncMock(spec=AuthCache)
        mock_cache.get = AsyncMock(return_value=cached_user)

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", mock_cache
        ):
            user = await get_current_user(credentials)
            assert user == cached_user
            mock_client.authenticate.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_current_user_list_uid(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="password")
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(
            return_value={
                "dn": "uid=testuser,dc=example,dc=com",
                "uid": ["testuser"],
                "mail": "test@example.com",
                "cn": "Test User",
            }
        )
        mock_client.get_user_groups = AsyncMock(return_value=["users"])

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", None
        ):
            user = await get_current_user(credentials)
            assert user.username == "testuser"

class TestGetCurrentUserAdditional:
    @pytest.mark.asyncio
    async def test_get_current_user_fallback_username(self, ldap_settings):
        credentials = HTTPBasicCredentials(username="testuser", password="password")
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.authenticate = AsyncMock(
            return_value={
                "dn": "uid=testuser,dc=example,dc=com",
                "mail": "test@example.com",
                "cn": "Test User",
            }
        )
        mock_client.get_user_groups = AsyncMock(return_value=[])

        with patch("fastapi_ldap.auth._client", mock_client), patch(
            "fastapi_ldap.auth._cache", None
        ):
            user = await get_current_user(credentials)
            assert user.username == "testuser"

