import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError

from fastapi_ldap.client import LDAPClient, _normalize_username
from fastapi_ldap.config import LDAPSettings
from fastapi_ldap.exceptions import LDAPConnectionError, LDAPError

class TestLDAPClient:
    @pytest.mark.asyncio
    async def test_initialization(self, ldap_settings):
        with patch("fastapi_ldap.client.Server") as mock_server_class:
            mock_server = Mock(spec=Server)
            mock_server_class.return_value = mock_server

            client = LDAPClient(ldap_settings)
            assert client.settings == ldap_settings
            assert client._server is None
            assert client._pool_size == 0

    @pytest.mark.asyncio
    async def test_initialize_success(self, ldap_settings):
        client = LDAPClient(ldap_settings)

        with patch("fastapi_ldap.client.Server") as mock_server_class, patch(
            "fastapi_ldap.client.Tls"
        ) as mock_tls_class, patch.object(
            client, "_create_connection", new_callable=AsyncMock
        ) as mock_create, patch.object(
            client, "_bind_connection", new_callable=AsyncMock
        ) as mock_bind:
            mock_server = Mock(spec=Server)
            mock_server_class.return_value = mock_server

            mock_conn = Mock(spec=Connection)
            mock_conn.bound = True
            mock_conn.closed = False
            mock_create.return_value = mock_conn

            await client.initialize()

            assert client._server is not None
            mock_create.assert_called()
            mock_bind.assert_called()

    @pytest.mark.asyncio
    async def test_initialize_failure(self, ldap_settings):
        with patch("fastapi_ldap.client.Server") as mock_server_class:
            mock_server_class.side_effect = Exception("Connection failed")

            client = LDAPClient(ldap_settings)
            with pytest.raises(LDAPConnectionError):
                await client.initialize()

    @pytest.mark.asyncio
    async def test_close(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.unbind = Mock()

        await client._pool.put(mock_conn)
        client._pool_size = 1

        await client.close()

        assert client._pool_size == 0
        mock_conn.unbind.assert_called()

    @pytest.mark.asyncio
    async def test_connection_context_manager(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False

        await client._pool.put(mock_conn)
        client._pool_size = 1

        async with client.connection() as conn:
            assert conn == mock_conn

        assert not client._pool.empty()

    @pytest.mark.asyncio
    async def test_connection_pool_exhausted(self, ldap_settings):
        ldap_settings.pool_size = 1
        ldap_settings.pool_timeout = 0.1
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)

        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        await client._pool.put(mock_conn)
        client._pool_size = 1

        empty_queue = asyncio.Queue(maxsize=1)
        client._pool = empty_queue

        with pytest.raises((LDAPConnectionError, LDAPError), match="Connection pool exhausted"):
            async with client.connection():
                pass

    @pytest.mark.asyncio
    async def test_authenticate_success(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False

        mock_entry = Mock()
        mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
        mock_entry.entry_attributes_as_dict = {
            "uid": ["testuser"],
            "mail": ["test@example.com"],
        }
        mock_conn.entries = [mock_entry]
        mock_conn.search = Mock(return_value=True)
        mock_conn.rebind = Mock(return_value=True)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await client.authenticate("testuser", "password")

            assert result is not None
            assert result["dn"] == "cn=testuser,dc=example,dc=com"
            assert result["uid"] == "testuser"

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.entries = []
        mock_conn.search = Mock(return_value=True)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await client.authenticate("nonexistent", "password")

            assert result is None

    @pytest.mark.asyncio
    async def test_authenticate_invalid_password(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False

        mock_entry = Mock()
        mock_entry.entry_dn = "cn=testuser,dc=example,dc=com"
        mock_entry.entry_attributes_as_dict = {"uid": ["testuser"]}
        mock_conn.entries = [mock_entry]
        mock_conn.search = Mock(return_value=True)
        mock_conn.rebind = Mock(side_effect=LDAPException("Invalid credentials"))

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await client.authenticate("testuser", "wrongpassword")

            assert result is None

    @pytest.mark.asyncio
    async def test_authenticate_empty_credentials(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        result = await client.authenticate("", "")
        assert result is None

        result = await client.authenticate("user", "")
        assert result is None

        result = await client.authenticate("", "pass")
        assert result is None

    def test_normalize_username(self):
        assert _normalize_username("jsmith@example.com") == "jsmith"
        assert _normalize_username("EXAMPLE\\jsmith") == "jsmith"
        assert _normalize_username("jsmith") == "jsmith"

    @pytest.mark.asyncio
    async def test_authenticate_normalizes_upn_for_search(self, ldap_settings):
        ldap_settings.user_search_filter = "(sAMAccountName={username})"
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.entries = []
        mock_conn.search = Mock(return_value=True)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            await client.authenticate("jsmith@example.com", "password")

            search_filter = mock_conn.search.call_args[0][1]
            assert search_filter == "(sAMAccountName=jsmith)"

    @pytest.mark.asyncio
    async def test_authenticate_normalizes_netbios_for_search(self, ldap_settings):
        ldap_settings.user_search_filter = "(sAMAccountName={username})"
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.entries = []
        mock_conn.search = Mock(return_value=True)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            await client.authenticate("EXAMPLE\\jsmith", "password")

            search_filter = mock_conn.search.call_args[0][1]
            assert search_filter == "(sAMAccountName=jsmith)"

    @pytest.mark.asyncio
    async def test_authenticate_escapes_filter_special_chars(self, ldap_settings):
        ldap_settings.user_search_filter = "(sAMAccountName={username})"
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.entries = []
        mock_conn.search = Mock(return_value=True)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            await client.authenticate("user*@example.com", "password")

            search_filter = mock_conn.search.call_args[0][1]
            assert search_filter == "(sAMAccountName=user\\2a)"

    @pytest.mark.asyncio
    async def test_get_user_groups_success(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False

        # Mock group entries
        mock_group1 = Mock()
        mock_group1.entry_attributes_as_dict = {"cn": ["admins"]}
        mock_group2 = Mock()
        mock_group2.entry_attributes_as_dict = {"cn": ["users"]}
        mock_conn.entries = [mock_group1, mock_group2]
        mock_conn.search = Mock(return_value=True)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            groups = await client.get_user_groups("cn=testuser,dc=example,dc=com")

            assert "admins" in groups
            assert "users" in groups

    @pytest.mark.asyncio
    async def test_get_user_groups_empty(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.entries = []
        mock_conn.search = Mock(return_value=True)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            groups = await client.get_user_groups("cn=testuser,dc=example,dc=com")

            assert groups == []

    @pytest.mark.asyncio
    async def test_get_user_groups_search_failure(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.search = Mock(return_value=False)

        with patch.object(client, "connection") as mock_ctx:
            mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            groups = await client.get_user_groups("cn=testuser,dc=example,dc=com")

            assert groups == []

    @pytest.mark.asyncio
    async def test_bind_connection_success(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = False
        mock_conn.rebind = Mock(return_value=True)

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=lambda executor, func, *args: func())

            await client._bind_connection(mock_conn)

            assert mock_conn.rebind.called
            mock_conn.rebind.assert_called_with(
                user=ldap_settings.bind_dn,
                password=ldap_settings.bind_password
            )

    @pytest.mark.asyncio
    async def test_bind_connection_retry(self, ldap_settings):
        ldap_settings.max_retries = 1
        ldap_settings.retry_delay = 0.01
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = False

        executor_call_count = 0
        def executor_side_effect(executor, func, *args):
            nonlocal executor_call_count
            executor_call_count += 1
            if executor_call_count == 1:
                raise LDAPSocketOpenError("Failed")
            return func()
        
        with patch("asyncio.get_event_loop") as mock_loop, patch(
            "asyncio.sleep", new_callable=AsyncMock
        ):
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=executor_side_effect)

            await client._bind_connection(mock_conn)
            
            assert executor_call_count == 2

    @pytest.mark.asyncio
    async def test_bind_connection_max_retries_exceeded(self, ldap_settings):
        ldap_settings.max_retries = 1
        ldap_settings.retry_delay = 0.01
        client = LDAPClient(ldap_settings)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = False

        with patch("asyncio.get_event_loop") as mock_loop, patch(
            "asyncio.sleep", new_callable=AsyncMock
        ):
            mock_loop.return_value.run_in_executor = AsyncMock(
                side_effect=LDAPSocketOpenError("Failed")
            )

            with pytest.raises(LDAPConnectionError):
                await client._bind_connection(mock_conn)

    @pytest.mark.asyncio
    async def test_anonymous_bind(self, ldap_settings_anonymous):
        client = LDAPClient(ldap_settings_anonymous)
        client._server = Mock(spec=Server)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = False
        mock_conn.rebind = Mock(return_value=True)

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=lambda executor, func, *args: func())

            await client._bind_connection(mock_conn)

            mock_conn.rebind.assert_called_with(user="", password="")

    @pytest.mark.asyncio
    async def test_initialize_with_ldaps_url(self, ldap_settings):
        ldap_settings.ldap_url = "ldaps://ldap.example.com:636"
        client = LDAPClient(ldap_settings)

        with patch("fastapi_ldap.client.Server") as mock_server_class, patch(
            "fastapi_ldap.client.Tls"
        ) as mock_tls_class, patch.object(
            client, "_create_connection", new_callable=AsyncMock
        ) as mock_create, patch.object(
            client, "_bind_connection", new_callable=AsyncMock
        ) as mock_bind:
            mock_server = Mock(spec=Server)
            mock_server_class.return_value = mock_server
            mock_tls = Mock()
            mock_tls_class.return_value = mock_tls

            mock_conn = Mock(spec=Connection)
            mock_conn.bound = True
            mock_conn.closed = False
            mock_create.return_value = mock_conn

            await client.initialize()

            mock_tls_class.assert_called_once()
            mock_server_class.assert_called_once()
            call_args = mock_server_class.call_args
            assert call_args[1]["tls"] == mock_tls
            assert call_args[1]["use_ssl"] is True

    @pytest.mark.asyncio
    async def test_close_with_unbind_errors(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._pool = asyncio.Queue()
        client._pool_size = 2

        mock_conn1 = Mock(spec=Connection)
        mock_conn1.bound = True
        mock_conn1.unbind = Mock(side_effect=Exception("Unbind failed"))

        mock_conn2 = Mock(spec=Connection)
        mock_conn2.bound = False

        await client._pool.put(mock_conn1)
        await client._pool.put(mock_conn2)

        await client.close()

        mock_conn1.unbind.assert_called_once()
        mock_conn2.unbind.assert_not_called()
        assert client._pool_size == 0

    @pytest.mark.asyncio
    async def test_connection_pool_timeout_creates_new(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        
        client._lock = asyncio.Lock()
        client._pool = asyncio.Queue()
        client._pool_size = 0
        
        ldap_settings.pool_timeout = 0.01

        with patch.object(client, "_create_connection", new_callable=AsyncMock) as mock_create, patch.object(
            client, "_bind_connection", new_callable=AsyncMock
        ) as mock_bind:
            mock_new_conn = Mock(spec=Connection)
            mock_new_conn.bound = False
            mock_new_conn.closed = False
            mock_create.return_value = mock_new_conn

            async with client.connection() as conn:
                assert conn is not None
                mock_create.assert_called_once()
                mock_bind.assert_called_once()

    @pytest.mark.asyncio
    async def test_connection_rebind_error_handling(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        client._lock = asyncio.Lock()
        client._pool = asyncio.Queue()
        
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = True
        mock_conn.closed = False
        mock_conn.rebind = Mock(side_effect=Exception("Rebind failed"))
        await client._pool.put(mock_conn)
        client._pool_size = 1

        async with client.connection() as conn:
            assert conn == mock_conn

    @pytest.mark.asyncio
    async def test_connection_unbound_returns_replacement(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        client._lock = asyncio.Lock()
        client._pool = asyncio.Queue()
        
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = False
        mock_conn.closed = True
        await client._pool.put(mock_conn)
        client._pool_size = 1

        with patch.object(client, "_create_connection", new_callable=AsyncMock) as mock_create:
            mock_new_conn = Mock(spec=Connection)
            mock_new_conn.bound = True
            mock_new_conn.closed = False
            mock_create.return_value = mock_new_conn

            async with client.connection() as conn:
                assert conn == mock_conn

    @pytest.mark.asyncio
    async def test_authenticate_exception_handling(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        client._lock = asyncio.Lock()
        client._pool = asyncio.Queue()

        with patch.object(client, "connection") as mock_conn_ctx:
            mock_conn = Mock(spec=Connection)
            mock_conn.search = Mock(side_effect=Exception("Search failed"))
            mock_conn.bound = True
            mock_conn.closed = False
            mock_conn_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_conn_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await client.authenticate("testuser", "password")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_user_groups_extract_username_from_dn(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        client._lock = asyncio.Lock()
        client._pool = asyncio.Queue()

        mock_conn = Mock(spec=Connection)
        mock_conn.search = Mock(return_value=True)
        mock_conn.entries = []
        mock_conn.bound = True
        mock_conn.closed = False

        with patch.object(client, "connection") as mock_conn_ctx:
            mock_conn_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_conn_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            groups = await client.get_user_groups("uid=testuser,ou=users,dc=example,dc=com")
            assert groups == []

            assert mock_conn.search.called

    @pytest.mark.asyncio
    async def test_get_user_groups_fallback_username_extraction(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        client._lock = asyncio.Lock()
        client._pool = asyncio.Queue()

        mock_conn = Mock(spec=Connection)
        mock_conn.search = Mock(return_value=True)
        mock_conn.entries = []
        mock_conn.bound = True
        mock_conn.closed = False

        with patch.object(client, "connection") as mock_conn_ctx:
            mock_conn_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_conn_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            groups = await client.get_user_groups("cn=testuser,ou=users,dc=example,dc=com")
            assert groups == []

    @pytest.mark.asyncio
    async def test_get_user_groups_exception_handling(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        client._lock = asyncio.Lock()
        client._pool = asyncio.Queue()

        with patch.object(client, "connection") as mock_conn_ctx:
            mock_conn_ctx.side_effect = Exception("Connection failed")

            groups = await client.get_user_groups("uid=testuser,ou=users,dc=example,dc=com", username="testuser")
            assert groups == []

    @pytest.mark.asyncio
    async def test_bind_connection_retry_exhausted(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)
        mock_conn = Mock(spec=Connection)
        mock_conn.bound = False
        mock_conn.rebind = Mock(side_effect=LDAPException("Bind failed"))

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(side_effect=lambda executor, func, *args: func())

            with pytest.raises(LDAPConnectionError, match="Failed to bind LDAP connection"):
                await client._bind_connection(mock_conn)

    @pytest.mark.asyncio
    async def test_populate_pool_handles_errors(self, ldap_settings):
        client = LDAPClient(ldap_settings)
        client._server = Mock(spec=Server)

        with patch.object(client, "_create_connection", new_callable=AsyncMock) as mock_create, patch.object(
            client, "_bind_connection", new_callable=AsyncMock
        ) as mock_bind:
            mock_create.side_effect = Exception("Connection failed")

            await client._populate_pool()

            assert mock_create.called

