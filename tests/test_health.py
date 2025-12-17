from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException, status

from fastapi_ldap.client import LDAPClient
from fastapi_ldap.exceptions import LDAPConnectionError
from fastapi_ldap.health import health_check, readiness_check, set_client

class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check_success(self):
        result = await health_check()
        assert result == {"status": "healthy"}

class TestReadinessCheck:
    @pytest.mark.asyncio
    async def test_readiness_check_success(self):
        mock_client = AsyncMock(spec=LDAPClient)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=Mock())
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_client.connection = Mock(return_value=mock_ctx)

        set_client(mock_client)

        result = await readiness_check()

        assert result == {"status": "ready", "service": "ldap"}
        mock_client.connection.assert_called_once()

    @pytest.mark.asyncio
    async def test_readiness_check_client_not_initialized(self):
        set_client(None)

        with pytest.raises(HTTPException) as exc_info:
            await readiness_check()

        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_readiness_check_connection_error(self):
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.connection = Mock(side_effect=LDAPConnectionError("Connection failed"))

        set_client(mock_client)

        with pytest.raises(HTTPException) as exc_info:
            await readiness_check()

        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_readiness_check_unexpected_error(self):
        mock_client = AsyncMock(spec=LDAPClient)
        mock_client.connection = Mock(side_effect=Exception("Unexpected error"))

        set_client(mock_client)

        with pytest.raises(HTTPException) as exc_info:
            await readiness_check()

        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

class TestSetClient:
    def test_set_client(self):
        mock_client = Mock(spec=LDAPClient)
        set_client(mock_client)

        assert True

