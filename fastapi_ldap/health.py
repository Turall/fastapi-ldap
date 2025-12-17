"""Health and readiness checks for LDAP service.

These endpoints are Kubernetes-friendly and follow standard health check patterns.
"""

import logging
from typing import Optional

from fastapi import HTTPException, status

from fastapi_ldap.client import LDAPClient
from fastapi_ldap.exceptions import LDAPConnectionError

logger = logging.getLogger(__name__)

# Global client reference (set by auth layer)
_client: Optional[LDAPClient] = None


def set_client(client: LDAPClient) -> None:
    global _client
    _client = client


async def health_check() -> dict[str, str]:
    """Health check endpoint.

    Returns basic health status. Does not check LDAP connectivity.

    Returns:
        Health status dictionary

    Usage:
        @app.get("/health")
        async def health():
            return await health_check()
    """
    return {"status": "healthy"}


async def readiness_check() -> dict[str, str]:
    global _client

    if not _client:
        logger.warning("LDAP client not initialized")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LDAP client not initialized",
        )

    try:
        async with _client.connection():
            return {"status": "ready", "service": "ldap"}
    except LDAPConnectionError as e:
        logger.warning("LDAP readiness check failed", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LDAP service not ready",
        ) from e
    except Exception as e:
        logger.error("Unexpected error in readiness check", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable",
        ) from e

