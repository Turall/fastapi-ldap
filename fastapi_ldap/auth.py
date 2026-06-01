import logging
from contextlib import asynccontextmanager
from typing import Annotated, Any, AsyncIterator, Callable, Coroutine, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from fastapi_ldap.cache import AuthCache
from fastapi_ldap.client import LDAPClient
from fastapi_ldap.config import LDAPSettings
from fastapi_ldap.exceptions import (
    LDAPConnectionError,
)
from fastapi_ldap.models import LDAPUser

logger = logging.getLogger(__name__)

# Global instances (initialized in lifespan)
_client: Optional[LDAPClient] = None
_cache: Optional[AuthCache] = None
_settings: Optional[LDAPSettings] = None

# HTTP Basic Auth scheme
_security = HTTPBasic()


class LDAPAuth:
    """LDAP authentication manager for FastAPI.

    This class manages LDAP client lifecycle and provides FastAPI dependencies.
    """

    def __init__(self, settings: LDAPSettings) -> None:
        self.settings = settings
        self._client: Optional[LDAPClient] = None
        self._cache: Optional[AuthCache] = None

    @asynccontextmanager
    async def lifespan(self, app: object) -> AsyncIterator[None]:
        global _client, _cache, _settings

        try:
            self._client = LDAPClient(self.settings)
            await self._client.initialize()

            if self.settings.cache_enabled:
                self._cache = AuthCache(ttl=self.settings.cache_ttl)

            _client = self._client
            _cache = self._cache
            _settings = self.settings

            from fastapi_ldap.health import set_client
            set_client(self._client)

            logger.info("LDAP authentication initialized")

            yield

        finally:
            if self._client:
                await self._client.close()
            _client = None
            _cache = None
            _settings = None
            logger.info("LDAP authentication shutdown")

    async def authenticate_user(
        self, username: str, password: str
    ) -> Optional[LDAPUser]:
        client = self._client if self._client else _client
        cache = self._cache if self._cache else _cache

        if not client:
            raise LDAPConnectionError("LDAP client not initialized")

        cache_key = f"auth:{username}"
        if cache:
            cached_user = await cache.get(cache_key)
            if cached_user:
                logger.debug(f"Cache hit for user: {username}")
                return cached_user  # type: ignore

        user_attrs = await client.authenticate(username, password)
        if not user_attrs:
            return None

        user_dn = user_attrs.get("dn", "")
        uid_value = user_attrs.get("uid") or user_attrs.get("sAMAccountName")
        if isinstance(uid_value, list) and uid_value:
            user_username = uid_value[0]
        elif uid_value:
            user_username = uid_value
        else:
            user_username = username
        groups = await client.get_user_groups(user_dn, username=user_username)

        user = LDAPUser(
            dn=user_dn,
            username=user_attrs.get("uid") or user_attrs.get("sAMAccountName") or username,
            email=user_attrs.get("mail") or user_attrs.get("email"),
            display_name=user_attrs.get("displayName") or user_attrs.get("cn"),
            groups=frozenset(groups),
            attributes={
                k: v[0] if isinstance(v, list) and v else str(v)
                for k, v in user_attrs.items()
                if k not in ["dn", "uid", "sAMAccountName", "mail", "email", "displayName", "cn"]
            },
        )

        if cache:
            await cache.set(cache_key, user)

        return user


async def get_current_user(
    credentials: Annotated[HTTPBasicCredentials, Security(_security)],
) -> LDAPUser:
    """FastAPI dependency to get current authenticated user.

    Usage:
        @app.get("/protected")
        async def protected_route(user: LDAPUser = Depends(get_current_user)):
            return {"user": user.username}

    Raises:
        HTTPException: 401 if authentication fails
        HTTPException: 503 if LDAP is unavailable
    """
    if not _client:
        logger.error("LDAP client not initialized")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LDAP authentication service unavailable",
        )

    try:
        cache_key = f"auth:{credentials.username}"
        if _cache:
            cached_user = await _cache.get(cache_key)
            if cached_user:
                logger.debug(f"Cache hit for user: {credentials.username}")
                return cached_user  # type: ignore

        user_attrs = await _client.authenticate(credentials.username, credentials.password)
        if not user_attrs:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

        user_dn = user_attrs.get("dn", "")
        uid_value = user_attrs.get("uid") or user_attrs.get("sAMAccountName")
        if isinstance(uid_value, list) and uid_value:
            user_username = uid_value[0]
        elif uid_value:
            user_username = str(uid_value)
        else:
            user_username = credentials.username
        groups = await _client.get_user_groups(user_dn, username=user_username)

        # Extract username for LDAPUser, handling both list and string formats
        uid_for_username = user_attrs.get("uid") or user_attrs.get("sAMAccountName")
        if isinstance(uid_for_username, list) and uid_for_username:
            username_for_user = uid_for_username[0]
        elif uid_for_username:
            username_for_user = str(uid_for_username)
        else:
            username_for_user = credentials.username
        
        user = LDAPUser(
            dn=user_dn,
            username=username_for_user,
            email=user_attrs.get("mail") or user_attrs.get("email"),
            display_name=user_attrs.get("displayName") or user_attrs.get("cn"),
            groups=frozenset(groups),
            attributes={
                k: v[0] if isinstance(v, list) and v else str(v)
                for k, v in user_attrs.items()
                if k not in ["dn", "uid", "sAMAccountName", "mail", "email", "displayName", "cn"]
            },
        )

        if _cache:
            await _cache.set(cache_key, user)

        return user

    except HTTPException:
        raise
    except LDAPConnectionError as e:
        logger.error("LDAP connection error", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LDAP service unavailable",
        ) from e
    except Exception as e:
        logger.error("Unexpected authentication error", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        ) from e


def require_groups(*groups: str) -> Callable[[LDAPUser], Coroutine[Any, Any, LDAPUser]]:
    """FastAPI dependency factory to require specific groups.

    Usage:
        @app.get("/admin")
        async def admin_route(
            user: LDAPUser = Depends(require_groups("admins", "superusers"))
        ):
            return {"message": "Admin access granted"}

    Args:
        *groups: Required group names

    Returns:
        FastAPI dependency function
    """
    async def group_check(
        user: LDAPUser = Depends(get_current_user),
    ) -> LDAPUser:
        required_groups = set(groups)
        if not user.has_any_group(required_groups):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User does not belong to required groups: {', '.join(groups)}",
            )
        return user

    return group_check


def require_roles(*roles: str) -> Callable[[LDAPUser], Coroutine[Any, Any, LDAPUser]]:
    """FastAPI dependency factory to require specific roles.

    Note: Roles are treated as groups in LDAP. This is an alias for require_groups
    for semantic clarity.

    Usage:
        @app.get("/api/data")
        async def data_route(
            user: LDAPUser = Depends(require_roles("data-reader"))
        ):
            return {"data": "..."}

    Args:
        *roles: Required role names (treated as groups)

    Returns:
        FastAPI dependency function
    """
    return require_groups(*roles)

