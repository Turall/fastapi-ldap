import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from typing import AsyncIterator, Optional, TypeVar, Union

from ldap3 import (
    ALL,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError  # type: ignore[import-untyped]
from ldap3.utils.conv import escape_filter_chars  # type: ignore[import-untyped]

from fastapi_ldap.config import LDAPSettings
from fastapi_ldap.exceptions import (
    LDAPConnectionError,
    LDAPError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _normalize_username(username: str) -> str:
    """Strip UPN or NetBIOS prefix for sAMAccountName-style searches."""
    if "@" in username:
        return username.split("@", 1)[0]
    if "\\" in username:
        return username.split("\\", 1)[-1]
    return username


def _normalize_ldap_attribute(value: object) -> Union[str, list[str]]:
    """Convert ldap3 attribute values: unwrap single-item lists, keep multi-valued."""
    if isinstance(value, list):
        if not value:
            return ""
        normalized = [str(v) for v in value]
        if len(normalized) == 1:
            return normalized[0]
        return normalized
    return str(value)


def _is_invalid_credentials(exc: LDAPException) -> bool:
    result = getattr(exc, "result", None)
    if isinstance(result, dict) and result.get("result") == 49:
        return True
    description = str(getattr(exc, "description", exc)).lower()
    return "invalidcredentials" in description or "invalid credentials" in description


def _connection_error(message: str, exc: Optional[Exception] = None) -> LDAPConnectionError:
    details = str(exc) if exc is not None else None
    return LDAPConnectionError(message, details=details)


class LDAPClient:
    """Async LDAP client with connection pooling and retry logic.

    This client is isolated from FastAPI and handles all LDAP operations.
    All IO is async-safe and does not block the event loop.
    """

    def __init__(self, settings: LDAPSettings) -> None:
        self.settings = settings
        self._server: Optional[Server] = None
        self._pool: asyncio.Queue[Connection] = asyncio.Queue(
            maxsize=settings.pool_size
        )
        self._pool_size = 0
        self._lock = asyncio.Lock()
        self._max_checkout_attempts = 3

    async def _run_in_executor(self, func: Callable[[], T]) -> T:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func)

    def _service_bind_credentials(self) -> tuple[str, str]:
        if self.settings.allow_anonymous:
            return "", ""
        return self.settings.bind_dn or "", self.settings.bind_password or ""

    def _is_connection_idle_expired(self, conn: Connection) -> bool:
        if self.settings.pool_max_idle_seconds <= 0:
            return False
        idle_since = getattr(conn, "_pool_idle_since", None)
        if idle_since is None:
            return False
        return (time.time() - idle_since) > self.settings.pool_max_idle_seconds

    async def _discard_connection(self, conn: Connection) -> None:
        with suppress(Exception):
            if conn.bound and not conn.closed:
                await self._run_in_executor(conn.unbind)

        async with self._lock:
            self._pool_size = max(0, self._pool_size - 1)

    async def _create_and_bind_connection(self) -> Connection:
        conn = await self._create_connection()
        await self._bind_connection(conn)
        conn._pool_idle_since = time.time()  # type: ignore[attr-defined]
        async with self._lock:
            self._pool_size += 1
        return conn

    async def _maybe_replenish_pool(self) -> None:
        async with self._lock:
            if self._pool_size >= self.settings.pool_size:
                return

        with suppress(Exception):
            conn = await self._create_and_bind_connection()
            conn._pool_idle_since = time.time()  # type: ignore[attr-defined]
            await self._pool.put(conn)

    async def _pool_has_capacity(self) -> bool:
        async with self._lock:
            return self._pool_size < self.settings.pool_size

    async def _raise_if_pool_exhausted(self) -> None:
        if not await self._pool_has_capacity():
            raise _connection_error("Connection pool exhausted and at maximum size")

    async def _acquire_new_connection(self) -> Connection:
        await self._raise_if_pool_exhausted()
        return await self._create_and_bind_connection()

    async def _prepare_pooled_connection(self, conn: Connection) -> Optional[Connection]:
        if self._is_connection_idle_expired(conn):
            logger.debug("Discarding idle-expired LDAP connection")
            await self._discard_connection(conn)
            return None

        try:
            await self._bind_connection(conn)
        except LDAPConnectionError:
            logger.warning(
                "Discarding LDAP connection after failed service rebind on checkout"
            )
            await self._discard_connection(conn)
            return None

        return conn

    async def _checkout_connection(self) -> Connection:
        last_error: Optional[Exception] = None

        for _ in range(self._max_checkout_attempts):
            if self._pool.empty():
                return await self._acquire_new_connection()

            try:
                conn = await asyncio.wait_for(
                    self._pool.get(), timeout=self.settings.pool_timeout
                )
            except asyncio.TimeoutError:
                return await self._acquire_new_connection()

            if conn is None:
                raise _connection_error("LDAP connection pool returned no connection")

            prepared = await self._prepare_pooled_connection(conn)
            if prepared is not None:
                return prepared

        raise _connection_error(
            "Unable to obtain a valid LDAP connection from pool",
            last_error,
        ) from last_error

    async def _return_connection_to_pool(self, conn: Connection) -> None:
        if not conn.bound or conn.closed:
            await self._discard_connection(conn)
            await self._maybe_replenish_pool()
            return

        try:
            await self._bind_connection(conn)
        except LDAPConnectionError:
            logger.warning(
                "Failed to return LDAP connection to pool; discarding",
                exc_info=True,
            )
            await self._discard_connection(conn)
            await self._maybe_replenish_pool()
            return

        conn._pool_idle_since = time.time()  # type: ignore[attr-defined]
        await self._pool.put(conn)

    def _create_server(self) -> Server:
        tls_config = None
        if self.settings.use_tls or self.settings.ldap_url.startswith("ldaps://"):
            tls_config = Tls(
                ca_certs_file=self.settings.tls_ca_cert_file,
                local_certificate_file=self.settings.tls_cert_file,
                local_private_key_file=self.settings.tls_key_file,
                validate=self.settings.tls_require_cert,
            )

        return Server(
            self.settings.ldap_url,
            use_ssl=self.settings.ldap_url.startswith("ldaps://"),
            tls=tls_config,
            get_info=ALL,
        )

    async def initialize(self) -> None:
        try:
            self._server = self._create_server()
            await self._populate_pool()
            logger.info(
                "LDAP client initialized",
                extra={
                    "ldap_url": self.settings.ldap_url,
                    "pool_size": self.settings.pool_size,
                },
            )
        except LDAPConnectionError:
            raise
        except Exception as exc:
            logger.error("Failed to initialize LDAP client", exc_info=True)
            raise _connection_error(
                f"Failed to initialize LDAP client: {exc}",
                exc,
            ) from exc

    async def close(self) -> None:
        async with self._lock:
            while not self._pool.empty():
                with suppress(Exception):
                    conn = await asyncio.wait_for(self._pool.get(), timeout=1.0)
                    if conn.bound:
                        conn.unbind()
            self._pool_size = 0
            logger.info("LDAP client closed")

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[Connection]:
        conn = await self._checkout_connection()
        try:
            yield conn
        except LDAPConnectionError:
            raise
        except LDAPException as exc:
            logger.error("LDAP operation failed", exc_info=True)
            raise _connection_error(f"LDAP operation failed: {exc}", exc) from exc
        except LDAPError:
            raise
        except Exception as exc:
            logger.error("Unexpected error in LDAP operation", exc_info=True)
            raise LDAPError(f"Unexpected error: {exc}", details=str(exc)) from exc
        finally:
            await self._return_connection_to_pool(conn)

    async def _create_connection(self) -> Connection:
        if self._server is None:
            raise _connection_error("LDAP client not initialized")

        return await self._run_in_executor(
            lambda: Connection(
                self._server,
                auto_bind=False,
                raise_exceptions=True,
            )
        )

    async def _bind_connection(self, conn: Connection) -> None:
        if self._server is None:
            raise _connection_error("LDAP client not initialized")

        bind_dn, bind_password = self._service_bind_credentials()
        last_error: Optional[Exception] = None

        for attempt in range(self.settings.max_retries + 1):
            try:
                await self._run_in_executor(
                    lambda: conn.rebind(user=bind_dn, password=bind_password)
                )
                logger.debug("LDAP connection bound successfully")
                return
            except (LDAPSocketOpenError, LDAPException) as exc:
                last_error = exc
                if attempt < self.settings.max_retries:
                    await asyncio.sleep(self.settings.retry_delay * (attempt + 1))
                    logger.warning(
                        "LDAP bind failed, retrying (attempt %s/%s)",
                        attempt + 1,
                        self.settings.max_retries,
                    )
                else:
                    logger.error("LDAP bind failed after retries", exc_info=True)

        raise _connection_error(
            f"Failed to bind LDAP connection after {self.settings.max_retries + 1} attempts",
            last_error,
        ) from last_error

    async def _populate_pool(self) -> None:
        for _ in range(min(2, self.settings.pool_size)):
            try:
                conn = await self._create_and_bind_connection()
                await self._pool.put(conn)
            except Exception as exc:
                logger.warning(
                    "Failed to pre-populate connection: %s", exc, exc_info=True
                )

    async def _with_connection_retry(
        self,
        operation: Callable[[], Awaitable[T]],
        *,
        log_message: str,
    ) -> T:
        for attempt in range(2):
            try:
                return await operation()
            except LDAPConnectionError:
                if attempt == 0:
                    logger.warning("%s, retrying once", log_message, exc_info=True)
                    continue
                raise
            except LDAPSocketOpenError as exc:
                if attempt == 0:
                    logger.warning("%s, retrying once", log_message, exc_info=True)
                    continue
                raise _connection_error(
                    f"LDAP socket error: {exc}",
                    exc,
                ) from exc

        raise _connection_error("LDAP operation failed after retry")

    async def _authenticate_once(
        self, username: str, password: str, sam: str
    ) -> Optional[dict[str, Union[str, list[str]]]]:
        async with self.connection() as conn:
            search_filter = self.settings.user_search_filter.format(
                username=escape_filter_chars(sam)
            )
            search_base = self.settings.user_search_base or self.settings.ldap_base_dn

            success = await self._run_in_executor(
                lambda: conn.search(
                    search_base,
                    search_filter,
                    attributes=["*"],
                    size_limit=1,
                )
            )

            if not success or not conn.entries:
                logger.debug("User not found: %s", username)
                return None

            user_dn = conn.entries[0].entry_dn
            user_attrs = conn.entries[0].entry_attributes_as_dict

            try:
                await self._run_in_executor(
                    lambda: conn.rebind(user=user_dn, password=password)
                )
            except LDAPException as exc:
                if _is_invalid_credentials(exc):
                    logger.info("Authentication failed for user: %s", username)
                    return None
                raise

            logger.info("User authenticated successfully: %s", username)
            return {
                "dn": user_dn,
                **{k: _normalize_ldap_attribute(v) for k, v in user_attrs.items()},
            }

    async def authenticate(
        self, username: str, password: str
    ) -> Optional[dict[str, Union[str, list[str]]]]:
        if not username or not password:
            return None

        sam = _normalize_username(username)

        try:
            return await self._with_connection_retry(
                lambda: self._authenticate_once(username, password, sam),
                log_message="LDAP connection error during authentication",
            )
        except LDAPConnectionError:
            raise
        except Exception:
            logger.error("Error during authentication", exc_info=True)
            return None

    def _resolve_group_username(self, user_dn: str, username: str) -> str:
        if username or not user_dn:
            return username

        for part in user_dn.split(","):
            if part.startswith("uid="):
                return part.split("=")[1]

        return user_dn.split(",")[0].split("=")[-1]

    async def _fetch_user_groups(self, user_dn: str, username: str) -> list[str]:
        async with self.connection() as conn:
            group_username = _normalize_username(username) if username else username
            search_filter = self.settings.group_search_filter.format(
                user_dn=escape_filter_chars(user_dn),
                username=escape_filter_chars(group_username),
            )
            search_base = (
                self.settings.group_search_base or self.settings.ldap_base_dn
            )

            success = await self._run_in_executor(
                lambda: conn.search(
                    search_base,
                    search_filter,
                    attributes=[self.settings.group_attribute],
                )
            )

            if not success:
                logger.warning("Group search failed for user: %s", user_dn)
                return []

            groups: list[str] = []
            for entry in conn.entries:
                group_attr = entry.entry_attributes_as_dict.get(
                    self.settings.group_attribute, []
                )
                if not group_attr:
                    continue
                group_name = group_attr[0] if isinstance(group_attr, list) else group_attr
                groups.append(str(group_name))

            return groups

    async def get_user_groups(self, user_dn: str, username: str = "") -> list[str]:
        username = self._resolve_group_username(user_dn, username)

        try:
            return await self._fetch_user_groups(user_dn, username)
        except Exception:
            logger.error("Error fetching user groups", exc_info=True)
            return []
