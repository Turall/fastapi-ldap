import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from typing import AsyncIterator, Optional

from ldap3 import (
    ALL,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError  # type: ignore[import-untyped]

from fastapi_ldap.config import LDAPSettings
from fastapi_ldap.exceptions import (
    LDAPConnectionError,
    LDAPError,
)

logger = logging.getLogger(__name__)


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

    async def initialize(self) -> None:
        try:
            tls_config = None
            if self.settings.use_tls or self.settings.ldap_url.startswith("ldaps://"):
                tls_config = Tls(
                    ca_certs_file=self.settings.tls_ca_cert_file,
                    local_certificate_file=self.settings.tls_cert_file,
                    local_private_key_file=self.settings.tls_key_file,
                    validate=self.settings.tls_require_cert,
                )

            self._server = Server(
                self.settings.ldap_url,
                use_ssl=self.settings.ldap_url.startswith("ldaps://"),
                tls=tls_config,
                get_info=ALL,
            )

            await self._populate_pool()

            logger.info(
                "LDAP client initialized",
                extra={
                    "ldap_url": self.settings.ldap_url,
                    "pool_size": self.settings.pool_size,
                },
            )
        except Exception as e:
            logger.error("Failed to initialize LDAP client", exc_info=True)
            raise LDAPConnectionError(
                f"Failed to initialize LDAP client: {e}",
                details=str(e),
            ) from e

    async def close(self) -> None:
        async with self._lock:
            while not self._pool.empty():
                try:
                    conn = await asyncio.wait_for(
                        self._pool.get(), timeout=1.0
                    )
                    if conn.bound:
                        conn.unbind()
                except Exception as e:
                    logger.warning("Error closing connection", exc_info=True)
            self._pool_size = 0
            logger.info("LDAP client closed")

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[Connection]:
        conn: Optional[Connection] = None
        try:
            try:
                conn = await asyncio.wait_for(
                    self._pool.get(), timeout=self.settings.pool_timeout
                )
            except asyncio.TimeoutError:
                async with self._lock:
                    if self._pool_size < self.settings.pool_size:
                        conn = await self._create_connection()
                        self._pool_size += 1
                    else:
                        raise LDAPConnectionError(
                            "Connection pool exhausted and at maximum size"
                        )

            if conn is not None and not conn.bound:
                await self._bind_connection(conn)

            yield conn

        except LDAPException as e:
            logger.error("LDAP operation failed", exc_info=True)
            raise LDAPConnectionError(
                f"LDAP operation failed: {e}",
                details=str(e),
            ) from e
        except Exception as e:
            logger.error("Unexpected error in LDAP operation", exc_info=True)
            raise LDAPError(
                f"Unexpected error: {e}",
                details=str(e),
            ) from e
        finally:
            # Check and return connection to pool if still valid
            if conn is not None:
                try:
                    if conn.bound and not conn.closed:
                        # Rebind to service account to ensure connection is in clean state
                        try:
                            loop = asyncio.get_event_loop()
                            if self.settings.allow_anonymous:
                                bind_dn = ""
                                bind_password = ""
                            else:
                                bind_dn = self.settings.bind_dn or ""
                                bind_password = self.settings.bind_password or ""
                            
                            await loop.run_in_executor(
                                None,
                                lambda: conn.rebind(user=bind_dn, password=bind_password),
                            )
                            # Connection is now bound as service account, safe to return
                            await self._pool.put(conn)
                        except Exception as rebind_error:
                            # If rebind fails connection might be in bad state
                            logger.debug(f"Failed to rebind connection to service account: {rebind_error}")
                            # Don't return bad connection to pool
                            async with self._lock:
                                self._pool_size -= 1
                                # Create replacement if under limit
                                if self._pool_size < self.settings.pool_size:
                                    with suppress(Exception):
                                        new_conn = await self._create_connection()
                                        await self._pool.put(new_conn)
                                        self._pool_size += 1

                    else:
                        async with self._lock:
                            self._pool_size -= 1
                            if self._pool_size < self.settings.pool_size:
                                with suppress(Exception):
                                    new_conn = await self._create_connection()
                                    await self._pool.put(new_conn)
                                    self._pool_size += 1
                except Exception as e:
                    logger.warning("Error returning connection to pool", exc_info=True)
                    async with self._lock:
                        self._pool_size -= 1

    async def _create_connection(self) -> Connection:
        if self._server is None:
            raise LDAPConnectionError("LDAP client not initialized")
        
        server = self._server
        
        loop = asyncio.get_event_loop()
        conn = await loop.run_in_executor(
            None,
            lambda: Connection(
                server,
                auto_bind=False,
                raise_exceptions=True,
            ),
        )

        return conn

    async def _bind_connection(self, conn: Connection) -> None:
        if self._server is None:
            raise LDAPConnectionError("LDAP client not initialized")

        last_error: Optional[Exception] = None

        for attempt in range(self.settings.max_retries + 1):
            try:
                loop = asyncio.get_event_loop()

                if self.settings.allow_anonymous:
                    bind_dn = ""
                    bind_password = ""
                else:
                    bind_dn = self.settings.bind_dn or ""
                    bind_password = self.settings.bind_password or ""

                await loop.run_in_executor(
                    None,
                    lambda: conn.rebind(
                        user=bind_dn,
                        password=bind_password,
                    ),
                )

                logger.debug("LDAP connection bound successfully")
                return

            except (LDAPSocketOpenError, LDAPException) as e:
                last_error = e
                if attempt < self.settings.max_retries:
                    await asyncio.sleep(
                        self.settings.retry_delay * (attempt + 1)
                    )
                    logger.warning(
                        f"LDAP bind failed, retrying (attempt {attempt + 1}/{self.settings.max_retries})"
                    )
                else:
                    logger.error("LDAP bind failed after retries", exc_info=True)

        raise LDAPConnectionError(
            f"Failed to bind LDAP connection after {self.settings.max_retries + 1} attempts",
            details=str(last_error),
        ) from last_error

    async def _populate_pool(self) -> None:
        for _ in range(min(2, self.settings.pool_size)):
            try:
                conn = await self._create_connection()
                await self._bind_connection(conn)
                await self._pool.put(conn)
                self._pool_size += 1
            except Exception as e:
                logger.warning(
                    f"Failed to pre-populate connection: {e}",
                    exc_info=True,
                )

    async def authenticate(
        self, username: str, password: str
    ) -> Optional[dict[str, str]]:
        if not username or not password:
            return None

        try:
            async with self.connection() as conn:
                loop = asyncio.get_event_loop()

                search_filter = self.settings.user_search_filter.format(
                    username=username
                )
                search_base = self.settings.user_search_base or self.settings.ldap_base_dn

                success = await loop.run_in_executor(
                    None,
                    lambda: conn.search(
                        search_base,
                        search_filter,
                        attributes=["*"],
                        size_limit=1,
                    ),
                )

                if not success or not conn.entries:
                    logger.debug(f"User not found: {username}")
                    return None

                user_dn = conn.entries[0].entry_dn
                user_attrs = conn.entries[0].entry_attributes_as_dict

                try:
                    await loop.run_in_executor(
                        None,
                        lambda: conn.rebind(user=user_dn, password=password),
                    )

                    logger.info(f"User authenticated successfully: {username}")
                    return {
                        "dn": user_dn,
                        **{k: v[0] if isinstance(v, list) and v else v for k, v in user_attrs.items()},
                    }

                except LDAPException:
                    logger.debug(f"Authentication failed for user: {username}")
                    return None

        except Exception as e:
            logger.error("Error during authentication", exc_info=True)
            return None

    async def get_user_groups(self, user_dn: str, username: str = "") -> list[str]:
        try:
            async with self.connection() as conn:
                loop = asyncio.get_event_loop()

                # Extract username from DN if not provided (e.g., uid=username,ou=users,dc=example,dc=com)
                if not username and user_dn:
                    # Try to extract uid from DN
                    for part in user_dn.split(","):
                        if part.startswith("uid="):
                            username = part.split("=")[1]
                            break
                    if not username:
                        username = user_dn.split(",")[0].split("=")[-1]

                # Format search filter with both user_dn and username
                search_filter = self.settings.group_search_filter.format(
                    user_dn=user_dn,
                    username=username
                )
                search_base = (
                    self.settings.group_search_base or self.settings.ldap_base_dn
                )

                success = await loop.run_in_executor(
                    None,
                    lambda: conn.search(
                        search_base,
                        search_filter,
                        attributes=[self.settings.group_attribute],
                    ),
                )

                if not success:
                    logger.warning(f"Group search failed for user: {user_dn}")
                    return []

                groups = []
                for entry in conn.entries:
                    group_attr = entry.entry_attributes_as_dict.get(
                        self.settings.group_attribute, []
                    )
                    if group_attr:
                        group_name = (
                            group_attr[0]
                            if isinstance(group_attr, list)
                            else group_attr
                        )
                        groups.append(str(group_name))

                return groups

        except Exception as e:
            logger.error("Error fetching user groups", exc_info=True)
            return []

