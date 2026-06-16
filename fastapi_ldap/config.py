from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LDAPSettings(BaseSettings):

    ldap_url: str = Field(
        ...,
        description="LDAP server URL (e.g., 'ldaps://ldap.example.com:636')",
    )
    ldap_base_dn: str = Field(
        ...,
        description="Base DN for LDAP searches (e.g., 'dc=example,dc=com')",
    )

    bind_dn: Optional[str] = Field(
        default=None,
        description="DN for bind user (service account). Required unless allow_anonymous=True.",
    )
    bind_password: Optional[str] = Field(
        default=None,
        description="Password for bind user. Required unless allow_anonymous=True.",
    )
    allow_anonymous: bool = Field(
        default=False,
        description="Allow anonymous binds. Default: False (security-first).",
    )

    use_tls: bool = Field(
        default=True,
        description="Enable TLS by default. Set to False only for testing.",
    )
    tls_ca_cert_file: Optional[str] = Field(
        default=None,
        description="Path to CA certificate file for TLS verification.",
    )
    tls_cert_file: Optional[str] = Field(
        default=None,
        description="Path to client certificate file for TLS.",
    )
    tls_key_file: Optional[str] = Field(
        default=None,
        description="Path to client key file for TLS.",
    )
    tls_require_cert: bool = Field(
        default=True,
        description="Require valid certificate. Default: True (security-first).",
    )

    user_search_filter: str = Field(
        default="(uid={username})",
        description="LDAP filter for user search. {username} will be replaced.",
    )
    user_search_base: Optional[str] = Field(
        default=None,
        description="Base DN for user searches. Defaults to ldap_base_dn if not set.",
    )
    group_search_filter: str = Field(
        default="(member={user_dn})",
        description="LDAP filter for group membership. {user_dn} will be replaced.",
    )
    group_search_base: Optional[str] = Field(
        default=None,
        description="Base DN for group searches. Defaults to ldap_base_dn if not set.",
    )
    group_attribute: str = Field(
        default="cn",
        description="Attribute name for group names.",
    )

    pool_size: int = Field(
        default=10,
        ge=1,
        description="Maximum number of connections in pool.",
    )
    pool_timeout: float = Field(
        default=30.0,
        ge=0.0,
        description="Timeout for acquiring connection from pool (seconds).",
    )
    pool_max_idle_seconds: float = Field(
        default=1800.0,
        ge=0.0,
        description=(
            "Discard pooled connections idle longer than this (seconds). "
            "Set to 0 to disable. Helps avoid stale AD/LDAP idle disconnects."
        ),
    )

    connect_timeout: float = Field(
        default=10.0,
        ge=0.0,
        description="Connection timeout (seconds).",
    )
    operation_timeout: float = Field(
        default=30.0,
        ge=0.0,
        description="LDAP operation timeout (seconds).",
    )

    max_retries: int = Field(
        default=3,
        ge=0,
        description="Maximum number of retry attempts for failed operations.",
    )
    retry_delay: float = Field(
        default=1.0,
        ge=0.0,
        description="Delay between retries (seconds).",
    )

    cache_enabled: bool = Field(
        default=False,
        description="Enable caching of authentication results.",
    )
    cache_ttl: int = Field(
        default=300,
        ge=1,
        description="Cache TTL in seconds. Only used if cache_enabled=True.",
    )

    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR).",
    )

    model_config = SettingsConfigDict(
        env_prefix="LDAP_",
        case_sensitive=False,
        extra="forbid",
    )

    def model_post_init(self, __context: object) -> None:
        if not self.allow_anonymous:
            if not self.bind_dn or not self.bind_password:
                raise ValueError(
                    "bind_dn and bind_password are required when allow_anonymous=False. "
                    "Set allow_anonymous=True only if you understand the security implications."
                )

        if self.use_tls is True and "ldaps://" not in self.ldap_url.lower() and "ldap://" in self.ldap_url.lower():
            raise ValueError(
                "TLS is required by default. Set use_tls=False for testing or use ldaps:// URL. "
                "Disable TLS only for testing in secure environments."
            )

        if self.user_search_base is None:
            self.user_search_base = self.ldap_base_dn
        if self.group_search_base is None:
            self.group_search_base = self.ldap_base_dn

