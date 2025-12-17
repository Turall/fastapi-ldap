"""Custom exceptions for fastapi-ldap."""

from typing import Optional


class LDAPError(Exception):
    """Base exception for all LDAP-related errors."""

    def __init__(self, message: str, details: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class LDAPConnectionError(LDAPError):
    """Raised when LDAP connection fails."""

    pass


class LDAPAuthenticationError(LDAPError):
    """Raised when authentication fails.

    This exception is intentionally generic to prevent user enumeration.
    """

    pass


class LDAPAuthorizationError(LDAPError):
    """Raised when authorization fails (e.g., user lacks required groups/roles)."""

    pass


class LDAPConfigurationError(LDAPError):
    """Raised when LDAP configuration is invalid."""

    pass

