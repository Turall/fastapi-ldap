"""
fastapi-ldap: Production-ready LDAP authentication and authorization for FastAPI.

This package provides async-first LDAP authentication with safe defaults,
enterprise LDAP/Active Directory compatibility, and Kubernetes-friendly design.
"""

from fastapi_ldap.auth import LDAPAuth, get_current_user, require_groups, require_roles
from fastapi_ldap.client import LDAPClient
from fastapi_ldap.config import LDAPSettings
from fastapi_ldap.exceptions import (
    LDAPAuthenticationError,
    LDAPAuthorizationError,
    LDAPConnectionError,
    LDAPError,
)
from fastapi_ldap.health import health_check, readiness_check
from fastapi_ldap.models import LDAPUser

__version__ = "0.1.0"

__all__ = [
    "LDAPAuth",
    "LDAPClient",
    "LDAPSettings",
    "LDAPUser",
    "LDAPError",
    "LDAPAuthenticationError",
    "LDAPAuthorizationError",
    "LDAPConnectionError",
    "get_current_user",
    "require_groups",
    "require_roles",
    "health_check",
    "readiness_check",
]

