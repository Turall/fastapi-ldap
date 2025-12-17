[![codecov](https://codecov.io/github/turall/fastapi-ldap/graph/badge.svg?token=NA6MHAOAL2)](https://codecov.io/github/turall/fastapi-ldap)

# fastapi-ldap

Production-ready LDAP authentication and authorization for FastAPI.

## Features

- ✅ **Async-first design** - No blocking LDAP calls in the event loop
- ✅ **Security by default** - TLS enabled, no anonymous binds, fail-closed behavior
- ✅ **Enterprise-ready** - LDAP and Active Directory compatible
- ✅ **Kubernetes-friendly** - Health and readiness checks included
- ✅ **FastAPI-native** - Idiomatic dependencies and lifespan management
- ✅ **Optional caching** - Configurable TTL for authentication results
- ✅ **Type-safe** - Full type hints, Python 3.10+

## Installation

```bash
pip install fastapi-ldap
```

## Quick Start

```python
from fastapi import Depends, FastAPI
from fastapi_ldap import (
    LDAPAuth,
    LDAPSettings,
    get_current_user,
    health_check,
    readiness_check,
    require_groups,
)
from fastapi_ldap.models import LDAPUser

# Configure LDAP settings
settings = LDAPSettings(
    ldap_url="ldaps://ldap.example.com:636",
    ldap_base_dn="dc=example,dc=com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="secret",
)

# Create LDAP auth instance
ldap_auth = LDAPAuth(settings)

# Create FastAPI app with lifespan
app = FastAPI(lifespan=ldap_auth.lifespan)

# Health checks
@app.get("/health")
async def health():
    return await health_check()

@app.get("/ready")
async def ready():
    return await readiness_check()

# Protected route
@app.get("/protected")
async def protected_route(user: LDAPUser = Depends(get_current_user)):
    return {
        "username": user.username,
        "email": user.email,
        "groups": list(user.groups),
    }

# Route requiring specific groups
@app.get("/admin")
async def admin_route(
    user: LDAPUser = Depends(require_groups("admins", "superusers"))
):
    return {"message": f"Welcome, {user.username}!"}
```

## Configuration

Configuration can be provided via environment variables (prefixed with `LDAP_`) or directly:

```python
from fastapi_ldap import LDAPSettings

settings = LDAPSettings(
    # Required
    ldap_url="ldaps://ldap.example.com:636",
    ldap_base_dn="dc=example,dc=com",
    
    # Bind credentials (required unless allow_anonymous=True)
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="secret",
    
    # TLS (enabled by default)
    use_tls=True,
    tls_ca_cert_file="/path/to/ca.crt",
    
    # Search configuration
    user_search_filter="(uid={username})",  # Default for OpenLDAP
    # user_search_filter="(sAMAccountName={username})",  # For Active Directory
    
    # Connection pool
    pool_size=10,
    pool_timeout=30.0,
    
    # Caching (optional)
    cache_enabled=True,
    cache_ttl=300,  # 5 minutes
)
```

### Environment Variables

All settings can be configured via environment variables:

```bash
export LDAP_URL="ldaps://ldap.example.com:636"
export LDAP_BASE_DN="dc=example,dc=com"
export LDAP_BIND_DN="cn=admin,dc=example,dc=com"
export LDAP_BIND_PASSWORD="secret"
export LDAP_CACHE_ENABLED="true"
export LDAP_CACHE_TTL="300"
```

**Important: Passwords with Special Characters**

If your password contains special characters (e.g., `$`, `%`, `&`, `*`, `(`, `)`, `\`, etc.), make sure to properly quote the environment variable to prevent shell interpretation:

```bash
# ✅ Correct - use single quotes to prevent shell interpretation
export LDAP_BIND_PASSWORD='pass$word%test&more'

# ✅ Also correct - use double quotes and escape special chars
export LDAP_BIND_PASSWORD="pass\$word%test&more"

# ❌ Wrong - shell will interpret $word as a variable
export LDAP_BIND_PASSWORD=pass$word
```

**Note:** LDAP passwords can contain any characters, including special ones and Unicode. The `fastapi-ldap` library accepts passwords as-is without validation, as LDAP servers handle password validation. The only requirement is that passwords are properly set in environment variables to avoid shell interpretation issues.

## Active Directory Example

```python
settings = LDAPSettings(
    ldap_url="ldaps://ad.example.com:636",
    ldap_base_dn="dc=example,dc=com",
    bind_dn="CN=Service Account,CN=Users,DC=example,DC=com",
    bind_password="password",
    user_search_filter="(sAMAccountName={username})",
    user_search_base="CN=Users,DC=example,DC=com",
    group_search_filter="(member:1.2.840.113556.1.4.1941:={user_dn})",  # Recursive group search
    group_attribute="cn",
)
```

## API Reference

### Dependencies

- `get_current_user` - Get the current authenticated user (HTTP Basic Auth)
- `require_groups(*groups)` - Require user to belong to at least one of the specified groups
- `require_roles(*roles)` - Alias for `require_groups` (semantic clarity)

### Models

- `LDAPUser` - Immutable user object with:
  - `dn` - Distinguished Name
  - `username` - Username
  - `email` - Email address (optional)
  - `display_name` - Display name (optional)
  - `groups` - Frozen set of group names
  - `attributes` - Additional LDAP attributes
  - `has_group(group)` - Check if user belongs to a group
  - `has_any_group(groups)` - Check if user belongs to any group
  - `has_all_groups(groups)` - Check if user belongs to all groups

### Health Checks

- `health_check()` - Basic health check (does not verify LDAP)
- `readiness_check()` - Verifies LDAP connectivity (for Kubernetes probes)

## Security Considerations

- **TLS is enabled by default** - Disable only for testing in secure environments
- **Anonymous binds are disabled by default** - Must be explicitly enabled
- **Authentication failures are indistinguishable** - Prevents user enumeration
- **No credential logging** - Passwords are never logged
- **Fail-closed behavior** - If LDAP is unavailable, authentication fails securely

## Architecture

The module follows a layered architecture:

1. **LDAP Client Layer** (`client.py`) - Isolated from FastAPI, handles connections, retries, timeouts, TLS
2. **Auth Layer** (`auth.py`) - FastAPI dependencies, converts LDAP errors to HTTP errors
3. **Models** (`models.py`) - Immutable LDAP user objects
4. **Cache Layer** (`cache.py`) - Optional caching with configurable TTL
5. **Configuration** (`config.py`) - Explicit, documented settings

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black fastapi_ldap tests

# Lint code
ruff check fastapi_ldap tests

# Type check
mypy fastapi_ldap
```

## License

MIT
