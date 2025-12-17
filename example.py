from fastapi import Depends, FastAPI
from fastapi_ldap import (
    LDAPAuth,
    LDAPSettings,
    get_current_user,
    health_check,
    readiness_check,
    require_groups,
    require_roles,
)
from fastapi_ldap.models import LDAPUser

# Configure LDAP settings
# In production, use environment variables:
# export LDAP_URL="ldaps://ldap.example.com:636"
# export LDAP_BASE_DN="dc=example,dc=com"
# export LDAP_BIND_DN="cn=admin,dc=example,dc=com"
# export LDAP_BIND_PASSWORD="secret"

settings = LDAPSettings(
    ldap_url="ldap://localhost:389",  # Use ldap:// for non-TLS (or ldaps://localhost:636 for TLS)
    ldap_base_dn="dc=example,dc=com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="admin",
    use_tls=False,  # Set to True if using ldaps://
    # Search configuration for OpenLDAP
    user_search_filter="(uid={username})",
    user_search_base="ou=users,dc=example,dc=com",
    group_search_filter="(memberUid={username})",
    group_search_base="ou=groups,dc=example,dc=com",
    group_attribute="cn",
    # Optional: enable caching
    cache_enabled=True,
    cache_ttl=300,
)

ldap_auth = LDAPAuth(settings)

app = FastAPI(
    title="FastAPI LDAP Example",
    description="Example application demonstrating fastapi-ldap usage",
    lifespan=ldap_auth.lifespan,
)

@app.get("/health")
async def health():
    """Basic health check."""
    return await health_check()


@app.get("/ready")
async def ready():
    """Readiness check - verifies LDAP connectivity."""
    return await readiness_check()


@app.get("/")
async def root():
    """Public endpoint."""
    return {"message": "Welcome to FastAPI LDAP Example"}


@app.get("/protected")
async def protected_route(user: LDAPUser = Depends(get_current_user)):
    """Protected endpoint requiring authentication."""
    return {
        "message": "You are authenticated!",
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "groups": list(user.groups),
    }


@app.get("/admin")
async def admin_route(
    user: LDAPUser = Depends(require_groups("admins", "superusers"))
):
    """Admin endpoint requiring group membership."""
    return {
        "message": f"Welcome, {user.username}!",
        "role": "admin",
    }


@app.get("/data")
async def data_route(user: LDAPUser = Depends(require_roles("admins"))):
    return {
        "message": "Access granted to data",
        "data": {"sample": "data"},
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

