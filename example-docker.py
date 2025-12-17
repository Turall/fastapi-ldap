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

# Configure LDAP settings for Docker OpenLDAP
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
    title="FastAPI LDAP Example (Docker)",
    description="Example application demonstrating fastapi-ldap usage with Docker OpenLDAP",
    lifespan=ldap_auth.lifespan,
)

# Health checks
@app.get("/health")
async def health():
    return await health_check()


@app.get("/ready")
async def ready():
    return await readiness_check()


# Public route
@app.get("/")
async def root():
    return {
        "message": "Welcome to FastAPI LDAP Example",
        "docs": "/docs",
        "test_users": {
            "testuser": "testpass123",
            "adminuser": "adminpass123",
        },
    }


# Protected route - requires authentication
@app.get("/protected")
async def protected_route(user: LDAPUser = Depends(get_current_user)):
    return {
        "message": "You are authenticated!",
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "groups": list(user.groups),
    }


@app.get("/admin")
async def admin_route(
    user: LDAPUser = Depends(require_groups("admins"))
):
    return {
        "message": f"Welcome, {user.username}!",
        "role": "admin",
        "groups": list(user.groups),
    }


@app.get("/users")
async def users_route(user: LDAPUser = Depends(require_groups("users","admins"))):
    return {
        "message": "Access granted to users area",
        "user": user.username,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

