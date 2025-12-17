"""Pytest configuration and fixtures."""

import asyncio
from unittest.mock import Mock

import pytest
from ldap3 import Connection, Server

from fastapi_ldap.config import LDAPSettings


@pytest.fixture
def ldap_settings() -> LDAPSettings:
    return LDAPSettings(
        ldap_url="ldaps://ldap.example.com:636",
        ldap_base_dn="dc=example,dc=com",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="secret",
        use_tls=True,
        cache_enabled=False,
    )


@pytest.fixture
def ldap_settings_anonymous() -> LDAPSettings:
    return LDAPSettings(
        ldap_url="ldaps://ldap.example.com:636",
        ldap_base_dn="dc=example,dc=com",
        allow_anonymous=True,
        use_tls=True,
    )


@pytest.fixture
def mock_ldap_server() -> Server:
    server = Mock(spec=Server)
    return server


@pytest.fixture
def mock_ldap_connection() -> Connection:
    conn = Mock(spec=Connection)
    conn.bound = True
    conn.closed = False
    conn.entries = []
    conn.search = Mock(return_value=True)
    conn.bind = Mock(return_value=True)
    conn.rebind = Mock(return_value=True)
    conn.unbind = Mock(return_value=True)
    return conn


@pytest.fixture
def mock_ldap_entry() -> Mock:
    entry = Mock()
    entry.entry_dn = "cn=testuser,dc=example,dc=com"
    entry.entry_attributes_as_dict = {
        "uid": ["testuser"],
        "mail": ["test@example.com"],
        "cn": ["Test User"],
        "displayName": ["Test User"],
    }
    return entry


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

