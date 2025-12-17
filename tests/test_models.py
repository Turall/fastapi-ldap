import pytest

from fastapi_ldap.models import LDAPUser

class TestLDAPUser:
    def test_create_user_minimal(self):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
        )
        assert user.dn == "cn=testuser,dc=example,dc=com"
        assert user.username == "testuser"
        assert user.email is None
        assert user.display_name is None
        assert user.groups == frozenset()
        assert user.attributes == {}

    def test_create_user_full(self):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            groups=frozenset(["admins", "users"]),
            attributes={"department": "IT"},
        )
        assert user.dn == "cn=testuser,dc=example,dc=com"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.display_name == "Test User"
        assert user.groups == frozenset(["admins", "users"])
        assert user.attributes == {"department": "IT"}

    def test_user_immutable(self):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["admins"]),
        )
        with pytest.raises(AttributeError):
            user.username = "newuser"  # type: ignore
        with pytest.raises(AttributeError):
            user.groups = frozenset(["newgroup"])  # type: ignore

    def test_has_group(self):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["admins", "users"]),
        )
        assert user.has_group("admins") is True
        assert user.has_group("users") is True
        assert user.has_group("guests") is False

    def test_has_any_group(self):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["admins", "users"]),
        )
        assert user.has_any_group({"admins", "guests"}) is True
        assert user.has_any_group({"guests", "visitors"}) is False
        assert user.has_any_group(set()) is False

    def test_has_all_groups(self):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
            groups=frozenset(["admins", "users"]),
        )
        assert user.has_all_groups({"admins"}) is True
        assert user.has_all_groups({"admins", "users"}) is True
        assert user.has_all_groups({"admins", "guests"}) is False
        assert user.has_all_groups(set()) is True

    def test_empty_groups(self):
        user = LDAPUser(
            dn="cn=testuser,dc=example,dc=com",
            username="testuser",
        )
        assert user.groups == frozenset()
        assert user.has_group("any") is False
        assert user.has_any_group({"any"}) is False
        assert user.has_all_groups(set()) is True

