
from fastapi_ldap.exceptions import (
    LDAPAuthenticationError,
    LDAPAuthorizationError,
    LDAPConnectionError,
    LDAPConfigurationError,
    LDAPError,
)

class TestLDAPError:
    def test_base_exception(self):
        error = LDAPError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.details is None

    def test_exception_with_details(self):
        error = LDAPError("Test error", details="Detailed info")
        assert error.message == "Test error"
        assert error.details == "Detailed info"

class TestLDAPConnectionError:
    def test_connection_error(self):
        error = LDAPConnectionError("Connection failed")
        assert isinstance(error, LDAPError)
        assert error.message == "Connection failed"

class TestLDAPAuthenticationError:
    def test_authentication_error(self):
        error = LDAPAuthenticationError("Auth failed")
        assert isinstance(error, LDAPError)
        assert error.message == "Auth failed"

class TestLDAPAuthorizationError:
    def test_authorization_error(self):
        error = LDAPAuthorizationError("Not authorized")
        assert isinstance(error, LDAPError)
        assert error.message == "Not authorized"

class TestLDAPConfigurationError:
    def test_configuration_error(self):
        error = LDAPConfigurationError("Invalid config")
        assert isinstance(error, LDAPError)
        assert error.message == "Invalid config"

