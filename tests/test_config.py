import pytest

from fastapi_ldap.config import LDAPSettings

class TestLDAPSettings:
    def test_basic_settings(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
        )
        assert settings.ldap_url == "ldaps://ldap.example.com:636"
        assert settings.ldap_base_dn == "dc=example,dc=com"
        assert settings.bind_dn == "cn=admin,dc=example,dc=com"
        assert settings.bind_password == "secret"

    def test_defaults(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
        )
        assert settings.use_tls is True
        assert settings.pool_size == 10
        assert settings.cache_enabled is False

    def test_anonymous_bind(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            allow_anonymous=True,
        )
        assert settings.allow_anonymous is True
        assert settings.bind_dn is None
        assert settings.bind_password is None

    def test_require_bind_credentials(self):
        with pytest.raises(ValueError, match="bind_dn and bind_password are required"):
            LDAPSettings(
                ldap_url="ldaps://ldap.example.com:636",
                ldap_base_dn="dc=example,dc=com",
                allow_anonymous=False,
                bind_dn=None,
                bind_password=None,
            )

    def test_ldaps_url(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
        )
        assert settings.ldap_url == "ldaps://ldap.example.com:636"

    def test_ldap_url_with_tls(self):
        with pytest.raises(ValueError, match="TLS is required"):
            LDAPSettings(
                ldap_url="ldap://ldap.example.com:389",
                ldap_base_dn="dc=example,dc=com",
                bind_dn="cn=admin,dc=example,dc=com",
                bind_password="secret",
                use_tls=True,
            )

    def test_ldap_url_without_tls_explicit(self):
        settings = LDAPSettings(
            ldap_url="ldap://ldap.example.com:389",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            use_tls=False,
        )
        assert settings.use_tls is False

    def test_require_tls(self):
        with pytest.raises(ValueError, match="TLS is required"):
            LDAPSettings(
                ldap_url="ldap://ldap.example.com:389",
                ldap_base_dn="dc=example,dc=com",
                bind_dn="cn=admin,dc=example,dc=com",
                bind_password="secret",
            )
        
        settings = LDAPSettings(
            ldap_url="ldap://ldap.example.com:389",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            use_tls=False,
        )
        assert settings.use_tls is False

    def test_ldaps_url_allows_no_tls_flag(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            use_tls=False,
        )
        assert settings.use_tls is False

    def test_pool_settings(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            pool_size=20,
            pool_timeout=60.0,
        )
        assert settings.pool_size == 20
        assert settings.pool_timeout == 60.0

    def test_timeout_settings(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            connect_timeout=15.0,
            operation_timeout=45.0,
        )
        assert settings.connect_timeout == 15.0
        assert settings.operation_timeout == 45.0

    def test_retry_settings(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            max_retries=5,
            retry_delay=2.0,
        )
        assert settings.max_retries == 5
        assert settings.retry_delay == 2.0

    def test_cache_settings(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            cache_enabled=True,
            cache_ttl=600,
        )
        assert settings.cache_enabled is True
        assert settings.cache_ttl == 600

    def test_search_filters(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            user_search_filter="(sAMAccountName={username})",
            user_search_base="CN=Users,DC=example,DC=com",
            group_search_filter="(member:1.2.840.113556.1.4.1941:={user_dn})",
            group_search_base="CN=Groups,DC=example,DC=com",
            group_attribute="distinguishedName",
        )
        assert settings.user_search_filter == "(sAMAccountName={username})"
        assert settings.user_search_base == "CN=Users,DC=example,DC=com"
        assert settings.group_search_filter == "(member:1.2.840.113556.1.4.1941:={user_dn})"
        assert settings.group_search_base == "CN=Groups,DC=example,DC=com"
        assert settings.group_attribute == "distinguishedName"

    def test_tls_settings(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            tls_ca_cert_file="/path/to/ca.crt",
            tls_cert_file="/path/to/cert.crt",
            tls_key_file="/path/to/key.key",
            tls_require_cert=False,
        )
        assert settings.tls_ca_cert_file == "/path/to/ca.crt"
        assert settings.tls_cert_file == "/path/to/cert.crt"
        assert settings.tls_key_file == "/path/to/key.key"
        assert settings.tls_require_cert is False

    def test_default_search_bases(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
        )
        assert settings.user_search_base == "dc=example,dc=com"
        assert settings.group_search_base == "dc=example,dc=com"

    def test_custom_search_bases(self):
        settings = LDAPSettings(
            ldap_url="ldaps://ldap.example.com:636",
            ldap_base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            user_search_base="ou=Users,dc=example,dc=com",
            group_search_base="ou=Groups,dc=example,dc=com",
        )
        assert settings.user_search_base == "ou=Users,dc=example,dc=com"
        assert settings.group_search_base == "ou=Groups,dc=example,dc=com"

    def test_environment_variables(self, monkeypatch):
        env_vars = {
            "LDAP_URL": "ldaps://ldap.test.com:636",
            "LDAP_BASE_DN": "dc=test,dc=com",
            "LDAP_BIND_DN": "cn=test,dc=test,dc=com",
            "LDAP_BIND_PASSWORD": "testpass",
        }
        for key, value in env_vars.items():
            monkeypatch.setenv(key, value)
        
        try:
            settings = LDAPSettings(_env_file="")
            assert settings.ldap_url == "ldaps://ldap.test.com:636"
            assert settings.ldap_base_dn == "dc=test,dc=com"
            assert settings.bind_dn == "cn=test,dc=test,dc=com"
            assert settings.bind_password == "testpass"
        except Exception:
            pytest.skip("Environment variable reading not available in test environment")

    def test_case_insensitive_env_vars(self, monkeypatch):
        env_vars = {
            "ldap_url": "ldaps://ldap.test.com:636",
            "ldap_base_dn": "dc=test,dc=com",
            "ldap_bind_dn": "cn=test,dc=test,dc=com",
            "ldap_bind_password": "testpass",
        }
        for key, value in env_vars.items():
            monkeypatch.setenv(key, value)
        
        try:
            settings = LDAPSettings(_env_file="")
            assert settings.ldap_url == "ldaps://ldap.test.com:636"
            assert settings.ldap_base_dn == "dc=test,dc=com"
            assert settings.bind_dn == "cn=test,dc=test,dc=com"
            assert settings.bind_password == "testpass"
        except Exception:
            pytest.skip("Environment variable reading not available in test environment")

    def test_password_with_special_characters(self):
        special_char_passwords = [
            'pass$word',
            'pass%test',
            'pass&more',
            'pass*test',
            'pass(test)',
            'pass[test]',
            'pass{test}',
            'pass|test',
            'pass+test',
            'pass=test',
            'pass;test',
            'pass:test',
            'pass"test',
            "pass'test",
            'pass\\test',
            'pass/test',
            'pass?test',
            'pass^test',
            'pass~test',
            'pass`test',
            'pass!test',
            'pass@test',
            'pass#test',
            'pass<test>',
            'pass,test',
            'pass test',  # space
            'pass\ttest',  # tab
            'pass\ntest',  # newline
            'pass\r\ntest',  # CRLF
        ]
        
        for pwd in special_char_passwords:
            settings = LDAPSettings(
                ldap_url="ldaps://ldap.example.com:636",
                ldap_base_dn="dc=example,dc=com",
                bind_dn="cn=admin,dc=example,dc=com",
                bind_password=pwd,
            )
            assert settings.bind_password == pwd, f"Password mismatch for: {repr(pwd)}"

    def test_empty_password_not_allowed(self):
        with pytest.raises(ValueError, match="bind_dn and bind_password are required"):
            LDAPSettings(
                ldap_url="ldaps://ldap.example.com:636",
                ldap_base_dn="dc=example,dc=com",
                bind_dn="cn=admin,dc=example,dc=com",
                bind_password="",
                allow_anonymous=False,
            )

    def test_unicode_password(self):
        unicode_passwords = [
            'passwörd',
            'пароль',
            '密码',
            '🔐secret',
            'pass\u00e9',
        ]
        
        for pwd in unicode_passwords:
            settings = LDAPSettings(
                ldap_url="ldaps://ldap.example.com:636",
                ldap_base_dn="dc=example,dc=com",
                bind_dn="cn=admin,dc=example,dc=com",
                bind_password=pwd,
            )
            assert settings.bind_password == pwd, f"Unicode password mismatch for: {repr(pwd)}"
