# Test Suite

This directory contains comprehensive unit tests for fastapi-ldap.

## Test Structure

- `test_models.py` - Tests for immutable LDAP user models
- `test_exceptions.py` - Tests for custom exceptions
- `test_config.py` - Tests for configuration settings and validation
- `test_cache.py` - Tests for optional caching layer
- `test_client.py` - Tests for LDAP client layer (with mocked LDAP)
- `test_auth.py` - Tests for authentication layer (with mocked client)
- `test_health.py` - Tests for health and readiness checks
- `conftest.py` - Shared pytest fixtures

## Running Tests

```bash
# Install dependencies
pip install -e ".[dev]"

# Run all tests with coverage
pytest --cov=fastapi_ldap --cov-report=term-missing --cov-report=html

# Run specific test file
pytest tests/test_models.py -v

# Run with coverage threshold (fails if below 80%)
pytest --cov=fastapi_ldap --cov-fail-under=80
```

## Coverage Requirements

- Minimum coverage: 80%+
- All tests use mocked LDAP operations (no real LDAP server required)
- Async tests use pytest-asyncio
- Tests follow the guidelines in AGENT_GUIDELINES.md

## Test Principles

1. **Unit tests** - All LDAP operations are mocked
2. **Async-safe** - All async operations properly tested
3. **Security-focused** - Tests verify fail-closed behavior
4. **Comprehensive** - Tests cover success paths, error paths, and edge cases

