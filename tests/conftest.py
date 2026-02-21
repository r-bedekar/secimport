"""Shared fixtures for secimport tests."""

import pytest

from secimport.connectors.base import AuthConfig, ConnectionConfig


@pytest.fixture()
def basic_auth() -> AuthConfig:
    """Basic auth credentials for testing."""
    return AuthConfig(
        auth_type="basic",
        credentials={"username": "testuser", "password": "testpass"},
    )


@pytest.fixture()
def api_key_auth() -> AuthConfig:
    """API-key auth credentials for testing."""
    return AuthConfig(
        auth_type="api_key",
        credentials={"access_key": "ak_test", "secret_key": "sk_test"},
    )


@pytest.fixture()
def oauth2_auth() -> AuthConfig:
    """OAuth2 auth credentials for testing."""
    return AuthConfig(
        auth_type="oauth2",
        credentials={"client_id": "test_id", "client_secret": "test_secret"},
    )


@pytest.fixture()
def connection_config() -> ConnectionConfig:
    """Standard connection config for testing."""
    return ConnectionConfig(
        base_url="https://scanner.example.com",
        verify_ssl=False,
        timeout=10,
    )
