"""Tests for connector infrastructure and scanner connector initialization."""

import pytest

from secimport.connectors.base import (
    AuthConfig,
    ConnectionConfig,
    ConnectorRegistry,
    ConnectorStatus,
)
from secimport.connectors.scanners import (
    CrowdStrikeConnector,
    NessusConnector,
    OpenVASConnector,
    QualysConnector,
    Rapid7Connector,
    TenableConnector,
)


class TestConnectionConfig:
    def test_defaults(self):
        cfg = ConnectionConfig(base_url="https://example.com")
        assert cfg.verify_ssl is True
        assert cfg.timeout == 30
        assert cfg.max_retries == 3

    def test_custom(self):
        cfg = ConnectionConfig(base_url="https://example.com", timeout=60, verify_ssl=False)
        assert cfg.timeout == 60
        assert cfg.verify_ssl is False


class TestAuthConfig:
    def test_basic(self):
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "u", "password": "p"},
        )
        assert auth.auth_type == "basic"

    def test_api_key(self):
        auth = AuthConfig(
            auth_type="api_key",
            credentials={"access_key": "ak", "secret_key": "sk"},
        )
        assert auth.credentials["access_key"] == "ak"


class TestAuthTypeValidation:
    """Verify that connectors reject unsupported auth types."""

    def test_qualys_rejects_oauth2(self, connection_config):
        auth = AuthConfig(auth_type="oauth2", credentials={"client_id": "x", "client_secret": "y"})
        with pytest.raises(ValueError, match="does not support"):
            QualysConnector(connection_config, auth)

    def test_crowdstrike_rejects_basic(self, connection_config):
        auth = AuthConfig(auth_type="basic", credentials={"username": "u", "password": "p"})
        with pytest.raises(ValueError, match="does not support"):
            CrowdStrikeConnector(connection_config, auth)


class TestConnectorRegistry:
    def test_scanners_registered(self):
        registry = ConnectorRegistry.list_connectors()
        assert "qualys" in registry
        assert "nessus" in registry
        assert "tenable" in registry
        assert "rapid7" in registry
        assert "openvas" in registry
        assert "crowdstrike" in registry

    def test_get_by_name(self):
        assert ConnectorRegistry.get("qualys") is QualysConnector
        assert ConnectorRegistry.get("nonexistent") is None


class TestScannerConnectorInit:
    """Verify all scanner connectors can be instantiated."""

    @pytest.mark.parametrize(
        ("cls", "auth_fixture"),
        [
            (QualysConnector, "basic_auth"),
            (NessusConnector, "api_key_auth"),
            (TenableConnector, "api_key_auth"),
            (Rapid7Connector, "basic_auth"),
            (OpenVASConnector, "basic_auth"),
            (CrowdStrikeConnector, "oauth2_auth"),
        ],
    )
    def test_init(self, cls, auth_fixture, connection_config, request):
        auth = request.getfixturevalue(auth_fixture)
        connector = cls(connection_config, auth)
        assert connector.status == ConnectorStatus.DISCONNECTED
        assert connector._client is None

    @pytest.mark.parametrize(
        "cls",
        [
            QualysConnector,
            NessusConnector,
            TenableConnector,
            Rapid7Connector,
            OpenVASConnector,
            CrowdStrikeConnector,
        ],
    )
    def test_has_required_attrs(self, cls):
        assert isinstance(cls.name, str)
        assert isinstance(cls.vendor, str)
        assert isinstance(cls.description, str)
        assert isinstance(cls.auth_types, tuple)
        assert len(cls.ENDPOINTS) > 0
