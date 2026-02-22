"""Tests for SIEM connector initialization and registry."""

import pytest

from secimport.connectors.base import ConnectorRegistry, ConnectorStatus
from secimport.connectors.siem import QRadarConnector, SentinelConnector, SplunkConnector

ALL_SIEM = [SplunkConnector, SentinelConnector, QRadarConnector]


class TestSIEMRegistry:
    def test_all_siem_registered(self):
        registry = ConnectorRegistry.list_connectors()
        for name in ["splunk", "sentinel", "qradar"]:
            assert name in registry, f"{name} not in registry"

    def test_get_by_name(self):
        assert ConnectorRegistry.get("splunk") is SplunkConnector
        assert ConnectorRegistry.get("sentinel") is SentinelConnector
        assert ConnectorRegistry.get("qradar") is QRadarConnector


class TestSIEMConnectorAttrs:
    @pytest.mark.parametrize("cls", ALL_SIEM)
    def test_has_required_attrs(self, cls):
        assert isinstance(cls.name, str)
        assert isinstance(cls.vendor, str)
        assert isinstance(cls.description, str)
        assert isinstance(cls.auth_types, tuple)
        assert len(cls.ENDPOINTS) > 0


class TestSIEMConnectorInit:
    @pytest.mark.parametrize(
        ("cls", "auth_fixture"),
        [
            (SplunkConnector, "basic_auth"),
            (SentinelConnector, "oauth2_auth"),
            (QRadarConnector, "token_auth"),
        ],
    )
    def test_init(self, cls, auth_fixture, connection_config, request):
        auth = request.getfixturevalue(auth_fixture)
        connector = cls(connection_config, auth)
        assert connector.status == ConnectorStatus.DISCONNECTED
        assert connector._client is None

    def test_qradar_rejects_basic(self, connection_config, basic_auth):
        with pytest.raises(ValueError, match="does not support"):
            QRadarConnector(connection_config, basic_auth)
