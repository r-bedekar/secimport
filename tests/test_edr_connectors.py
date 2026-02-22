"""Tests for EDR/AV connector initialization and registry."""

import pytest

from secimport.connectors.base import ConnectorRegistry, ConnectorStatus
from secimport.connectors.edr import (
    CarbonBlackConnector,
    CrowdStrikeFalconConnector,
    DefenderForEndpointConnector,
    SentinelOneConnector,
    SymantecEndpointConnector,
    TrellixConnector,
    TrendMicroConnector,
)

ALL_EDR = [
    CrowdStrikeFalconConnector,
    DefenderForEndpointConnector,
    SentinelOneConnector,
    CarbonBlackConnector,
    SymantecEndpointConnector,
    TrellixConnector,
    TrendMicroConnector,
]


class TestEDRRegistry:
    def test_all_edr_registered(self):
        registry = ConnectorRegistry.list_connectors()
        expected = [
            "crowdstrike_falcon",
            "defender_endpoint",
            "sentinelone",
            "carbon_black",
            "symantec_endpoint",
            "trellix",
            "trend_micro",
        ]
        for name in expected:
            assert name in registry, f"{name} not in registry"

    def test_get_by_name(self):
        assert ConnectorRegistry.get("crowdstrike_falcon") is CrowdStrikeFalconConnector
        assert ConnectorRegistry.get("sentinelone") is SentinelOneConnector


class TestEDRConnectorAttrs:
    @pytest.mark.parametrize("cls", ALL_EDR)
    def test_has_required_attrs(self, cls):
        assert isinstance(cls.name, str)
        assert isinstance(cls.vendor, str)
        assert isinstance(cls.description, str)
        assert isinstance(cls.auth_types, tuple)
        assert len(cls.ENDPOINTS) > 0


class TestEDRConnectorInit:
    @pytest.mark.parametrize(
        ("cls", "auth_fixture"),
        [
            (CrowdStrikeFalconConnector, "oauth2_auth"),
            (DefenderForEndpointConnector, "oauth2_auth"),
            (SentinelOneConnector, "api_key_auth"),
            (CarbonBlackConnector, "api_key_auth"),
            (SymantecEndpointConnector, "basic_auth"),
            (TrellixConnector, "api_key_auth"),
            (TrendMicroConnector, "api_key_auth"),
        ],
    )
    def test_init(self, cls, auth_fixture, connection_config, request):
        auth = request.getfixturevalue(auth_fixture)
        connector = cls(connection_config, auth)
        assert connector.status == ConnectorStatus.DISCONNECTED
        assert connector._client is None

    def test_rejects_unsupported_auth(self, connection_config, basic_auth):
        with pytest.raises(ValueError, match="does not support"):
            CrowdStrikeFalconConnector(connection_config, basic_auth)
