"""Tests for XDR connector initialization and registry."""

import pytest

from secimport.connectors.base import ConnectorRegistry, ConnectorStatus
from secimport.connectors.xdr import CortexXDRConnector, VisionOneConnector

ALL_XDR = [CortexXDRConnector, VisionOneConnector]


class TestXDRRegistry:
    def test_all_xdr_registered(self):
        registry = ConnectorRegistry.list_connectors()
        for name in ["cortex_xdr", "vision_one"]:
            assert name in registry, f"{name} not in registry"

    def test_get_by_name(self):
        assert ConnectorRegistry.get("cortex_xdr") is CortexXDRConnector
        assert ConnectorRegistry.get("vision_one") is VisionOneConnector


class TestXDRConnectorAttrs:
    @pytest.mark.parametrize("cls", ALL_XDR)
    def test_has_required_attrs(self, cls):
        assert isinstance(cls.name, str)
        assert isinstance(cls.vendor, str)
        assert isinstance(cls.description, str)
        assert isinstance(cls.auth_types, tuple)
        assert len(cls.ENDPOINTS) > 0


class TestXDRConnectorInit:
    @pytest.mark.parametrize(
        ("cls", "auth_fixture"),
        [
            (CortexXDRConnector, "api_key_auth"),
            (VisionOneConnector, "api_key_auth"),
        ],
    )
    def test_init(self, cls, auth_fixture, connection_config, request):
        auth = request.getfixturevalue(auth_fixture)
        connector = cls(connection_config, auth)
        assert connector.status == ConnectorStatus.DISCONNECTED
        assert connector._client is None

    def test_cortex_rejects_basic(self, connection_config, basic_auth):
        with pytest.raises(ValueError, match="does not support"):
            CortexXDRConnector(connection_config, basic_auth)
