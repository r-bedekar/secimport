"""Tests for NDR connector initialization and registry."""

import pytest

from secimport.connectors.base import ConnectorRegistry, ConnectorStatus
from secimport.connectors.ndr import DarktraceConnector, ExtraHopConnector, VectraConnector

ALL_NDR = [DarktraceConnector, ExtraHopConnector, VectraConnector]


class TestNDRRegistry:
    def test_all_ndr_registered(self):
        registry = ConnectorRegistry.list_connectors()
        for name in ["darktrace", "extrahop", "vectra"]:
            assert name in registry, f"{name} not in registry"

    def test_get_by_name(self):
        assert ConnectorRegistry.get("darktrace") is DarktraceConnector
        assert ConnectorRegistry.get("extrahop") is ExtraHopConnector
        assert ConnectorRegistry.get("vectra") is VectraConnector


class TestNDRConnectorAttrs:
    @pytest.mark.parametrize("cls", ALL_NDR)
    def test_has_required_attrs(self, cls):
        assert isinstance(cls.name, str)
        assert isinstance(cls.vendor, str)
        assert isinstance(cls.description, str)
        assert isinstance(cls.auth_types, tuple)
        assert len(cls.ENDPOINTS) > 0


class TestNDRConnectorInit:
    @pytest.mark.parametrize(
        ("cls", "auth_fixture"),
        [
            (DarktraceConnector, "token_auth"),
            (ExtraHopConnector, "api_key_auth"),
            (VectraConnector, "token_auth"),
        ],
    )
    def test_init(self, cls, auth_fixture, connection_config, request):
        auth = request.getfixturevalue(auth_fixture)
        connector = cls(connection_config, auth)
        assert connector.status == ConnectorStatus.DISCONNECTED
        assert connector._client is None

    def test_darktrace_rejects_basic(self, connection_config, basic_auth):
        with pytest.raises(ValueError, match="does not support"):
            DarktraceConnector(connection_config, basic_auth)
