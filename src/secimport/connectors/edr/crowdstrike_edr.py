"""
CrowdStrike Falcon EDR Connector.

API Docs: https://falcon.crowdstrike.com/documentation/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseEDRConnector


class CrowdStrikeFalconConnector(BaseEDRConnector):
    """
    CrowdStrike Falcon EDR connector.

    Usage::

        from secimport.connectors.edr import CrowdStrikeFalconConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://api.crowdstrike.com")
        auth = AuthConfig(
            auth_type="oauth2",
            credentials={"client_id": "...", "client_secret": "..."},
        )

        with CrowdStrikeFalconConnector(config, auth) as cs:
            for ep in cs.get_endpoints():
                print(ep.hostname, ep.agent_status)
    """

    name: ClassVar[str] = "crowdstrike_falcon"
    vendor: ClassVar[str] = "CrowdStrike"
    description: ClassVar[str] = "CrowdStrike Falcon EDR platform"
    auth_types: ClassVar[Tuple[str, ...]] = ("oauth2",)

    _test_endpoint: ClassVar[str] = "/sensors/queries/installers/v1?limit=1"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "oauth2_token": "/oauth2/token",
        "devices_query": "/devices/queries/devices-scroll/v1",
        "devices_detail": "/devices/entities/devices/v2",
        "detections_query": "/detects/queries/detects/v1",
        "detections_detail": "/detects/entities/summaries/GET/v1",
    }

    def connect(self) -> bool:
        """OAuth2 client credentials flow."""
        token_url = f"{self.connection.base_url}{self.ENDPOINTS['oauth2_token']}"
        response = self._build_client(auth=None, headers={}).post(
            token_url,
            data={
                "client_id": self.auth.credentials["client_id"],
                "client_secret": self.auth.credentials["client_secret"],
            },
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        client = self._build_client(
            auth=None,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        return self._connect_with_test(client)

    def _auth_headers(self) -> Dict[str, str]:
        return {}

    def get_endpoints(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
        status_filter: Optional[str] = None,
    ) -> Iterator[ParsedEndpoint]:
        raise NotImplementedError("Community contribution welcome!")

    def get_endpoint_by_id(
        self, endpoint_id: str
    ) -> Optional[ParsedEndpoint]:
        raise NotImplementedError("Community contribution welcome!")

    def get_detections(
        self,
        since: Optional[datetime] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        raise NotImplementedError("Community contribution welcome!")

    def get_policy_compliance(
        self, limit: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        raise NotImplementedError("Community contribution welcome!")

    def _parse_endpoint(self, raw: Dict[str, Any]) -> ParsedEndpoint:
        return ParsedEndpoint(
            hostname=raw.get("hostname"),
            ip_address=raw.get("local_ip"),
            mac_address=raw.get("mac_address"),
            serial_number=raw.get("serial_number"),
            agent_id=raw.get("device_id"),
            agent_version=raw.get("agent_version"),
            agent_status="Online" if raw.get("status") == "normal" else "Offline",
            operating_system=raw.get("platform_name"),
            os_version=raw.get("os_version"),
            manufacturer=raw.get("system_manufacturer"),
            model=raw.get("system_product_name"),
            policy_name=raw.get("device_policies", {}).get("prevention", {}).get("policy_name"),
            site_name=raw.get("groups", [None])[0] if raw.get("groups") else None,
            source_system="crowdstrike",
            extra=raw,
        )
