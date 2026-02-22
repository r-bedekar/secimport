"""
Microsoft Defender for Endpoint Connector.

API Docs: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseEDRConnector


class DefenderForEndpointConnector(BaseEDRConnector):
    """
    Microsoft Defender for Endpoint connector.

    Usage::

        config = ConnectionConfig(
            base_url="https://api.securitycenter.microsoft.com"
        )
        auth = AuthConfig(
            auth_type="oauth2",
            credentials={
                "tenant_id": "...",
                "client_id": "...",
                "client_secret": "...",
            },
        )

        with DefenderForEndpointConnector(config, auth) as mde:
            for ep in mde.get_endpoints():
                print(ep.hostname, ep.agent_status)
    """

    name: ClassVar[str] = "defender_endpoint"
    vendor: ClassVar[str] = "Microsoft"
    description: ClassVar[str] = "Microsoft Defender for Endpoint"
    auth_types: ClassVar[Tuple[str, ...]] = ("oauth2",)

    _test_endpoint: ClassVar[str] = "/api/machines?$top=1"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "machines": "/api/machines",
        "alerts": "/api/alerts",
        "vulnerabilities": "/api/vulnerabilities",
    }

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
            hostname=raw.get("computerDnsName"),
            ip_address=raw.get("lastIpAddress"),
            device_id=raw.get("id"),
            agent_id=raw.get("aadDeviceId"),
            agent_version=raw.get("agentVersion"),
            agent_status=raw.get("healthStatus"),
            operating_system=raw.get("osPlatform"),
            os_version=raw.get("osVersion"),
            os_build=raw.get("osBuild"),
            source_system="defender_endpoint",
            extra=raw,
        )
