"""
Trellix (formerly McAfee) Endpoint Security Connector.

API Docs: https://developer.manage.trellix.com/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseEDRConnector


class TrellixConnector(BaseEDRConnector):
    """Trellix (McAfee) endpoint security connector."""

    name: ClassVar[str] = "trellix"
    vendor: ClassVar[str] = "Trellix"
    description: ClassVar[str] = "Trellix Endpoint Security (formerly McAfee)"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key", "oauth2")

    _test_endpoint: ClassVar[str] = "/epo/v2/devices?limit=1"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "devices": "/epo/v2/devices",
        "threats": "/epo/v2/threats",
    }

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth.auth_type == "api_key":
            return {"x-api-key": self.auth.credentials["api_key"]}
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
            hostname=raw.get("name"),
            ip_address=raw.get("ipAddress"),
            mac_address=raw.get("macAddress"),
            agent_id=raw.get("agentGuid"),
            agent_version=raw.get("agentVersion"),
            operating_system=raw.get("operatingSystem"),
            os_version=raw.get("osVersion"),
            tags=raw.get("tags", []),
            source_system="trellix",
            extra=raw,
        )
