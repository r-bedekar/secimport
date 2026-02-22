"""
SentinelOne EDR Connector.

API Docs: https://usea1-partners.sentinelone.net/api-doc/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseEDRConnector


class SentinelOneConnector(BaseEDRConnector):
    """SentinelOne EDR connector."""

    name: ClassVar[str] = "sentinelone"
    vendor: ClassVar[str] = "SentinelOne"
    description: ClassVar[str] = "SentinelOne Singularity EDR"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    _test_endpoint: ClassVar[str] = "/web/api/v2.1/system/status"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "agents": "/web/api/v2.1/agents",
        "threats": "/web/api/v2.1/threats",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"ApiToken {self.auth.credentials['api_key']}"}

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
            hostname=raw.get("computerName"),
            ip_address=(raw.get("lastIpToMgmt") or "").split(",")[0] or None,
            mac_address=(raw.get("networkInterfaces", [{}])[0].get("physical")
                         if raw.get("networkInterfaces") else None),
            serial_number=raw.get("serialNumber"),
            agent_id=raw.get("uuid"),
            agent_version=raw.get("agentVersion"),
            agent_status=raw.get("networkStatus"),
            operating_system=raw.get("osName"),
            os_version=raw.get("osRevision"),
            manufacturer=raw.get("modelName"),
            site_name=raw.get("siteName"),
            source_system="sentinelone",
            extra=raw,
        )
