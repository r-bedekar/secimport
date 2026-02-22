"""
Trend Micro Apex One / Worry-Free Connector.

API Docs: https://automation.trendmicro.com/apex-central/api/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseEDRConnector


class TrendMicroConnector(BaseEDRConnector):
    """Trend Micro Apex One / Worry-Free endpoint connector."""

    name: ClassVar[str] = "trend_micro"
    vendor: ClassVar[str] = "Trend Micro"
    description: ClassVar[str] = "Trend Micro Apex One endpoint security"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    _test_endpoint: ClassVar[str] = "/WebApp/API/ServerResource/ProductServers"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "agents": "/WebApp/API/AgentResource/ProductAgents",
        "security_events": "/WebApp/API/v1/logs/SecurityEvents",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.auth.credentials['api_key']}"}

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
            hostname=raw.get("host_name"),
            ip_address=raw.get("ip_address_list", "").split(",")[0] or None,
            mac_address=raw.get("mac_address_list", "").split(",")[0] or None,
            agent_id=raw.get("entity_id"),
            agent_version=raw.get("product_version"),
            operating_system=raw.get("platform"),
            endpoint_type=raw.get("product_type"),
            source_system="trend_micro",
            extra=raw,
        )
