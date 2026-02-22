"""
Trend Micro Vision One XDR Connector.

API Docs: https://automation.trendmicro.com/xdr/api-v3

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseXDRConnector


class VisionOneConnector(BaseXDRConnector):
    """Trend Micro Vision One XDR connector."""

    name: ClassVar[str] = "vision_one"
    vendor: ClassVar[str] = "Trend Micro"
    description: ClassVar[str] = "Trend Micro Vision One XDR"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    _test_endpoint: ClassVar[str] = "/v3.0/healthcheck/connectivity"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "endpoints": "/v3.0/eicar/endpoints",
        "alerts": "/v3.0/workbench/alerts",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.auth.credentials['api_key']}",
            "TMV1-Filter": "",
        }

    def get_endpoints(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedEndpoint]:
        raise NotImplementedError("Community contribution welcome!")

    def get_incidents(
        self,
        since: Optional[datetime] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        raise NotImplementedError("Community contribution welcome!")

    def get_alerts(
        self,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        raise NotImplementedError("Community contribution welcome!")

    def _parse_endpoint(self, raw: Dict[str, Any]) -> ParsedEndpoint:
        return ParsedEndpoint(
            hostname=raw.get("endpointName"),
            ip_address=raw.get("ip"),
            agent_id=raw.get("agentGuid"),
            operating_system=raw.get("osName"),
            os_version=raw.get("osVersion"),
            source_system="vision_one",
            extra=raw,
        )
