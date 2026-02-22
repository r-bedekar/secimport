"""
Palo Alto Cortex XDR Connector.

API Docs: https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseXDRConnector


class CortexXDRConnector(BaseXDRConnector):
    """Palo Alto Cortex XDR connector."""

    name: ClassVar[str] = "cortex_xdr"
    vendor: ClassVar[str] = "Palo Alto Networks"
    description: ClassVar[str] = "Palo Alto Cortex XDR"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    _test_endpoint: ClassVar[str] = "/public_api/v1/endpoints/get_endpoint/"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "endpoints": "/public_api/v1/endpoints/get_endpoint/",
        "incidents": "/public_api/v1/incidents/get_incidents/",
        "alerts": "/public_api/v1/alerts/get_alerts_multi_events/",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "x-xdr-auth-id": self.auth.credentials.get("api_key_id", ""),
            "Authorization": self.auth.credentials.get("api_key", ""),
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
            hostname=raw.get("endpoint_name"),
            ip_address=(
                (raw.get("ip") or [""])[0]
                if isinstance(raw.get("ip"), list)
                else raw.get("ip")
            ),
            agent_id=raw.get("endpoint_id"),
            agent_version=raw.get("content_version"),
            agent_status=raw.get("endpoint_status"),
            operating_system=raw.get("os_type"),
            isolation_status=raw.get("is_isolated"),
            source_system="cortex_xdr",
            extra=raw,
        )
