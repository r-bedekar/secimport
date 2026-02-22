"""
Symantec Endpoint Protection (Broadcom) Connector.

API Docs: https://apidocs.securitycloud.symantec.com/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedEndpoint, ParsedVulnerability
from .base import BaseEDRConnector


class SymantecEndpointConnector(BaseEDRConnector):
    """Symantec Endpoint Protection (Broadcom) connector."""

    name: ClassVar[str] = "symantec_endpoint"
    vendor: ClassVar[str] = "Broadcom"
    description: ClassVar[str] = "Symantec Endpoint Protection"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic", "token")

    _test_endpoint: ClassVar[str] = "/sepm/api/v1/identity/authenticate"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "computers": "/sepm/api/v1/computers",
        "threats": "/sepm/api/v1/threats",
    }

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth.auth_type == "token":
            return {"Authorization": f"Bearer {self.auth.credentials['token']}"}
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
            hostname=raw.get("computerName"),
            ip_address=raw.get("ipAddresses", [None])[0] if raw.get("ipAddresses") else None,
            mac_address=raw.get("macAddresses", [None])[0] if raw.get("macAddresses") else None,
            device_id=raw.get("hardwareKey"),
            agent_version=raw.get("agentVersion"),
            agent_status="Online" if raw.get("onlineStatus") == 1 else "Offline",
            operating_system=raw.get("operatingSystem"),
            signatures_up_to_date=raw.get("apOnOff") == 1,
            source_system="symantec_endpoint",
            extra=raw,
        )
