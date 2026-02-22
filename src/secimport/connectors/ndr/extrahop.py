"""
ExtraHop Reveal(x) NDR Connector.

API Docs: https://docs.extrahop.com/current/rest-api-guide/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedNetworkObservation
from .base import BaseNDRConnector


class ExtraHopConnector(BaseNDRConnector):
    """ExtraHop Reveal(x) NDR connector."""

    name: ClassVar[str] = "extrahop"
    vendor: ClassVar[str] = "ExtraHop"
    description: ClassVar[str] = "ExtraHop Reveal(x) NDR"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key", "oauth2")

    _test_endpoint: ClassVar[str] = "/api/v1/extrahop"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "devices": "/api/v1/devices",
        "detections": "/api/v1/detections",
    }

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth.auth_type == "api_key":
            return {"Authorization": f"ExtraHop apikey={self.auth.credentials['api_key']}"}
        return {}

    def get_devices(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedNetworkObservation]:
        raise NotImplementedError("Community contribution welcome!")

    def get_device_by_ip(
        self, ip_address: str
    ) -> Optional[ParsedNetworkObservation]:
        raise NotImplementedError("Community contribution welcome!")

    def get_alerts(
        self,
        since: Optional[datetime] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        raise NotImplementedError("Community contribution welcome!")

    def _parse_device(self, raw: Dict[str, Any]) -> ParsedNetworkObservation:
        return ParsedNetworkObservation(
            ip_address=raw.get("ipaddr4") or raw.get("ipaddr6"),
            mac_address=raw.get("macaddr"),
            hostname=raw.get("dhcp_name") or raw.get("dns_name") or raw.get("cdp_name"),
            device_type_guess=raw.get("device_class"),
            risk_score=raw.get("risk_score_id"),
            source_system="extrahop",
            extra=raw,
        )
