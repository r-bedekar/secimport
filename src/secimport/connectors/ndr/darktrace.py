"""
Darktrace NDR Connector.

API Docs: https://customerportal.darktrace.com/product-guides/main/api-overview

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedNetworkObservation
from .base import BaseNDRConnector


class DarktraceConnector(BaseNDRConnector):
    """Darktrace NDR connector."""

    name: ClassVar[str] = "darktrace"
    vendor: ClassVar[str] = "Darktrace"
    description: ClassVar[str] = "Darktrace Network Detection and Response"
    auth_types: ClassVar[Tuple[str, ...]] = ("token",)

    _test_endpoint: ClassVar[str] = "/status"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "devices": "/devices",
        "model_breaches": "/modelbreaches",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Token {self.auth.credentials['token']}"}

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
            ip_address=raw.get("ip"),
            mac_address=raw.get("macaddress"),
            hostname=raw.get("hostname"),
            device_type_guess=raw.get("typename"),
            vlan=str(raw.get("vid", "")) or None,
            source_system="darktrace",
            extra=raw,
        )
