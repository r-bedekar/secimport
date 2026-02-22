"""
Vectra AI NDR Connector.

API Docs: https://support.vectra.ai/s/article/KB-VS-1689

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedNetworkObservation
from .base import BaseNDRConnector


class VectraConnector(BaseNDRConnector):
    """Vectra AI NDR connector."""

    name: ClassVar[str] = "vectra"
    vendor: ClassVar[str] = "Vectra AI"
    description: ClassVar[str] = "Vectra AI Network Detection and Response"
    auth_types: ClassVar[Tuple[str, ...]] = ("token", "oauth2")

    _test_endpoint: ClassVar[str] = "/api/v2.5/health/connectivity"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "hosts": "/api/v2.5/hosts",
        "detections": "/api/v2.5/detections",
    }

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth.auth_type == "token":
            return {"Authorization": f"Token {self.auth.credentials['token']}"}
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
            ip_address=raw.get("last_source"),
            hostname=raw.get("name"),
            risk_score=raw.get("threat"),
            tags=raw.get("tags", []),
            source_system="vectra",
            extra=raw,
        )
