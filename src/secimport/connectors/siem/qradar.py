"""
IBM QRadar SIEM Connector.

API Docs: https://www.ibm.com/docs/en/qradar-common

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple

from ...models.base import ParsedAsset
from .base import BaseSIEMConnector


class QRadarConnector(BaseSIEMConnector):
    """IBM QRadar SIEM connector."""

    name: ClassVar[str] = "qradar"
    vendor: ClassVar[str] = "IBM"
    description: ClassVar[str] = "IBM QRadar SIEM"
    auth_types: ClassVar[Tuple[str, ...]] = ("token",)

    _test_endpoint: ClassVar[str] = "/api/system/about"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "assets": "/api/asset_model/assets",
        "offenses": "/api/siem/offenses",
        "log_sources": (
            "/api/config/event_sources/log_source_management/log_sources"
        ),
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {"SEC": self.auth.credentials.get("token", "")}

    def get_assets(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedAsset]:
        raise NotImplementedError("Community contribution welcome!")

    def get_log_sources(
        self, limit: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        raise NotImplementedError("Community contribution welcome!")

    def search(
        self,
        query: str,
        time_range: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        raise NotImplementedError("Community contribution welcome!")

    def _parse_asset(self, raw: Dict[str, Any]) -> ParsedAsset:
        return ParsedAsset(
            hostname=raw.get("hostnames", [None])[0] if raw.get("hostnames") else None,
            ip_address=(
                raw.get("interfaces", [{}])[0].get("ip_addresses", [{}])[0].get("value")
                if raw.get("interfaces") else None
            ),
            source_system="qradar",
            extra=raw,
        )
