"""
Microsoft Sentinel Connector.

API Docs: https://learn.microsoft.com/en-us/rest/api/securityinsights/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple

from ...models.base import ParsedAsset
from .base import BaseSIEMConnector


class SentinelConnector(BaseSIEMConnector):
    """Microsoft Sentinel SIEM connector."""

    name: ClassVar[str] = "sentinel"
    vendor: ClassVar[str] = "Microsoft"
    description: ClassVar[str] = "Microsoft Sentinel SIEM"
    auth_types: ClassVar[Tuple[str, ...]] = ("oauth2",)

    _test_endpoint: ClassVar[str] = "/"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "incidents": "/providers/Microsoft.SecurityInsights/incidents",
        "query": "/query",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {}

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
            hostname=raw.get("HostName"),
            ip_address=raw.get("IpAddress"),
            source_system="sentinel",
            extra=raw,
        )
