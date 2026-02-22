"""
Splunk Enterprise / Cloud Connector.

API Docs: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, Optional, Tuple

from ...models.base import ParsedAsset
from .base import BaseSIEMConnector


class SplunkConnector(BaseSIEMConnector):
    """Splunk Enterprise / Cloud SIEM connector."""

    name: ClassVar[str] = "splunk"
    vendor: ClassVar[str] = "Splunk"
    description: ClassVar[str] = "Splunk Enterprise / Cloud SIEM"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic", "token")

    _test_endpoint: ClassVar[str] = "/services/server/info"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "search": "/services/search/jobs",
        "results": "/services/search/jobs/{sid}/results",
        "inputs": "/services/data/inputs/all",
    }

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth.auth_type == "token":
            return {"Authorization": f"Bearer {self.auth.credentials['token']}"}
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
            hostname=raw.get("host"),
            ip_address=raw.get("ip"),
            source_system="splunk",
            extra=raw,
        )
