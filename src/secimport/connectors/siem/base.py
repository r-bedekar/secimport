"""
Base class for SIEM connectors.

Extend this for: Splunk, Microsoft Sentinel, QRadar, etc.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterator, Optional

from ...models.base import ParsedAsset
from ..base import BaseConnector


class BaseSIEMConnector(BaseConnector):
    """
    Base class for SIEM connectors.

    SIEM tools provide asset context through log-based inventory:
    which hosts are sending logs, when they were last seen, and
    what log sources are configured.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_assets``, ``get_log_sources``, ``search``.
        * Implement ``_parse_asset``.
    """

    @abstractmethod
    def get_assets(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedAsset]:
        """Fetch assets known to the SIEM (hosts sending logs)."""
        ...

    @abstractmethod
    def get_log_sources(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Fetch configured log sources / forwarders."""
        ...

    @abstractmethod
    def search(
        self,
        query: str,
        time_range: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Execute a search query against the SIEM."""
        ...

    @abstractmethod
    def _parse_asset(
        self, raw: Dict[str, Any]
    ) -> ParsedAsset:
        """Map raw SIEM data to ``ParsedAsset``."""
        ...
