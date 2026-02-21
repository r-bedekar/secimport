"""
Base class for CMDB (Configuration Management Database) connectors.

Extend this for: ServiceNow, BMC Helix, Device42, etc.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from ...models.base import ParsedAsset
from ..base import BaseConnector


class BaseCMDBConnector(BaseConnector):
    """
    Base class for all CMDB API connectors.

    Inherits connection plumbing (``connect``, ``test_connection``,
    ``disconnect``, auth hooks) from ``BaseConnector``.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_assets``, ``get_asset_by_id``, ``search_assets``.
        * Implement ``get_relationships`` for CI dependency graphs.
        * Implement ``_parse_asset`` to map raw API data to the model.
    """

    # -- abstract data methods -------------------------------------------------

    @abstractmethod
    def get_assets(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedAsset]:
        """
        Fetch configuration items from the CMDB.

        Args:
            limit: Maximum number of assets to return.
            since: Only assets updated after this date.

        Yields:
            ``ParsedAsset`` objects.
        """
        ...

    @abstractmethod
    def get_asset_by_id(self, asset_id: str) -> Optional[ParsedAsset]:
        """
        Retrieve a single asset by its unique identifier.

        Args:
            asset_id: System-specific asset / CI identifier.

        Returns:
            ``ParsedAsset`` if found, ``None`` otherwise.
        """
        ...

    @abstractmethod
    def search_assets(
        self,
        query: str,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedAsset]:
        """
        Search assets using a query string.

        Args:
            query: Free-text or system-specific query string.
            limit: Maximum results.

        Yields:
            Matching ``ParsedAsset`` objects.
        """
        ...

    @abstractmethod
    def get_relationships(self, asset_id: str) -> List[Dict[str, Any]]:
        """
        Get relationships / dependencies for a configuration item.

        Args:
            asset_id: CI identifier whose relationships to fetch.

        Returns:
            List of relationship dicts with keys like
            ``type``, ``parent``, ``child``, ``direction``.
        """
        ...

    # -- parse helper ----------------------------------------------------------

    @abstractmethod
    def _parse_asset(self, raw: Dict[str, Any]) -> ParsedAsset:
        """Map a single raw API record to ``ParsedAsset``."""
        ...
