"""
Base class for EDR, AV, and endpoint security connectors.

Extend this for: CrowdStrike Falcon, Microsoft Defender, SentinelOne,
Carbon Black, Symantec, Trellix, Trend Micro, etc.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from ...models.base import ParsedEndpoint, ParsedVulnerability
from ..base import BaseConnector


class BaseEDRConnector(BaseConnector):
    """
    Base class for all EDR / AV / endpoint security connectors.

    Inherits connection plumbing from ``BaseConnector``.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_endpoints``, ``get_endpoint_by_id``,
          ``get_detections``, ``get_policy_compliance``.
        * Implement ``_parse_endpoint`` to map raw API data to the model.
    """

    @abstractmethod
    def get_endpoints(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
        status_filter: Optional[str] = None,
    ) -> Iterator[ParsedEndpoint]:
        """
        Fetch managed endpoints.

        Args:
            limit: Maximum number of endpoints to return.
            since: Only endpoints seen after this date.
            status_filter: Filter by agent status (Online, Offline, etc.).

        Yields:
            ``ParsedEndpoint`` objects.
        """
        ...

    @abstractmethod
    def get_endpoint_by_id(
        self, endpoint_id: str
    ) -> Optional[ParsedEndpoint]:
        """Retrieve a single endpoint by agent/device ID."""
        ...

    @abstractmethod
    def get_detections(
        self,
        since: Optional[datetime] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch detections/alerts, mapped to ParsedVulnerability for
        cross-source correlation.

        Yields:
            ``ParsedVulnerability`` objects.
        """
        ...

    @abstractmethod
    def get_policy_compliance(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get endpoint policy compliance status."""
        ...

    # -- convenience filters ---------------------------------------------------

    def get_offline_endpoints(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedEndpoint]:
        """Yield endpoints with agent_status == Offline."""
        return self.get_endpoints(
            status_filter="Offline", limit=limit
        )

    def get_non_compliant_endpoints(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedEndpoint]:
        """Yield endpoints with non-compliant policy status."""
        for ep in self.get_endpoints(limit=limit):
            if ep.policy_status and ep.policy_status != "Compliant":
                yield ep

    # -- parse helper ----------------------------------------------------------

    @abstractmethod
    def _parse_endpoint(
        self, raw: Dict[str, Any]
    ) -> ParsedEndpoint:
        """Map a single raw API record to ``ParsedEndpoint``."""
        ...
