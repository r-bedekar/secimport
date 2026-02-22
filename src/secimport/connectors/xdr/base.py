"""
Base class for XDR platform connectors.

Extend this for: Palo Alto Cortex XDR, Trend Micro Vision One, etc.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from ...models.base import ParsedEndpoint, ParsedVulnerability
from ..base import BaseConnector


class BaseXDRConnector(BaseConnector):
    """
    Base class for XDR (Extended Detection and Response) connectors.

    XDR platforms combine EDR, NDR, email, and cloud signals.
    Connectors provide endpoint inventory and correlated incidents.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_endpoints``, ``get_incidents``, ``get_alerts``.
        * Implement ``_parse_endpoint``.
    """

    @abstractmethod
    def get_endpoints(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> Iterator[ParsedEndpoint]:
        """Fetch endpoints known to the XDR platform."""
        ...

    @abstractmethod
    def get_incidents(
        self,
        since: Optional[datetime] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Fetch XDR incidents (cross-domain correlated alerts)."""
        ...

    @abstractmethod
    def get_alerts(
        self,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """Fetch individual alerts, mapped to ParsedVulnerability."""
        ...

    @abstractmethod
    def _parse_endpoint(
        self, raw: Dict[str, Any]
    ) -> ParsedEndpoint:
        """Map raw API data to ``ParsedEndpoint``."""
        ...
