"""
Base class for vulnerability scanner connectors.

Extend this for: Qualys, Nessus, Tenable, Rapid7, OpenVAS, CrowdStrike, etc.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from ...models.base import ParsedVulnerability
from ..base import BaseConnector


class BaseScannerConnector(BaseConnector):
    """
    Base class for all vulnerability scanner API connectors.

    Inherits connection plumbing (``connect``, ``test_connection``,
    ``disconnect``, auth hooks) from ``BaseConnector``.

    Subclass contract:
        * Override ``_auth_headers`` / ``_test_endpoint`` as needed.
        * Implement ``get_scans``, ``get_vulnerabilities``, ``get_assets``.
        * Implement ``_parse_vulnerability`` to map raw API data to the model.
    """

    # -- abstract data methods -------------------------------------------------

    @abstractmethod
    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get list of available scans.

        Args:
            limit: Maximum number of scans to return.
            since: Only scans after this date.

        Returns:
            List of scan metadata dicts.
        """
        ...

    @abstractmethod
    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from scanner.

        Args:
            scan_id: Specific scan to fetch (None = all/latest).
            severity: Filter by severity, e.g. ``["Critical", "High"]``.
            since: Only vulns detected after this date.
            limit: Maximum results.

        Yields:
            ``ParsedVulnerability`` objects.
        """
        ...

    @abstractmethod
    def get_assets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get assets known to the scanner.

        Yields:
            Asset dicts from scanner.
        """
        ...

    # -- convenience filters ---------------------------------------------------

    def get_critical_vulnerabilities(
        self,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """Convenience: yield only Critical-severity vulnerabilities."""
        return self.get_vulnerabilities(severity=["Critical"], since=since, limit=limit)

    def get_high_and_critical(
        self,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """Convenience: yield Critical and High vulnerabilities."""
        return self.get_vulnerabilities(
            severity=["Critical", "High"], since=since, limit=limit
        )

    # -- parse helper ----------------------------------------------------------

    @abstractmethod
    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Map a single raw API record to ``ParsedVulnerability``."""
        ...
