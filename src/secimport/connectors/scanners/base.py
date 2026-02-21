"""
Base class for vulnerability scanner connectors.

Extend this for: Qualys, Nessus, Tenable, Rapid7, OpenVAS, CrowdStrike, etc.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional

from ...models.base import ParsedVulnerability
from ..base import BaseConnector


class BaseScannerConnector(BaseConnector):
    """
    Base class for all vulnerability scanner API connectors.

    Provides shared ``connect`` / ``test_connection`` plumbing so that
    concrete scanners only need to declare how they build auth headers
    and which endpoint to ping.

    Subclass contract:
        * Override ``_auth_headers`` and/or ``_auth_credentials`` for auth.
        * Override ``_test_endpoint`` to point at a lightweight health-check URL.
        * Implement ``get_scans``, ``get_vulnerabilities``, ``get_assets``.
        * Implement ``_parse_vulnerability`` to map raw API data to the model.
    """

    # Subclasses may override to change the health-check URL.
    _test_endpoint: ClassVar[str] = "/"

    # ------------------------------------------------------------------
    # Shared connect / disconnect
    # ------------------------------------------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        """Return auth-related HTTP headers.  Override in subclass."""
        return {}

    def _auth_credentials(self) -> Optional[tuple]:
        """Return ``(username, password)`` for HTTP basic auth, or None."""
        if self.auth.auth_type == "basic":
            return (
                self.auth.credentials["username"],
                self.auth.credentials["password"],
            )
        return None

    def connect(self) -> bool:
        """Establish connection to the scanner API."""
        headers = {"Content-Type": "application/json", **self._auth_headers()}
        client = self._build_client(
            auth=self._auth_credentials(),
            headers=headers,
        )
        return self._connect_with_test(client)

    def test_connection(self) -> bool:
        """Ping the scanner's health-check endpoint."""
        try:
            response = self._client.get(self._test_endpoint)  # type: ignore[union-attr]
            return response.status_code == 200
        except Exception:
            return False

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Default rate-limit status. Override for scanner-specific info."""
        return {"limit": None, "remaining": None, "note": "Unknown"}

    # ------------------------------------------------------------------
    # Abstract data methods
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Convenience filters
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Parse helper (override in each scanner)
    # ------------------------------------------------------------------

    @abstractmethod
    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Map a single raw API record to ``ParsedVulnerability``."""
        ...
