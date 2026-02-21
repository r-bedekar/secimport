"""
CrowdStrike Falcon Spotlight API Connector.

API Docs: https://falcon.crowdstrike.com/documentation/

Status: STUB - Community contribution welcome!
"""

import logging
from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

import httpx

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from .base import BaseScannerConnector

logger = logging.getLogger("secimport.connectors")


class CrowdStrikeConnector(BaseScannerConnector):
    """
    CrowdStrike Falcon Spotlight vulnerability connector.

    Uses OAuth2 client-credentials flow for authentication.

    Usage::

        from secimport.connectors.scanners import CrowdStrikeConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://api.crowdstrike.com")
        auth = AuthConfig(
            auth_type="oauth2",
            credentials={"client_id": "xxx", "client_secret": "yyy"},
        )

        with CrowdStrikeConnector(config, auth) as cs:
            for vuln in cs.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """

    name: ClassVar[str] = "crowdstrike"
    vendor: ClassVar[str] = "CrowdStrike"
    description: ClassVar[str] = "CrowdStrike Falcon Spotlight vulnerability management"
    auth_types: ClassVar[Tuple[str, ...]] = ("oauth2",)

    _test_endpoint: ClassVar[str] = "/sensors/queries/installers/v1?limit=1"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "oauth2_token": "/oauth2/token",
        "vulns": "/spotlight/combined/vulnerabilities/v1",
        "hosts": "/devices/queries/devices/v1",
        "host_details": "/devices/entities/devices/v2",
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._access_token: Optional[str] = None

    def connect(self) -> bool:
        """Establish connection via OAuth2 client-credentials flow."""
        # Obtain an access token first
        token_client = httpx.Client(
            base_url=self.connection.base_url,
            timeout=self.connection.timeout,
            verify=self.connection.verify_ssl,
        )
        try:
            token_response = token_client.post(
                self.ENDPOINTS["oauth2_token"],
                data={
                    "client_id": self.auth.credentials["client_id"],
                    "client_secret": self.auth.credentials["client_secret"],
                },
            )
            if token_response.status_code != 201:
                raise ConnectionError("Failed to obtain OAuth2 token from CrowdStrike")

            self._access_token = token_response.json()["access_token"]
        finally:
            token_client.close()

        # Build the authenticated client
        client = self._build_client(
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
            },
        )
        return self._connect_with_test(client)

    def disconnect(self) -> None:
        super().disconnect()
        self._access_token = None

    def get_rate_limit_status(self) -> Dict[str, Any]:
        return {
            "note": "CrowdStrike uses per-minute rate limits",
            "see": "X-RateLimit-* response headers",
        }

    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """CrowdStrike doesn't have traditional scans."""
        return []

    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from CrowdStrike Spotlight.

        GET /spotlight/combined/vulnerabilities/v1
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_assets(self, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """
        Get hosts from CrowdStrike.

        GET /devices/queries/devices/v1
        GET /devices/entities/devices/v2
        """
        raise NotImplementedError("Community contribution welcome!")

    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Parse CrowdStrike vuln into normalized format."""
        cve = raw.get("cve", {})
        host = raw.get("host_info", {})
        return ParsedVulnerability(
            scanner_id=str(raw.get("id", "")),
            cve_id=cve.get("id"),
            title=cve.get("description", "Unknown")[:200],
            severity=normalize_severity(cve.get("severity"), "generic"),
            cvss_score=cve.get("base_score"),
            description=cve.get("description"),
            solution=raw.get("remediation"),
            hostname=host.get("hostname"),
            ip_address=host.get("local_ip"),
            extra=raw,
        )
