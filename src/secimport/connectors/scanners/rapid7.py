"""
Rapid7 InsightVM / Nexpose API Connector.

API Docs: https://help.rapid7.com/insightvm/en-us/api/index.html

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from .base import BaseScannerConnector


class Rapid7Connector(BaseScannerConnector):
    """
    Rapid7 InsightVM / Nexpose API connector.

    Usage::

        from secimport.connectors.scanners import Rapid7Connector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://insightvm.example.com:3780")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "user", "password": "pass"},
        )

        with Rapid7Connector(config, auth) as rapid7:
            for vuln in rapid7.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """

    name: ClassVar[str] = "rapid7"
    vendor: ClassVar[str] = "Rapid7"
    description: ClassVar[str] = "Rapid7 InsightVM / Nexpose vulnerability scanner"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic", "api_key")

    _test_endpoint: ClassVar[str] = "/api/3/administration/info"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "assets": "/api/3/assets",
        "vulnerabilities": "/api/3/vulnerabilities",
        "scans": "/api/3/scans",
        "asset_vulns": "/api/3/assets/{asset_id}/vulnerabilities",
    }

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth.auth_type == "api_key":
            return {"X-Api-Key": self.auth.credentials["api_key"]}
        return {}

    def get_rate_limit_status(self) -> Dict[str, Any]:
        return {"note": "Rapid7 rate limits vary by endpoint"}

    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of Rapid7 scans.  GET /api/3/scans"""
        raise NotImplementedError("Community contribution welcome!")

    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from Rapid7.

        GET /api/3/assets
        GET /api/3/assets/{id}/vulnerabilities
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_assets(self, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Get assets.  GET /api/3/assets"""
        raise NotImplementedError("Community contribution welcome!")

    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Parse Rapid7 vuln into normalized format."""
        return ParsedVulnerability(
            scanner_id=str(raw.get("id", "")),
            cve_id=raw.get("cve"),
            title=raw.get("title", "Unknown"),
            severity=normalize_severity(raw.get("severity"), "rapid7"),
            cvss_score=raw.get("cvss", {}).get("v3", {}).get("score"),
            description=raw.get("description"),
            solution=raw.get("solution"),
            hostname=raw.get("host_name"),
            ip_address=raw.get("ip"),
            port=raw.get("port"),
            protocol=raw.get("protocol"),
            extra=raw,
        )
