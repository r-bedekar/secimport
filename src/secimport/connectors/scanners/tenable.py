"""
Tenable.io / Tenable.sc API Connector.

API Docs: https://developer.tenable.com/reference/navigate

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from .base import BaseScannerConnector


class TenableConnector(BaseScannerConnector):
    """
    Tenable.io and Tenable.sc API connector.

    Usage::

        from secimport.connectors.scanners import TenableConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://cloud.tenable.com")
        auth = AuthConfig(
            auth_type="api_key",
            credentials={"access_key": "xxx", "secret_key": "yyy"},
        )

        with TenableConnector(config, auth) as tenable:
            for vuln in tenable.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """

    name: ClassVar[str] = "tenable"
    vendor: ClassVar[str] = "Tenable"
    description: ClassVar[str] = "Tenable.io / Tenable.sc vulnerability management"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key",)

    _test_endpoint: ClassVar[str] = "/server/status"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "vulns_export": "/vulns/export",
        "assets_export": "/assets/export",
        "scans": "/scans",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "X-ApiKeys": (
                f"accessKey={self.auth.credentials['access_key']};"
                f"secretKey={self.auth.credentials['secret_key']}"
            ),
        }

    def get_rate_limit_status(self) -> Dict[str, Any]:
        return {
            "limit": 1400,
            "window": "5 minutes",
            "note": "Tenable.io: 1400 requests per 5 minutes",
        }

    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of Tenable scans.  GET /scans"""
        raise NotImplementedError("Community contribution welcome!")

    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from Tenable export API.

        POST /vulns/export
        GET  /vulns/export/{export_uuid}/status
        GET  /vulns/export/{export_uuid}/chunks/{chunk_id}
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_assets(self, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Get assets via /assets/export."""
        raise NotImplementedError("Community contribution welcome!")

    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Parse Tenable vuln into normalized format."""
        return ParsedVulnerability(
            scanner_id=str(raw.get("plugin_id", "")),
            cve_id=raw.get("cve"),
            title=raw.get("plugin_name", "Unknown"),
            severity=normalize_severity(raw.get("severity"), "tenable"),
            cvss_score=raw.get("cvss_base_score"),
            description=raw.get("description"),
            solution=raw.get("solution"),
            hostname=raw.get("hostname"),
            ip_address=raw.get("ip_address"),
            port=raw.get("port"),
            protocol=raw.get("protocol"),
            first_detected=raw.get("first_found"),
            last_detected=raw.get("last_found"),
            extra=raw,
        )
