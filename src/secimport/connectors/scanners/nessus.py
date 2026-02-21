"""
Nessus API Connector.

API Docs: https://developer.tenable.com/reference/navigate

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from .base import BaseScannerConnector


class NessusConnector(BaseScannerConnector):
    """
    Nessus Professional/Essentials API connector.

    Note: For Tenable.io/Tenable.sc, use ``TenableConnector`` instead.

    Usage::

        from secimport.connectors.scanners import NessusConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://localhost:8834")
        auth = AuthConfig(
            auth_type="api_key",
            credentials={"access_key": "xxx", "secret_key": "yyy"},
        )

        with NessusConnector(config, auth) as nessus:
            for vuln in nessus.get_vulnerabilities(scan_id="123"):
                print(vuln.cve_id, vuln.severity)
    """

    name: ClassVar[str] = "nessus"
    vendor: ClassVar[str] = "Tenable"
    description: ClassVar[str] = "Nessus Professional/Essentials vulnerability scanner"
    auth_types: ClassVar[Tuple[str, ...]] = ("api_key", "basic")

    _test_endpoint: ClassVar[str] = "/server/status"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "scans": "/scans",
        "scan_details": "/scans/{scan_id}",
        "export": "/scans/{scan_id}/export",
        "plugins": "/plugins/plugin/{plugin_id}",
    }

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth.auth_type == "api_key":
            return {
                "X-ApiKeys": (
                    f"accessKey={self.auth.credentials['access_key']}; "
                    f"secretKey={self.auth.credentials['secret_key']}"
                ),
            }
        return {}

    def get_rate_limit_status(self) -> Dict[str, Any]:
        return {"limit": None, "remaining": None, "note": "Nessus has no rate limiting"}

    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of Nessus scans.  GET /scans"""
        raise NotImplementedError("Community contribution welcome!")

    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from Nessus scan export.

        GET /scans/{scan_id}/export
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_assets(self, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Get assets from Nessus."""
        raise NotImplementedError("Community contribution welcome!")

    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Parse Nessus finding into normalized vulnerability."""
        return ParsedVulnerability(
            scanner_id=str(raw.get("plugin_id", "")),
            cve_id=raw.get("cve"),
            title=raw.get("plugin_name", "Unknown"),
            severity=normalize_severity(raw.get("severity"), "nessus"),
            cvss_score=raw.get("cvss_base_score"),
            description=raw.get("synopsis"),
            solution=raw.get("solution"),
            hostname=raw.get("host"),
            ip_address=raw.get("host_ip"),
            port=raw.get("port"),
            protocol=raw.get("protocol"),
            extra=raw,
        )
