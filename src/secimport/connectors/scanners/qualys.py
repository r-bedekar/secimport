"""
Qualys API Connector.

API Docs: https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from .base import BaseScannerConnector


class QualysConnector(BaseScannerConnector):
    """
    Qualys VMDR API connector.

    Usage::

        from secimport.connectors.scanners import QualysConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://qualysapi.qualys.com")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "user", "password": "pass"},
        )

        with QualysConnector(config, auth) as qualys:
            for vuln in qualys.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """

    name: ClassVar[str] = "qualys"
    vendor: ClassVar[str] = "Qualys"
    description: ClassVar[str] = "Qualys VMDR vulnerability scanner"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic", "api_key")

    _test_endpoint: ClassVar[str] = "/api/2.0/fo/scan/"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "scan_list": "/api/2.0/fo/scan/",
        "vuln_list": "/api/2.0/fo/asset/host/vm/detection/",
        "asset_list": "/api/2.0/fo/asset/host/",
        "knowledge_base": "/api/2.0/fo/knowledge_base/vuln/",
    }

    def _auth_headers(self) -> Dict[str, str]:
        return {"X-Requested-With": "secimport"}

    def test_connection(self) -> bool:
        """Test Qualys API connection with a lightweight scan list call."""
        try:
            response = self._client.post(  # type: ignore[union-attr]
                self.ENDPOINTS["scan_list"],
                data={"action": "list", "show_last": "1"},
            )
            return response.status_code == 200
        except Exception:
            return False

    def get_rate_limit_status(self) -> Dict[str, Any]:
        return {
            "limit": "Parse from X-RateLimit-Limit header",
            "remaining": "Parse from X-RateLimit-Remaining header",
            "reset": "Parse from X-RateLimit-Reset header",
        }

    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of Qualys scans.  POST /api/2.0/fo/scan/?action=list"""
        raise NotImplementedError("Community contribution welcome!")

    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from Qualys Host Detection API.

        POST /api/2.0/fo/asset/host/vm/detection/
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_assets(self, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Get assets.  POST /api/2.0/fo/asset/host/?action=list"""
        raise NotImplementedError("Community contribution welcome!")

    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Parse Qualys detection into normalized vulnerability."""
        return ParsedVulnerability(
            scanner_id=str(raw.get("QID", "")),
            cve_id=raw.get("CVE_ID"),
            title=raw.get("TITLE", "Unknown"),
            severity=normalize_severity(raw.get("SEVERITY"), "qualys"),
            cvss_score=raw.get("CVSS_BASE"),
            description=raw.get("THREAT"),
            solution=raw.get("SOLUTION"),
            hostname=raw.get("DNS"),
            ip_address=raw.get("IP"),
            port=raw.get("PORT"),
            protocol=raw.get("PROTOCOL"),
            extra=raw,
        )
