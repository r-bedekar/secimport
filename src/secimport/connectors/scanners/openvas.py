"""
OpenVAS / Greenbone API Connector.

API Docs: https://docs.greenbone.net/API/GMP/gmp-22.04.html

Status: STUB - Community contribution welcome!
"""

from datetime import datetime
from typing import Any, ClassVar, Dict, Iterator, List, Optional, Tuple

from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity
from .base import BaseScannerConnector


class OpenVASConnector(BaseScannerConnector):
    """
    OpenVAS / Greenbone Vulnerability Manager connector.

    Uses GMP (Greenbone Management Protocol) over HTTP/HTTPS.

    Usage::

        from secimport.connectors.scanners import OpenVASConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig

        config = ConnectionConfig(base_url="https://openvas.example.com:9390")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "admin", "password": "pass"},
        )

        with OpenVASConnector(config, auth) as openvas:
            for vuln in openvas.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """

    name: ClassVar[str] = "openvas"
    vendor: ClassVar[str] = "Greenbone"
    description: ClassVar[str] = "OpenVAS / Greenbone Vulnerability Manager"
    auth_types: ClassVar[Tuple[str, ...]] = ("basic",)

    _test_endpoint: ClassVar[str] = "/gmp?cmd=get_version"

    ENDPOINTS: ClassVar[Dict[str, str]] = {
        "get_tasks": "/gmp?cmd=get_tasks",
        "get_reports": "/gmp?cmd=get_reports",
        "get_results": "/gmp?cmd=get_results",
    }

    def get_rate_limit_status(self) -> Dict[str, Any]:
        return {"limit": None, "note": "OpenVAS has no rate limiting"}

    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of OpenVAS tasks/scans.  GET /gmp?cmd=get_tasks"""
        raise NotImplementedError("Community contribution welcome!")

    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from OpenVAS.

        GET /gmp?cmd=get_results&report_id={id}
        """
        raise NotImplementedError("Community contribution welcome!")

    def get_assets(self, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Get assets/hosts.  GET /gmp?cmd=get_hosts"""
        raise NotImplementedError("Community contribution welcome!")

    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Parse OpenVAS result into normalized format."""
        nvt = raw.get("nvt", {})
        host = raw.get("host", {})
        return ParsedVulnerability(
            scanner_id=str(nvt.get("oid", "")),
            cve_id=nvt.get("cve"),
            title=nvt.get("name", "Unknown"),
            severity=normalize_severity(raw.get("threat"), "openvas"),
            cvss_score=nvt.get("cvss_base"),
            description=raw.get("description"),
            solution=nvt.get("solution"),
            hostname=host.get("hostname"),
            ip_address=host.get("ip"),
            port=raw.get("port"),
            extra=raw,
        )
