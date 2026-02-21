"""
OpenVAS / Greenbone API Connector.

API Docs: https://docs.greenbone.net/API/GMP/gmp-22.04.html

Status: STUB - Community contribution welcome!
"""

from typing import Iterator, List, Optional, Dict, Any
from datetime import datetime

from .base import BaseScannerConnector
from ..base import ConnectionConfig, AuthConfig, ConnectorStatus
from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity


class OpenVASConnector(BaseScannerConnector):
    """
    OpenVAS / Greenbone Vulnerability Manager connector.
    
    Uses GMP (Greenbone Management Protocol) over HTTP/HTTPS.
    
    Usage:
        from secimport.connectors.scanners import OpenVASConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig
        
        config = ConnectionConfig(base_url="https://openvas.example.com:9390")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "admin", "password": "pass"}
        )
        
        with OpenVASConnector(config, auth) as openvas:
            for vuln in openvas.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """
    
    name = "openvas"
    vendor = "Greenbone"
    description = "OpenVAS / Greenbone Vulnerability Manager"
    auth_types = ["basic"]
    
    ENDPOINTS = {
        "get_tasks": "/gmp?cmd=get_tasks",
        "get_reports": "/gmp?cmd=get_reports",
        "get_results": "/gmp?cmd=get_results",
    }
    
    def connect(self) -> bool:
        """Establish connection to OpenVAS GMP API."""
        import httpx
        
        try:
            auth = (
                self.auth.credentials["username"],
                self.auth.credentials["password"],
            )
            
            self._client = httpx.Client(
                base_url=self.connection.base_url,
                auth=auth,
                timeout=self.connection.timeout,
                verify=self.connection.verify_ssl,
            )
            
            if self.test_connection():
                self.status = ConnectorStatus.CONNECTED
                return True
            
            return False
            
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            raise ConnectionError(f"Failed to connect to OpenVAS: {e}")
    
    def disconnect(self) -> None:
        """Close OpenVAS connection."""
        if self._client:
            self._client.close()
            self._client = None
        self.status = ConnectorStatus.DISCONNECTED
    
    def test_connection(self) -> bool:
        """Test OpenVAS API connection."""
        try:
            response = self._client.get("/gmp?cmd=get_version")
            return response.status_code == 200
        except Exception:
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get rate limit info (OpenVAS has no rate limiting)."""
        return {"limit": None, "note": "OpenVAS has no rate limiting"}
    
    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of OpenVAS tasks/scans."""
        # TODO: Implement
        # GET /gmp?cmd=get_tasks
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
        
        TODO: Implement using get_results
        GET /gmp?cmd=get_results&report_id={id}
        """
        raise NotImplementedError("Community contribution welcome!")
    
    def get_assets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get assets/hosts from OpenVAS."""
        # TODO: Implement
        # GET /gmp?cmd=get_hosts
        raise NotImplementedError("Community contribution welcome!")
    
    def _parse_vulnerability(self, raw: Dict[str, Any]) -> ParsedVulnerability:
        """Parse OpenVAS result into normalized format."""
        return ParsedVulnerability(
            scanner_id=str(raw.get("nvt", {}).get("oid", "")),
            cve_id=raw.get("nvt", {}).get("cve"),
            title=raw.get("nvt", {}).get("name", "Unknown"),
            severity=normalize_severity(raw.get("threat"), "openvas"),
            cvss_score=raw.get("nvt", {}).get("cvss_base"),
            description=raw.get("description"),
            solution=raw.get("nvt", {}).get("solution"),
            hostname=raw.get("host", {}).get("hostname"),
            ip_address=raw.get("host", {}).get("ip"),
            port=raw.get("port"),
            extra=raw,
        )
