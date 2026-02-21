"""
Rapid7 InsightVM / Nexpose API Connector.

API Docs: https://help.rapid7.com/insightvm/en-us/api/index.html

Status: STUB - Community contribution welcome!
"""

from typing import Iterator, List, Optional, Dict, Any
from datetime import datetime

from .base import BaseScannerConnector
from ..base import ConnectionConfig, AuthConfig, ConnectorStatus
from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity


class Rapid7Connector(BaseScannerConnector):
    """
    Rapid7 InsightVM / Nexpose API connector.
    
    Usage:
        from secimport.connectors.scanners import Rapid7Connector
        from secimport.connectors.base import ConnectionConfig, AuthConfig
        
        config = ConnectionConfig(base_url="https://insightvm.example.com:3780")
        auth = AuthConfig(
            auth_type="basic",
            credentials={"username": "user", "password": "pass"}
        )
        
        with Rapid7Connector(config, auth) as rapid7:
            for vuln in rapid7.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """
    
    name = "rapid7"
    vendor = "Rapid7"
    description = "Rapid7 InsightVM / Nexpose vulnerability scanner"
    auth_types = ["basic", "api_key"]
    
    ENDPOINTS = {
        "assets": "/api/3/assets",
        "vulnerabilities": "/api/3/vulnerabilities",
        "scans": "/api/3/scans",
        "asset_vulns": "/api/3/assets/{asset_id}/vulnerabilities",
    }
    
    def connect(self) -> bool:
        """Establish connection to Rapid7 API."""
        import httpx
        
        try:
            auth = None
            headers = {"Content-Type": "application/json"}
            
            if self.auth.auth_type == "basic":
                auth = (
                    self.auth.credentials["username"],
                    self.auth.credentials["password"],
                )
            elif self.auth.auth_type == "api_key":
                headers["X-Api-Key"] = self.auth.credentials["api_key"]
            
            self._client = httpx.Client(
                base_url=self.connection.base_url,
                auth=auth,
                headers=headers,
                timeout=self.connection.timeout,
                verify=self.connection.verify_ssl,
            )
            
            if self.test_connection():
                self.status = ConnectorStatus.CONNECTED
                return True
            
            return False
            
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            raise ConnectionError(f"Failed to connect to Rapid7: {e}")
    
    def disconnect(self) -> None:
        """Close Rapid7 connection."""
        if self._client:
            self._client.close()
            self._client = None
        self.status = ConnectorStatus.DISCONNECTED
    
    def test_connection(self) -> bool:
        """Test Rapid7 API connection."""
        try:
            response = self._client.get("/api/3/administration/info")
            return response.status_code == 200
        except Exception:
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get rate limit info."""
        return {"note": "Rapid7 rate limits vary by endpoint"}
    
    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of Rapid7 scans."""
        # TODO: Implement
        # GET /api/3/scans
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
        
        TODO: Implement using assets + vulnerabilities API
        GET /api/3/assets
        GET /api/3/assets/{id}/vulnerabilities
        """
        raise NotImplementedError("Community contribution welcome!")
    
    def get_assets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get assets from Rapid7."""
        # TODO: Implement
        # GET /api/3/assets
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
