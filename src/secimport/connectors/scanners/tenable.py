"""
Tenable.io / Tenable.sc API Connector.

API Docs: https://developer.tenable.com/reference/navigate

Status: STUB - Community contribution welcome!
"""

from typing import Iterator, List, Optional, Dict, Any
from datetime import datetime

from .base import BaseScannerConnector
from ..base import ConnectionConfig, AuthConfig, ConnectorStatus
from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity


class TenableConnector(BaseScannerConnector):
    """
    Tenable.io and Tenable.sc API connector.
    
    Usage:
        from secimport.connectors.scanners import TenableConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig
        
        config = ConnectionConfig(base_url="https://cloud.tenable.com")
        auth = AuthConfig(
            auth_type="api_key",
            credentials={"access_key": "xxx", "secret_key": "yyy"}
        )
        
        with TenableConnector(config, auth) as tenable:
            for vuln in tenable.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """
    
    name = "tenable"
    vendor = "Tenable"
    description = "Tenable.io / Tenable.sc vulnerability management"
    auth_types = ["api_key"]
    
    ENDPOINTS = {
        "vulns_export": "/vulns/export",
        "assets_export": "/assets/export",
        "scans": "/scans",
    }
    
    def connect(self) -> bool:
        """Establish connection to Tenable API."""
        import httpx
        
        try:
            headers = {
                "Content-Type": "application/json",
                "X-ApiKeys": (
                    f"accessKey={self.auth.credentials['access_key']};"
                    f"secretKey={self.auth.credentials['secret_key']}"
                ),
            }
            
            self._client = httpx.Client(
                base_url=self.connection.base_url,
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
            raise ConnectionError(f"Failed to connect to Tenable: {e}")
    
    def disconnect(self) -> None:
        """Close Tenable connection."""
        if self._client:
            self._client.close()
            self._client = None
        self.status = ConnectorStatus.DISCONNECTED
    
    def test_connection(self) -> bool:
        """Test Tenable API connection."""
        try:
            response = self._client.get("/server/status")
            return response.status_code == 200
        except Exception:
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get Tenable rate limit info."""
        return {
            "note": "Tenable.io: 1400 requests per 5 minutes",
            "limit": 1400,
            "window": "5 minutes",
        }
    
    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Get list of Tenable scans."""
        # TODO: Implement
        # GET /scans
        raise NotImplementedError("Community contribution welcome!")
    
    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from Tenable.
        
        TODO: Implement using export API
        POST /vulns/export
        GET /vulns/export/{export_uuid}/status
        GET /vulns/export/{export_uuid}/chunks/{chunk_id}
        """
        raise NotImplementedError("Community contribution welcome!")
    
    def get_assets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get assets from Tenable."""
        # TODO: Implement using /assets/export
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
