"""
CrowdStrike Falcon Spotlight API Connector.

API Docs: https://falcon.crowdstrike.com/documentation/

Status: STUB - Community contribution welcome!
"""

from typing import Iterator, List, Optional, Dict, Any
from datetime import datetime

from .base import BaseScannerConnector
from ..base import ConnectionConfig, AuthConfig, ConnectorStatus
from ...models.base import ParsedVulnerability
from ...normalizers.severity import normalize_severity


class CrowdStrikeConnector(BaseScannerConnector):
    """
    CrowdStrike Falcon Spotlight vulnerability connector.
    
    Usage:
        from secimport.connectors.scanners import CrowdStrikeConnector
        from secimport.connectors.base import ConnectionConfig, AuthConfig
        
        config = ConnectionConfig(base_url="https://api.crowdstrike.com")
        auth = AuthConfig(
            auth_type="oauth2",
            credentials={"client_id": "xxx", "client_secret": "yyy"}
        )
        
        with CrowdStrikeConnector(config, auth) as cs:
            for vuln in cs.get_vulnerabilities():
                print(vuln.cve_id, vuln.severity)
    """
    
    name = "crowdstrike"
    vendor = "CrowdStrike"
    description = "CrowdStrike Falcon Spotlight vulnerability management"
    auth_types = ["oauth2"]
    
    ENDPOINTS = {
        "oauth2_token": "/oauth2/token",
        "vulns": "/spotlight/combined/vulnerabilities/v1",
        "hosts": "/devices/queries/devices/v1",
        "host_details": "/devices/entities/devices/v2",
    }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._access_token: Optional[str] = None
    
    def connect(self) -> bool:
        """Establish connection to CrowdStrike API."""
        import httpx
        
        try:
            # First get OAuth2 token
            token_client = httpx.Client(
                base_url=self.connection.base_url,
                timeout=self.connection.timeout,
                verify=self.connection.verify_ssl,
            )
            
            token_response = token_client.post(
                self.ENDPOINTS["oauth2_token"],
                data={
                    "client_id": self.auth.credentials["client_id"],
                    "client_secret": self.auth.credentials["client_secret"],
                },
            )
            
            if token_response.status_code != 201:
                raise ConnectionError("Failed to get OAuth2 token")
            
            self._access_token = token_response.json()["access_token"]
            token_client.close()
            
            # Create authenticated client
            self._client = httpx.Client(
                base_url=self.connection.base_url,
                headers={
                    "Authorization": f"Bearer {self._access_token}",
                    "Content-Type": "application/json",
                },
                timeout=self.connection.timeout,
                verify=self.connection.verify_ssl,
            )
            
            if self.test_connection():
                self.status = ConnectorStatus.CONNECTED
                return True
            
            return False
            
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            raise ConnectionError(f"Failed to connect to CrowdStrike: {e}")
    
    def disconnect(self) -> None:
        """Close CrowdStrike connection."""
        if self._client:
            self._client.close()
            self._client = None
        self._access_token = None
        self.status = ConnectorStatus.DISCONNECTED
    
    def test_connection(self) -> bool:
        """Test CrowdStrike API connection."""
        try:
            response = self._client.get("/sensors/queries/installers/v1?limit=1")
            return response.status_code == 200
        except Exception:
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get CrowdStrike rate limit info."""
        return {
            "note": "CrowdStrike uses per-minute rate limits",
            "see": "X-RateLimit-* response headers",
        }
    
    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """CrowdStrike doesn't have traditional scans - returns empty."""
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
        
        TODO: Implement using Spotlight API
        GET /spotlight/combined/vulnerabilities/v1
        """
        raise NotImplementedError("Community contribution welcome!")
    
    def get_assets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Get hosts from CrowdStrike."""
        # TODO: Implement
        # GET /devices/queries/devices/v1
        # GET /devices/entities/devices/v2
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
