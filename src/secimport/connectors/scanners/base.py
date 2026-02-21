"""
Base class for vulnerability scanner connectors.

Extend this for: Qualys, Nessus, Tenable, Rapid7, OpenVAS, CrowdStrike, etc.
"""

from abc import abstractmethod
from typing import Iterator, List, Optional, Dict, Any
from datetime import datetime

from ..base import BaseConnector
from ...models.base import ParsedVulnerability


class BaseScannerConnector(BaseConnector):
    """
    Base class for all vulnerability scanner API connectors.
    
    Implement this to add support for a new scanner.
    """
    
    @abstractmethod
    def get_scans(
        self,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get list of available scans.
        
        Args:
            limit: Maximum number of scans to return
            since: Only scans after this date
            
        Returns:
            List of scan metadata dicts
        """
        pass
    
    @abstractmethod
    def get_vulnerabilities(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[List[str]] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Fetch vulnerabilities from scanner.
        
        Args:
            scan_id: Specific scan to fetch (None = all/latest)
            severity: Filter by severity ["Critical", "High"]
            since: Only vulns detected after this date
            limit: Maximum results
            
        Yields:
            ParsedVulnerability objects
        """
        pass
    
    @abstractmethod
    def get_assets(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Get assets known to the scanner.
        
        Yields:
            Asset dicts from scanner
        """
        pass
    
    def get_critical_vulnerabilities(
        self,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Convenience method: Get only Critical severity.
        
        Yields:
            Critical vulnerabilities only
        """
        return self.get_vulnerabilities(
            severity=["Critical"],
            since=since,
            limit=limit,
        )
    
    def get_high_and_critical(
        self,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ParsedVulnerability]:
        """
        Convenience method: Get Critical and High severity.
        
        Yields:
            Critical and High vulnerabilities
        """
        return self.get_vulnerabilities(
            severity=["Critical", "High"],
            since=since,
            limit=limit,
        )
