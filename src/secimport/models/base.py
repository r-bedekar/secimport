"""
Base data models for secimport.

All parsers output these normalized models.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ParsedVulnerability(BaseModel):
    """Normalized vulnerability from any scanner."""
    
    # Identifiers
    scanner_id: Optional[str] = Field(None, description="Scanner-specific ID (QID, Plugin ID)")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    title: str = Field(..., description="Vulnerability title")
    
    # Classification
    severity: str = Field(..., description="Normalized: Critical, High, Medium, Low")
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    
    # Details
    description: Optional[str] = None
    solution: Optional[str] = None
    
    # Asset info
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    
    # Dates
    first_detected: Optional[datetime] = None
    last_detected: Optional[datetime] = None
    
    # Extra fields not in standard schema
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParsedAsset(BaseModel):
    """Normalized asset from any source."""
    
    # Identifiers (at least one required)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    
    # Classification
    asset_type: Optional[str] = None  # Server, Workstation, Network Device
    environment: Optional[str] = None  # Production, Development, Test
    criticality: Optional[str] = None  # Critical, High, Medium, Low
    
    # Ownership
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    department: Optional[str] = None
    business_unit: Optional[str] = None
    cost_center: Optional[str] = None
    
    # Technical details
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    location: Optional[str] = None
    
    # Extra fields
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParsedOwnerMapping(BaseModel):
    """Normalized owner mapping from IPAM, CMDB, AD, etc."""
    
    # What this mapping applies to
    ip_address: Optional[str] = None
    ip_range: Optional[str] = None  # CIDR notation: 10.0.0.0/24
    hostname_pattern: Optional[str] = None  # Regex or glob pattern
    subnet: Optional[str] = None
    
    # Owner info
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    department: Optional[str] = None
    business_unit: Optional[str] = None
    location: Optional[str] = None
    
    # Source metadata
    source_system: Optional[str] = None  # IPAM, CMDB, AD
    confidence: float = Field(default=1.0, ge=0, le=1)
    
    # Extra fields
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParseResult(BaseModel):
    """Result of parsing a file."""
    
    source_type: str = Field(..., description="Detected source: qualys, nessus, cmdb, etc.")
    data_type: str = Field(..., description="Type: vulnerability, asset, owner")
    file_path: Optional[str] = None
    total_rows: int = 0
    parsed_count: int = 0
    error_count: int = 0
    errors: List[str] = Field(default_factory=list)
