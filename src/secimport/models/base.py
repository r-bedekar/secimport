"""
Base data models for secimport.

All parsers and connectors output these normalized models.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SourceMetadata(BaseModel):
    """
    Provenance and timestamp tracking for all ingested records.

    Every record knows which system produced it, when it was ingested,
    and an optional source-side record ID for traceability.
    """

    source_system: Optional[str] = Field(
        None, description="System that produced this record (e.g. 'crowdstrike', 'qualys')"
    )
    source_instance: Optional[str] = Field(
        None, description="Specific instance URL or identifier"
    )
    ingested_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when this record was ingested",
    )
    source_updated_at: Optional[datetime] = Field(
        None, description="Last update timestamp from the source system"
    )
    record_id: Optional[str] = Field(
        None, description="Unique ID from the source system"
    )


class ParsedVulnerability(SourceMetadata):
    """Normalized vulnerability from any scanner."""

    # Identifiers
    scanner_id: Optional[str] = Field(
        None, description="Scanner-specific ID (QID, Plugin ID)"
    )
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    title: str = Field(..., description="Vulnerability title")

    # Classification
    severity: str = Field(
        ..., description="Normalized: Critical, High, Medium, Low"
    )
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


class ParsedAsset(SourceMetadata):
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


class ParsedOwnerMapping(SourceMetadata):
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
    confidence: float = Field(default=1.0, ge=0, le=1)

    # Extra fields
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParsedEndpoint(SourceMetadata):
    """
    Normalized endpoint from EDR, AV, XDR, or MDM sources.

    Captures agent-level data that tools like CrowdStrike Falcon,
    Microsoft Defender, SentinelOne, and antivirus products provide.
    """

    # Identifiers
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    agent_id: Optional[str] = Field(
        None, description="EDR/AV agent unique identifier"
    )
    device_id: Optional[str] = Field(
        None, description="Platform device ID"
    )

    # Agent status
    agent_version: Optional[str] = None
    agent_status: Optional[str] = Field(
        None, description="Online, Offline, Degraded, Uninstalled"
    )
    last_seen: Optional[datetime] = None
    first_seen: Optional[datetime] = None

    # Platform details
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    os_build: Optional[str] = None
    architecture: Optional[str] = Field(
        None, description="x86_64, arm64, etc."
    )
    manufacturer: Optional[str] = None
    model: Optional[str] = None

    # Security posture
    policy_name: Optional[str] = None
    policy_status: Optional[str] = Field(
        None, description="Compliant, Non-Compliant, Unknown"
    )
    isolation_status: Optional[str] = Field(
        None, description="Normal, Isolated, Pending"
    )
    prevention_mode: Optional[str] = Field(
        None, description="Detect, Prevent, Disabled"
    )
    signatures_up_to_date: Optional[bool] = None
    last_scan_date: Optional[datetime] = None

    # Classification
    endpoint_type: Optional[str] = Field(
        None, description="Workstation, Server, Container, Mobile"
    )
    site_name: Optional[str] = Field(
        None, description="Site/group in the EDR/AV console"
    )
    tags: List[str] = Field(default_factory=list)

    # Ownership (may come from EDR group assignment or AD integration)
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    department: Optional[str] = None

    # Extra
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParsedUser(SourceMetadata):
    """Normalized user from directory services, IdP, or HR systems."""

    # Identifiers
    username: Optional[str] = None
    email: Optional[str] = None
    employee_id: Optional[str] = None
    display_name: Optional[str] = None
    distinguished_name: Optional[str] = None

    # Status
    enabled: Optional[bool] = None
    last_login: Optional[datetime] = None
    account_created: Optional[datetime] = None

    # Organization
    department: Optional[str] = None
    title: Optional[str] = None
    manager_email: Optional[str] = None
    manager_name: Optional[str] = None
    business_unit: Optional[str] = None
    location: Optional[str] = None
    cost_center: Optional[str] = None

    # Groups
    groups: List[str] = Field(default_factory=list)

    # Extra
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParsedGroup(SourceMetadata):
    """Normalized group from directory services."""

    name: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    group_type: Optional[str] = Field(
        None, description="Security, Distribution, DynamicDistribution"
    )
    member_count: Optional[int] = None
    members: List[str] = Field(
        default_factory=list,
        description="List of member identifiers (email or DN)",
    )

    # Extra
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParsedNetworkObservation(SourceMetadata):
    """Normalized network observation from NDR tools."""

    # Observed entity
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None

    # Network metadata
    vlan: Optional[str] = None
    subnet: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None

    # Observation details
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    device_type_guess: Optional[str] = Field(
        None, description="NDR's device classification guess"
    )
    risk_score: Optional[float] = Field(None, ge=0, le=100)

    # Tags/labels from the NDR
    tags: List[str] = Field(default_factory=list)

    # Extra
    extra: Dict[str, Any] = Field(default_factory=dict)


class ParseResult(BaseModel):
    """Result of parsing a file."""

    source_type: str = Field(
        ..., description="Detected source: qualys, nessus, cmdb, etc."
    )
    data_type: str = Field(
        ..., description="Type: vulnerability, asset, owner"
    )
    file_path: Optional[str] = None
    total_rows: int = 0
    parsed_count: int = 0
    error_count: int = 0
    skipped_count: int = 0
    errors: List[str] = Field(default_factory=list)
    duration_seconds: Optional[float] = None
    parser_name: Optional[str] = None
