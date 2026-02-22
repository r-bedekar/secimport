"""
Enrichment data models for asset correlation and gap analysis.

These models track provenance (which source contributed each field),
enable correlation across multiple sources, and report coverage gaps.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field


class FieldProvenance(BaseModel):
    """
    Tracks the value, source, and confidence for a single enriched field.

    When the same field is reported by multiple sources, the correlator
    keeps the value with the highest confidence.
    """

    value: Any = None
    source_system: str = Field(..., description="Source that provided this value")
    source_instance: Optional[str] = None
    timestamp: Optional[datetime] = None
    confidence: float = Field(default=1.0, ge=0, le=1)


class CorrelationKey(BaseModel):
    """
    A set of identifiers used to match records across sources.

    Two records are considered the same asset if they share any
    high-confidence identifier (agent_id, serial, MAC) or a
    combination of lower-confidence ones (hostname + IP).
    """

    hostnames: Set[str] = Field(default_factory=set)
    ip_addresses: Set[str] = Field(default_factory=set)
    mac_addresses: Set[str] = Field(default_factory=set)
    serial_numbers: Set[str] = Field(default_factory=set)
    agent_ids: Set[str] = Field(default_factory=set)

    def is_empty(self) -> bool:
        """Return True if no identifiers are present."""
        return not any([
            self.hostnames,
            self.ip_addresses,
            self.mac_addresses,
            self.serial_numbers,
            self.agent_ids,
        ])

    def overlaps(self, other: "CorrelationKey") -> bool:
        """Return True if any identifier set overlaps with another key."""
        return bool(
            (self.agent_ids & other.agent_ids)
            or (self.serial_numbers & other.serial_numbers)
            or (self.mac_addresses & other.mac_addresses)
            or (self.hostnames & other.hostnames)
            or (self.ip_addresses & other.ip_addresses)
        )

    def merge(self, other: "CorrelationKey") -> None:
        """Merge identifiers from another key into this one."""
        self.hostnames |= other.hostnames
        self.ip_addresses |= other.ip_addresses
        self.mac_addresses |= other.mac_addresses
        self.serial_numbers |= other.serial_numbers
        self.agent_ids |= other.agent_ids


class MatchResult(BaseModel):
    """Result of attempting to match a record to an existing enriched asset."""

    matched: bool = False
    confidence: float = Field(default=0.0, ge=0, le=1)
    matched_on: List[str] = Field(
        default_factory=list,
        description="Identifier types that matched (e.g. ['hostname', 'ip_address'])",
    )
    enriched_asset_index: Optional[int] = Field(
        None, description="Index of the matched asset in the correlator"
    )


class EnrichedAsset(BaseModel):
    """
    A merged asset with provenance tracking on every field.

    Built by the correlator from records ingested from multiple sources.
    Each field is a ``FieldProvenance`` so consumers know which source
    contributed each value and with what confidence.
    """

    # Correlation key — the union of all identifiers across sources
    correlation_key: CorrelationKey = Field(default_factory=CorrelationKey)

    # Core fields with provenance
    hostname: Optional[FieldProvenance] = None
    ip_address: Optional[FieldProvenance] = None
    mac_address: Optional[FieldProvenance] = None
    serial_number: Optional[FieldProvenance] = None
    agent_id: Optional[FieldProvenance] = None

    operating_system: Optional[FieldProvenance] = None
    os_version: Optional[FieldProvenance] = None
    asset_type: Optional[FieldProvenance] = None
    owner_email: Optional[FieldProvenance] = None
    owner_name: Optional[FieldProvenance] = None
    department: Optional[FieldProvenance] = None
    location: Optional[FieldProvenance] = None

    # Security posture (from EDR/AV)
    agent_status: Optional[FieldProvenance] = None
    policy_status: Optional[FieldProvenance] = None
    isolation_status: Optional[FieldProvenance] = None

    # Source tracking
    present_in_sources: Set[str] = Field(default_factory=set)
    absent_from_sources: Set[str] = Field(default_factory=set)

    # Vulnerability summary
    vulnerability_count: int = 0
    critical_vuln_count: int = 0
    high_vuln_count: int = 0

    # Raw records from each source for full detail
    source_records: Dict[str, List[Any]] = Field(default_factory=dict)

    def set_field(
        self,
        field_name: str,
        value: Any,
        source_system: str,
        confidence: float = 1.0,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """
        Set a field only if the new value has higher confidence.

        Args:
            field_name: Name of the field on this model.
            value: The value to set.
            source_system: Source system providing this value.
            confidence: Confidence score (0-1).
            timestamp: When the source last updated this value.
        """
        if value is None:
            return

        current = getattr(self, field_name, None)
        if current is None or confidence > current.confidence:
            setattr(
                self,
                field_name,
                FieldProvenance(
                    value=value,
                    source_system=source_system,
                    confidence=confidence,
                    timestamp=timestamp,
                ),
            )


class GapReport(BaseModel):
    """
    Coverage gap analysis between two sources.

    Shows which assets are in source A but not B, in B but not A,
    and in both.
    """

    source_a: str
    source_b: str
    in_a_not_b: List[CorrelationKey] = Field(default_factory=list)
    in_b_not_a: List[CorrelationKey] = Field(default_factory=list)
    in_both: List[CorrelationKey] = Field(default_factory=list)

    @property
    def total_a(self) -> int:
        return len(self.in_a_not_b) + len(self.in_both)

    @property
    def total_b(self) -> int:
        return len(self.in_b_not_a) + len(self.in_both)

    @property
    def coverage_a_to_b(self) -> float:
        """Fraction of source A assets also found in source B."""
        total = self.total_a
        return len(self.in_both) / total if total else 0.0

    @property
    def coverage_b_to_a(self) -> float:
        """Fraction of source B assets also found in source A."""
        total = self.total_b
        return len(self.in_both) / total if total else 0.0
