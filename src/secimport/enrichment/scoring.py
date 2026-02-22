"""
Confidence scoring for asset correlation.

Defines how much weight each identifier type and source system
carries when merging records from multiple sources.
"""

from typing import ClassVar, Dict


class MatchWeights:
    """
    Weights for each identifier type when matching records.

    Higher weight = more confident that two records with the
    same value for this identifier are the same physical asset.
    """

    WEIGHTS: ClassVar[Dict[str, float]] = {
        "agent_id": 0.99,
        "serial_number": 0.95,
        "mac_address": 0.90,
        "hostname": 0.85,
        "ip_address": 0.70,
    }

    @classmethod
    def get(cls, identifier_type: str) -> float:
        """Return the match weight for an identifier type."""
        return cls.WEIGHTS.get(identifier_type, 0.5)

    @classmethod
    def best_match_confidence(cls, matched_on: list[str]) -> float:
        """
        Return the highest confidence from a list of matched identifier types.

        Args:
            matched_on: List of identifier type names that matched.

        Returns:
            The highest weight among matched types, or 0.0 if empty.
        """
        if not matched_on:
            return 0.0
        return max(cls.get(m) for m in matched_on)


class SourceConfidence:
    """
    Confidence scores for each source system category.

    Used to weight field provenance when multiple sources
    report different values for the same field.
    """

    SCORES: ClassVar[Dict[str, float]] = {
        # EDR/AV — agents installed on endpoint, very reliable
        "edr": 0.95,
        "crowdstrike": 0.95,
        "crowdstrike_falcon": 0.95,
        "defender_endpoint": 0.95,
        "sentinelone": 0.95,
        "carbon_black": 0.95,
        "symantec_endpoint": 0.90,
        "trellix": 0.90,
        "trend_micro": 0.90,
        # XDR — extended detection, high reliability
        "xdr": 0.93,
        "cortex_xdr": 0.93,
        "vision_one": 0.93,
        # Cloud providers — authoritative for cloud assets
        "cloud": 0.90,
        "aws": 0.90,
        "azure": 0.90,
        "gcp": 0.90,
        # AV standalone
        "av": 0.90,
        # CMDB — manually maintained, good but can drift
        "cmdb": 0.85,
        "servicenow": 0.85,
        "bmc_helix": 0.85,
        # Directory — authoritative for users/groups
        "directory": 0.85,
        "active_directory": 0.85,
        "azure_ad": 0.85,
        # Vulnerability scanners — good at discovery
        "scanner": 0.80,
        "qualys": 0.80,
        "nessus": 0.80,
        "tenable": 0.80,
        "rapid7": 0.80,
        "openvas": 0.80,
        "crowdstrike_scanner": 0.80,
        # IPAM — authoritative for IP/subnet, less so for hostnames
        "ipam": 0.75,
        "infoblox": 0.75,
        "netbox": 0.75,
        "solarwinds": 0.75,
        # NDR — passive observation, good for network layer
        "ndr": 0.60,
        "darktrace": 0.60,
        "extrahop": 0.60,
        "vectra": 0.60,
        # SIEM — aggregated data, lowest confidence
        "siem": 0.50,
        "splunk": 0.50,
        "sentinel": 0.50,
        "qradar": 0.50,
    }

    DEFAULT: ClassVar[float] = 0.50

    @classmethod
    def get(cls, source_system: str) -> float:
        """
        Return the confidence score for a source system.

        Args:
            source_system: Source name (e.g. 'crowdstrike', 'qualys').

        Returns:
            Confidence score between 0 and 1.
        """
        if not source_system:
            return cls.DEFAULT
        return cls.SCORES.get(source_system.lower(), cls.DEFAULT)
