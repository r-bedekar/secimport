"""
secimport -- Parse and normalize security data imports.

Vulnerability scans, assets, CMDB, IPAM, and more.
"""

__version__ = "0.1.0"

# Models
# Connector infrastructure
from .connectors.base import AuthConfig, ConnectionConfig, ConnectorRegistry, ConnectorStatus

# EDR/AV connectors
from .connectors.edr import (
    CarbonBlackConnector,
    CrowdStrikeFalconConnector,
    DefenderForEndpointConnector,
    SentinelOneConnector,
    SymantecEndpointConnector,
    TrellixConnector,
    TrendMicroConnector,
)

# NDR connectors
from .connectors.ndr import DarktraceConnector, ExtraHopConnector, VectraConnector

# Scanner connectors
from .connectors.scanners import (
    CrowdStrikeConnector,
    NessusConnector,
    OpenVASConnector,
    QualysConnector,
    Rapid7Connector,
    TenableConnector,
)

# SIEM connectors
from .connectors.siem import QRadarConnector, SentinelConnector, SplunkConnector

# XDR connectors
from .connectors.xdr import CortexXDRConnector, VisionOneConnector

# Auto-detection and parsing
from .detectors import detect_all, detect_data_type, detect_parser, detect_source, parse_file

# Enrichment
from .enrichment.correlator import AssetCorrelator
from .enrichment.models import EnrichedAsset, GapReport
from .enrichment.scoring import MatchWeights, SourceConfidence
from .models.base import (
    ParsedAsset,
    ParsedEndpoint,
    ParsedGroup,
    ParsedNetworkObservation,
    ParsedOwnerMapping,
    ParsedUser,
    ParsedVulnerability,
    ParseResult,
    SourceMetadata,
)

# Normalizers
from .normalizers.hostname import normalize_hostname, normalize_ip, normalize_mac
from .normalizers.severity import normalize_severity

# Parser infrastructure
from .parsers.base import BaseParser, ParserRegistry

__all__ = [
    # version
    "__version__",
    # models
    "ParsedAsset",
    "ParsedEndpoint",
    "ParsedGroup",
    "ParsedNetworkObservation",
    "ParsedOwnerMapping",
    "ParsedUser",
    "ParsedVulnerability",
    "ParseResult",
    "SourceMetadata",
    # normalizers
    "normalize_hostname",
    "normalize_ip",
    "normalize_mac",
    "normalize_severity",
    # enrichment
    "AssetCorrelator",
    "EnrichedAsset",
    "GapReport",
    "MatchWeights",
    "SourceConfidence",
    # connector infrastructure
    "AuthConfig",
    "ConnectionConfig",
    "ConnectorRegistry",
    "ConnectorStatus",
    # scanner connectors
    "CrowdStrikeConnector",
    "NessusConnector",
    "OpenVASConnector",
    "QualysConnector",
    "Rapid7Connector",
    "TenableConnector",
    # EDR/AV connectors
    "CarbonBlackConnector",
    "CrowdStrikeFalconConnector",
    "DefenderForEndpointConnector",
    "SentinelOneConnector",
    "SymantecEndpointConnector",
    "TrellixConnector",
    "TrendMicroConnector",
    # XDR connectors
    "CortexXDRConnector",
    "VisionOneConnector",
    # NDR connectors
    "DarktraceConnector",
    "ExtraHopConnector",
    "VectraConnector",
    # SIEM connectors
    "QRadarConnector",
    "SentinelConnector",
    "SplunkConnector",
    # parser infrastructure
    "BaseParser",
    "ParserRegistry",
    # detection & parsing
    "detect_all",
    "detect_data_type",
    "detect_parser",
    "detect_source",
    "parse_file",
]
