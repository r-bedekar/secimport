"""
secimport -- Parse and normalize security data imports.

Vulnerability scans, assets, CMDB, IPAM, and more.
"""

__version__ = "0.1.0"

# Models
# Connector infrastructure
from .connectors.base import AuthConfig, ConnectionConfig, ConnectorRegistry, ConnectorStatus

# Scanner connectors
from .connectors.scanners import (
    CrowdStrikeConnector,
    NessusConnector,
    OpenVASConnector,
    QualysConnector,
    Rapid7Connector,
    TenableConnector,
)

# Auto-detection and parsing
from .detectors import detect_all, detect_data_type, detect_parser, detect_source, parse_file
from .models.base import ParsedAsset, ParsedOwnerMapping, ParsedVulnerability, ParseResult

# Normalizers
from .normalizers.severity import normalize_severity

# Parser infrastructure
from .parsers.base import BaseParser, ParserRegistry

__all__ = [
    # version
    "__version__",
    # models
    "ParsedAsset",
    "ParsedOwnerMapping",
    "ParsedVulnerability",
    "ParseResult",
    # normalizers
    "normalize_severity",
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
