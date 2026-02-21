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
from .models.base import ParsedAsset, ParsedOwnerMapping, ParsedVulnerability, ParseResult

# Normalizers
from .normalizers.severity import normalize_severity

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
]
