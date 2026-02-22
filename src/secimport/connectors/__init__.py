"""Connectors for external security systems."""

from .base import AuthConfig, BaseConnector, ConnectionConfig, ConnectorRegistry, ConnectorStatus
from .cloud import AWSConnector, AzureConnector, GCPConnector  # noqa: F401
from .cmdb import ServiceNowConnector  # noqa: F401
from .directory import (  # noqa: F401
    ActiveDirectoryConnector,
    AzureADConnector,
)
from .edr import (  # noqa: F401
    CarbonBlackConnector,
    CrowdStrikeFalconConnector,
    DefenderForEndpointConnector,
    SentinelOneConnector,
    SymantecEndpointConnector,
    TrellixConnector,
    TrendMicroConnector,
)
from .ipam import InfobloxConnector, NetBoxConnector  # noqa: F401
from .ndr import DarktraceConnector, ExtraHopConnector, VectraConnector  # noqa: F401

# Import all connector categories so they auto-register
from .scanners import (  # noqa: F401
    CrowdStrikeConnector,
    NessusConnector,
    OpenVASConnector,
    QualysConnector,
    Rapid7Connector,
    TenableConnector,
)
from .siem import QRadarConnector, SentinelConnector, SplunkConnector  # noqa: F401
from .xdr import CortexXDRConnector, VisionOneConnector  # noqa: F401

__all__ = [
    # Infrastructure
    "AuthConfig",
    "BaseConnector",
    "ConnectionConfig",
    "ConnectorRegistry",
    "ConnectorStatus",
    # Scanners
    "CrowdStrikeConnector",
    "NessusConnector",
    "OpenVASConnector",
    "QualysConnector",
    "Rapid7Connector",
    "TenableConnector",
    # CMDB
    "ServiceNowConnector",
    # IPAM
    "InfobloxConnector",
    "NetBoxConnector",
    # Directory
    "ActiveDirectoryConnector",
    "AzureADConnector",
    # Cloud
    "AWSConnector",
    "AzureConnector",
    "GCPConnector",
    # EDR/AV
    "CarbonBlackConnector",
    "CrowdStrikeFalconConnector",
    "DefenderForEndpointConnector",
    "SentinelOneConnector",
    "SymantecEndpointConnector",
    "TrellixConnector",
    "TrendMicroConnector",
    # XDR
    "CortexXDRConnector",
    "VisionOneConnector",
    # NDR
    "DarktraceConnector",
    "ExtraHopConnector",
    "VectraConnector",
    # SIEM
    "QRadarConnector",
    "SentinelConnector",
    "SplunkConnector",
]
