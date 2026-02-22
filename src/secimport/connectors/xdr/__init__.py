"""XDR (Extended Detection and Response) platform connectors."""

from .cortex_xdr import CortexXDRConnector
from .vision_one import VisionOneConnector

__all__ = [
    "CortexXDRConnector",
    "VisionOneConnector",
]
