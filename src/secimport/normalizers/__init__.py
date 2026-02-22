"""Data normalizers for cross-scanner consistency."""

from .hostname import normalize_hostname, normalize_ip, normalize_mac
from .severity import SEVERITY_MAPPINGS, normalize_severity

__all__ = [
    "SEVERITY_MAPPINGS",
    "normalize_hostname",
    "normalize_ip",
    "normalize_mac",
    "normalize_severity",
]
