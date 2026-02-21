"""Data normalizers for cross-scanner consistency."""

from .severity import SEVERITY_MAPPINGS, normalize_severity

__all__ = [
    "SEVERITY_MAPPINGS",
    "normalize_severity",
]
