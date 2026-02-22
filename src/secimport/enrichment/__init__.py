"""Asset enrichment, correlation, and gap analysis."""

from .correlator import AssetCorrelator
from .models import (
    CorrelationKey,
    EnrichedAsset,
    FieldProvenance,
    GapReport,
    MatchResult,
)
from .scoring import MatchWeights, SourceConfidence

__all__ = [
    "AssetCorrelator",
    "CorrelationKey",
    "EnrichedAsset",
    "FieldProvenance",
    "GapReport",
    "MatchResult",
    "MatchWeights",
    "SourceConfidence",
]
