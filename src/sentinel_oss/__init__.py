"""Sentinel OSS MCP public Python API."""

from .api import authorize_action, check_safety, scan_exchange
from .contracts import (
    ActionRequest,
    DataLabel,
    DecisionStatus,
    ExchangeRequest,
    Outcome,
    SafetyDecision,
    SourceKind,
    TrustLevel,
)
from .engine import EngineConfig, SentinelEngine
from .providers import ClassificationResult, ClassifierProvider, ProviderError, ProviderMetrics

__all__ = [
    "ActionRequest",
    "ClassificationResult",
    "ClassifierProvider",
    "DataLabel",
    "DecisionStatus",
    "EngineConfig",
    "ExchangeRequest",
    "Outcome",
    "ProviderError",
    "ProviderMetrics",
    "SafetyDecision",
    "SentinelEngine",
    "SourceKind",
    "TrustLevel",
    "authorize_action",
    "check_safety",
    "scan_exchange",
]

__version__ = "0.1.0b1"
