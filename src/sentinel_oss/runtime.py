"""Lazy runtime construction and environment configuration."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from sentinel_oss.audit import AuditSink, SQLiteAuditStore, default_data_dir
from sentinel_oss.engine import EngineConfig, SentinelEngine
from sentinel_oss.providers import ClassifierProvider, UnavailableClassifier
from sentinel_oss.semantic import LanceSemanticRouter, NullSemanticRouter, SemanticRouter


@dataclass(frozen=True)
class RuntimeSettings:
    data_dir: Path
    lightweight_model: str = "gemini-3.5-flash-lite"
    expert_model: str = "gemini-3.7-flash"
    embedding_model: str = "gemini-embedding-001"
    provider_timeout_seconds: float = 15.0
    provider_max_retries: int = 1
    lightweight_allow_threshold: float = 0.90
    expert_allow_threshold: float = 0.80
    semantic_escalation_threshold: float = 0.80
    semantic_enabled: bool = False
    offline: bool = False
    audit_max_records: int = 10_000
    lightweight_input_price_per_million: float | None = None
    lightweight_output_price_per_million: float | None = None
    expert_input_price_per_million: float | None = None
    expert_output_price_per_million: float | None = None
    google_api_key: str | None = None
    use_vertex: bool = False
    google_cloud_project: str | None = None
    google_cloud_location: str | None = None

    def __post_init__(self) -> None:
        if self.provider_timeout_seconds <= 0:
            raise ValueError("provider_timeout_seconds must be greater than zero")
        if self.provider_max_retries < 0:
            raise ValueError("provider_max_retries must not be negative")
        if self.audit_max_records < 0:
            raise ValueError("audit_max_records must not be negative")
        for name, value in (
            ("lightweight_allow_threshold", self.lightweight_allow_threshold),
            ("expert_allow_threshold", self.expert_allow_threshold),
            ("semantic_escalation_threshold", self.semantic_escalation_threshold),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        _validate_price_pair(
            "lightweight",
            self.lightweight_input_price_per_million,
            self.lightweight_output_price_per_million,
        )
        _validate_price_pair(
            "expert",
            self.expert_input_price_per_million,
            self.expert_output_price_per_million,
        )

    @classmethod
    def from_env(cls) -> RuntimeSettings:
        return cls(
            data_dir=default_data_dir(),
            lightweight_model=os.getenv("SENTINEL_LIGHTWEIGHT_MODEL", "gemini-3.5-flash-lite"),
            expert_model=os.getenv("SENTINEL_EXPERT_MODEL", "gemini-3.7-flash"),
            embedding_model=os.getenv("SENTINEL_EMBEDDING_MODEL", "gemini-embedding-001"),
            provider_timeout_seconds=_env_float("SENTINEL_PROVIDER_TIMEOUT", 15.0),
            provider_max_retries=_env_int("SENTINEL_PROVIDER_RETRIES", 1),
            lightweight_allow_threshold=_env_float("SENTINEL_LIGHTWEIGHT_ALLOW_THRESHOLD", 0.90),
            expert_allow_threshold=_env_float("SENTINEL_EXPERT_ALLOW_THRESHOLD", 0.80),
            semantic_escalation_threshold=_env_float("SENTINEL_SEMANTIC_THRESHOLD", 0.80),
            semantic_enabled=_env_bool("SENTINEL_SEMANTIC_ENABLED", False),
            offline=_env_bool("SENTINEL_OFFLINE", False),
            audit_max_records=_env_int("SENTINEL_AUDIT_MAX_RECORDS", 10_000),
            lightweight_input_price_per_million=_env_optional_float(
                "SENTINEL_LIGHTWEIGHT_INPUT_PRICE_PER_MILLION"
            ),
            lightweight_output_price_per_million=_env_optional_float(
                "SENTINEL_LIGHTWEIGHT_OUTPUT_PRICE_PER_MILLION"
            ),
            expert_input_price_per_million=_env_optional_float(
                "SENTINEL_EXPERT_INPUT_PRICE_PER_MILLION"
            ),
            expert_output_price_per_million=_env_optional_float(
                "SENTINEL_EXPERT_OUTPUT_PRICE_PER_MILLION"
            ),
            google_api_key=os.getenv("SENTINEL_GOOGLE_API_KEY") or os.getenv("GOOGLE_API_KEY"),
            use_vertex=_env_bool(
                "GOOGLE_GENAI_USE_VERTEXAI",
                _env_bool("SENTINEL_USE_VERTEX", False),
            ),
            google_cloud_project=os.getenv("GOOGLE_CLOUD_PROJECT"),
            google_cloud_location=os.getenv("GOOGLE_CLOUD_LOCATION"),
        )


def build_engine(
    settings: RuntimeSettings | None = None,
    *,
    audit_store: AuditSink | None = None,
) -> SentinelEngine:
    settings = settings or RuntimeSettings.from_env()
    lightweight, expert = _build_classifiers(settings)
    semantic = _build_semantic_router(settings)
    audit = (
        audit_store
        if audit_store is not None
        else SQLiteAuditStore(
            settings.data_dir / "audit.sqlite3",
            max_records=settings.audit_max_records,
        )
    )
    return SentinelEngine(
        lightweight_provider=lightweight,
        expert_provider=expert,
        semantic_router=semantic,
        audit_store=audit,
        config=EngineConfig(
            lightweight_allow_threshold=settings.lightweight_allow_threshold,
            expert_allow_threshold=settings.expert_allow_threshold,
            semantic_escalation_threshold=settings.semantic_escalation_threshold,
        ),
    )


@lru_cache(maxsize=1)
def get_default_engine() -> SentinelEngine:
    """Build the process-wide engine on first use, never at import time."""

    return build_engine()


def reset_default_engine() -> None:
    """Testing and embedding hook for reloading environment configuration."""

    get_default_engine.cache_clear()


def _build_classifiers(
    settings: RuntimeSettings,
) -> tuple[ClassifierProvider, ClassifierProvider]:
    if settings.offline:
        return _unavailable_classifiers(settings, "Sentinel offline mode is enabled")
    try:
        from sentinel_oss.providers.gemini import GeminiClassifier

        return (
            GeminiClassifier(
                settings.lightweight_model,
                api_key=settings.google_api_key,
                use_vertex=settings.use_vertex,
                project=settings.google_cloud_project,
                location=settings.google_cloud_location,
                timeout_seconds=settings.provider_timeout_seconds,
                max_retries=settings.provider_max_retries,
                input_price_per_million=settings.lightweight_input_price_per_million,
                output_price_per_million=settings.lightweight_output_price_per_million,
            ),
            GeminiClassifier(
                settings.expert_model,
                api_key=settings.google_api_key,
                use_vertex=settings.use_vertex,
                project=settings.google_cloud_project,
                location=settings.google_cloud_location,
                timeout_seconds=settings.provider_timeout_seconds,
                max_retries=settings.provider_max_retries,
                input_price_per_million=settings.expert_input_price_per_million,
                output_price_per_million=settings.expert_output_price_per_million,
            ),
        )
    except Exception as exc:
        return _unavailable_classifiers(settings, f"Gemini provider is unavailable: {exc}")


def _build_semantic_router(settings: RuntimeSettings) -> SemanticRouter:
    if settings.offline or not settings.semantic_enabled:
        return NullSemanticRouter()
    try:
        from sentinel_oss.providers.gemini import GeminiEmbedder

        embedder = GeminiEmbedder(
            settings.embedding_model,
            api_key=settings.google_api_key,
            use_vertex=settings.use_vertex,
            project=settings.google_cloud_project,
            location=settings.google_cloud_location,
            timeout_seconds=settings.provider_timeout_seconds,
        )
        return LanceSemanticRouter(
            db_path=settings.data_dir / "semantic.lancedb", embedder=embedder
        )
    except Exception:
        # The classifier pipeline remains fail-safe and records semantic_unavailable.
        return NullSemanticRouter()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return default if raw is None else int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return default if raw is None else float(raw)


def _env_optional_float(name: str) -> float | None:
    raw = os.getenv(name)
    return None if raw is None or not raw.strip() else float(raw)


def _validate_price_pair(
    stage: str,
    input_price: float | None,
    output_price: float | None,
) -> None:
    if (input_price is None) != (output_price is None):
        raise ValueError(f"{stage} input and output prices must be configured together")
    for kind, value in (("input", input_price), ("output", output_price)):
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError(f"{stage} {kind} price must be a finite non-negative number")


def _unavailable_classifiers(
    settings: RuntimeSettings, message: str
) -> tuple[ClassifierProvider, ClassifierProvider]:
    return (
        UnavailableClassifier(message, model_id=settings.lightweight_model),
        UnavailableClassifier(message, model_id=settings.expert_model),
    )


__all__ = [
    "RuntimeSettings",
    "build_engine",
    "get_default_engine",
    "reset_default_engine",
]
