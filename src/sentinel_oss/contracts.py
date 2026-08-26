"""Public request and decision contracts for Sentinel OSS MCP."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1"
MAX_CONTENT_CHARS = 65_536
MAX_INTENT_CHARS = 32_768
MAX_ARGUMENT_CHARS = 65_536


class Outcome(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class DecisionStatus(StrEnum):
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"


class SourceKind(StrEnum):
    USER = "USER"
    TOOL = "TOOL"
    RETRIEVAL = "RETRIEVAL"
    WEB = "WEB"
    FILE = "FILE"
    MODEL = "MODEL"
    OTHER = "OTHER"


class TrustLevel(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class DataLabel(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PII = "PII"
    PHI = "PHI"
    PAYMENT = "PAYMENT"
    CREDENTIAL = "CREDENTIAL"


class EvaluationStage(StrEnum):
    INPUT_VALIDATION = "INPUT_VALIDATION"
    EXACT_SIGNATURE = "EXACT_SIGNATURE"
    SEMANTIC_ROUTING = "SEMANTIC_ROUTING"
    LIGHTWEIGHT_CLASSIFIER = "LIGHTWEIGHT_CLASSIFIER"
    EXPERT_CLASSIFIER = "EXPERT_CLASSIFIER"
    ACTION_POLICY = "ACTION_POLICY"
    ERROR = "ERROR"


class ContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class ExchangeRequest(ContractModel):
    policy_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    trusted_user_intent: str = Field(min_length=1)
    content: str = Field(min_length=1)
    source_kind: SourceKind
    trust_level: TrustLevel
    draft_output: str | None = None


class ActionRequest(ContractModel):
    policy_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    tool_name: str = Field(min_length=1, max_length=256)
    arguments: dict[str, Any]
    destination: str | None = Field(default=None, max_length=2_048)
    # These declarations are intentionally required. Defaulting missing provenance or
    # classification to a trusted/public value would turn incomplete input into permission.
    data_labels: set[DataLabel] = Field(min_length=1)
    source_kinds: set[SourceKind] = Field(min_length=1)
    reversible: bool
    user_confirmed: bool
    prior_decision_id: str | None = Field(default=None, max_length=64)

    @field_validator("arguments")
    @classmethod
    def arguments_must_be_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        import json

        try:
            json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("arguments must be JSON serializable") from exc
        return value


class SafetyDecision(ContractModel):
    schema_version: str = SCHEMA_VERSION
    decision_id: str
    status: DecisionStatus
    outcome: Outcome
    reason_code: str
    message: str
    policy_id: str
    policy_version: str
    matched_rule_ids: list[str] = Field(default_factory=list)
    stage: EvaluationStage
    requires_confirmation: bool = False
    obligations: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    signals: dict[str, str | float | int | bool] = Field(default_factory=dict)
    provider_id: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    model_id: str | None = None
    latency_ms: float = Field(ge=0.0)


class ProviderVerdict(ContractModel):
    """Strict provider response; converted into a public SafetyDecision by the engine."""

    outcome: Outcome
    reason_code: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Z][A-Z0-9_]*$",
    )
    message: str = Field(min_length=1, max_length=2_048)
    matched_rule_ids: list[str] = Field(default_factory=list)
    obligations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
