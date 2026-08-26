"""Provider-neutral classifier and embedding interfaces."""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sentinel_oss.contracts import EvaluationStage, ExchangeRequest, ProviderVerdict


@dataclass(frozen=True, slots=True)
class ProviderMetrics:
    """Non-sensitive accounting for one bounded classifier operation.

    Token observation counts are kept separately from token totals so callers do
    not mistake a partial measurement for a complete estimate.  An attempt means
    an actual provider request, including a retry.
    """

    attempts: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    input_token_attempts: int = 0
    output_token_attempts: int = 0
    estimated_cost_usd: float = 0.0
    costed_attempts: int = 0

    def __post_init__(self) -> None:
        integer_fields = (
            ("attempts", self.attempts),
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
            ("input_token_attempts", self.input_token_attempts),
            ("output_token_attempts", self.output_token_attempts),
            ("costed_attempts", self.costed_attempts),
        )
        for name, value in integer_fields:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.input_token_attempts > self.attempts:
            raise ValueError("input_token_attempts cannot exceed attempts")
        if self.output_token_attempts > self.attempts:
            raise ValueError("output_token_attempts cannot exceed attempts")
        if self.costed_attempts > min(self.input_token_attempts, self.output_token_attempts):
            raise ValueError("costed_attempts requires observed input and output tokens")
        if (
            isinstance(self.estimated_cost_usd, bool)
            or not isinstance(self.estimated_cost_usd, (int, float))
            or not math.isfinite(self.estimated_cost_usd)
            or self.estimated_cost_usd < 0
        ):
            raise ValueError("estimated_cost_usd must be a finite non-negative number")

    @property
    def token_usage_complete(self) -> bool:
        return (
            self.input_token_attempts == self.attempts
            and self.output_token_attempts == self.attempts
        )

    @property
    def cost_estimate_complete(self) -> bool:
        return self.costed_attempts == self.attempts

    def merged(self, other: ProviderMetrics) -> ProviderMetrics:
        """Return an aggregate without retaining request or response content."""

        return ProviderMetrics(
            attempts=self.attempts + other.attempts,
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            input_token_attempts=self.input_token_attempts + other.input_token_attempts,
            output_token_attempts=self.output_token_attempts + other.output_token_attempts,
            estimated_cost_usd=self.estimated_cost_usd + other.estimated_cost_usd,
            costed_attempts=self.costed_attempts + other.costed_attempts,
        )


@dataclass(frozen=True, slots=True, eq=False)
class ClassificationResult:
    """A strict verdict plus provider-supplied accounting metadata."""

    verdict: ProviderVerdict
    metrics: ProviderMetrics = field(default_factory=ProviderMetrics)
    provider_id: str | None = None

    def __eq__(self, other: object) -> bool:
        # This makes the new envelope gentle for direct adapter callers that used
        # to compare Gemini's return value with a ProviderVerdict.
        if isinstance(other, ProviderVerdict):
            return self.verdict == other
        if isinstance(other, ClassificationResult):
            return (
                self.verdict == other.verdict
                and self.metrics == other.metrics
                and self.provider_id == other.provider_id
            )
        return NotImplemented


class ProviderError(RuntimeError):
    """A bounded provider operation failed or returned an invalid response."""

    def __init__(
        self,
        message: str,
        *,
        metrics: ProviderMetrics | None = None,
    ) -> None:
        super().__init__(message)
        # A legacy adapter raising ProviderError normally represents one attempted
        # call. Providers that fail before any request (for example missing creds)
        # explicitly pass attempts=0.
        self.metrics = metrics or ProviderMetrics(attempts=1)


@dataclass(frozen=True)
class UnavailableClassifier:
    """Fail-safe provider used when runtime credentials or extras are unavailable."""

    message: str
    model_id: str = "unavailable"
    provider_id: str = "unavailable"

    async def classify(
        self,
        request: ExchangeRequest,
        *,
        policy_instructions: str,
        stage: EvaluationStage,
    ) -> ProviderVerdict | ClassificationResult:
        del request, policy_instructions, stage
        raise ProviderError(self.message, metrics=ProviderMetrics())


@runtime_checkable
class ClassifierProvider(Protocol):
    @property
    def model_id(self) -> str: ...

    async def classify(
        self,
        request: ExchangeRequest,
        *,
        policy_instructions: str,
        stage: EvaluationStage,
    ) -> ProviderVerdict | ClassificationResult: ...


@runtime_checkable
class EmbeddingProvider(Protocol):
    @property
    def model_id(self) -> str: ...

    async def embed(self, text: str) -> list[float]: ...


@dataclass
class ScriptedClassifier:
    """Deterministic test provider with call recording."""

    responses: Iterable[ProviderVerdict | ClassificationResult | Exception]
    model_id: str = "scripted-classifier"
    provider_id: str = "scripted"
    calls: list[tuple[ExchangeRequest, EvaluationStage]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._responses = deque(self.responses)

    async def classify(
        self,
        request: ExchangeRequest,
        *,
        policy_instructions: str,
        stage: EvaluationStage,
    ) -> ProviderVerdict | ClassificationResult:
        del policy_instructions
        self.calls.append((request, stage))
        if not self._responses:
            raise ProviderError(
                "scripted provider has no remaining response",
                metrics=ProviderMetrics(),
            )
        response = self._responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response


@dataclass
class ScriptedEmbedder:
    vectors: dict[str, list[float]]
    default: list[float]
    model_id: str = "scripted-embedder"
    calls: list[str] = field(default_factory=list)

    async def embed(self, text: str) -> list[float]:
        self.calls.append(text)
        return self.vectors.get(text, self.default)


__all__ = [
    "ClassificationResult",
    "ClassifierProvider",
    "EmbeddingProvider",
    "ProviderError",
    "ProviderMetrics",
    "ScriptedClassifier",
    "ScriptedEmbedder",
    "UnavailableClassifier",
]
