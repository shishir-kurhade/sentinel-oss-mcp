from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from sentinel_oss.audit import NullAuditStore, SQLiteAuditStore
from sentinel_oss.cli import _passes_release_gates
from sentinel_oss.contracts import (
    DecisionStatus,
    EvaluationStage,
    ExchangeRequest,
    Outcome,
    ProviderVerdict,
    SafetyDecision,
    SourceKind,
    TrustLevel,
)
from sentinel_oss.engine import SentinelEngine
from sentinel_oss.evaluation import EvaluationPrediction, evaluate_predictions, load_benchmark
from sentinel_oss.providers import (
    ClassificationResult,
    ProviderError,
    ProviderMetrics,
    ScriptedClassifier,
    UnavailableClassifier,
)
from sentinel_oss.providers.gemini import GeminiClassifier
from sentinel_oss.runtime import RuntimeSettings, build_engine
from sentinel_oss.semantic import NullSemanticRouter


def _verdict(outcome: Outcome = Outcome.ALLOW) -> ProviderVerdict:
    return ProviderVerdict(
        outcome=outcome,
        reason_code="TEST_RESULT",
        message="Synthetic result.",
        confidence=0.99,
    )


def _exchange() -> ExchangeRequest:
    return ExchangeRequest(
        policy_id="banking",
        trusted_user_intent="Answer safely.",
        content="A routine account question.",
        source_kind=SourceKind.USER,
        trust_level=TrustLevel.UNTRUSTED,
    )


class _FakeGenerateContentConfig:
    def __init__(self, **kwargs: object) -> None:
        self.values = kwargs


class _Models:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls = 0

    async def generate_content(self, **kwargs: object) -> object:
        del kwargs
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _install_fake_google(monkeypatch: pytest.MonkeyPatch) -> None:
    google = ModuleType("google")
    google.__path__ = []  # type: ignore[attr-defined]
    genai = ModuleType("google.genai")
    genai.__path__ = []  # type: ignore[attr-defined]
    types_module = ModuleType("google.genai.types")
    types_module.GenerateContentConfig = _FakeGenerateContentConfig  # type: ignore[attr-defined]
    genai.types = types_module  # type: ignore[attr-defined]
    google.genai = genai  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_module)


def _response(
    *,
    input_tokens: int,
    output_tokens: int,
    thought_tokens: int = 0,
    parsed: object | None = None,
) -> object:
    return SimpleNamespace(
        parsed=_verdict() if parsed is None else parsed,
        usage_metadata=SimpleNamespace(
            prompt_token_count=input_tokens,
            candidates_token_count=output_tokens,
            thoughts_token_count=thought_tokens,
        ),
    )


def test_provider_metrics_validate_merge_and_legacy_comparison() -> None:
    first = ProviderMetrics(
        attempts=1,
        input_tokens=10,
        output_tokens=2,
        input_token_attempts=1,
        output_token_attempts=1,
        estimated_cost_usd=0.00002,
        costed_attempts=1,
    )
    second = ProviderMetrics(attempts=1)

    merged = first.merged(second)

    assert merged.attempts == 2
    assert merged.input_tokens == 10
    assert merged.token_usage_complete is False
    assert merged.cost_estimate_complete is False
    assert ClassificationResult(_verdict(), first) == _verdict()
    with pytest.raises(ValueError, match="cannot exceed attempts"):
        ProviderMetrics(attempts=1, input_token_attempts=2)
    for non_finite in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="finite non-negative"):
            ProviderMetrics(estimated_cost_usd=non_finite)


@pytest.mark.asyncio
async def test_gemini_counts_retries_tokens_and_configured_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_google(monkeypatch)
    models = _Models(
        [
            _response(
                input_tokens=100,
                output_tokens=10,
                thought_tokens=30,
                parsed={"malformed": True},
            ),
            _response(input_tokens=50, output_tokens=5, thought_tokens=7),
        ]
    )
    classifier = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=models)),
        max_retries=1,
        input_price_per_million=2.0,
        output_price_per_million=10.0,
    )

    result = await classifier.classify(
        _exchange(),
        policy_instructions="Test policy.",
        stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
    )

    assert result.verdict == _verdict()
    assert result.provider_id == "google-gemini"
    assert result.metrics == ProviderMetrics(
        attempts=2,
        input_tokens=150,
        output_tokens=52,
        input_token_attempts=2,
        output_token_attempts=2,
        estimated_cost_usd=0.00082,
        costed_attempts=2,
    )
    assert models.calls == 2


@pytest.mark.asyncio
async def test_gemini_usage_falls_back_to_total_without_overclaiming_missing_thoughts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_google(monkeypatch)
    total_fallback = SimpleNamespace(
        parsed=_verdict(),
        usage_metadata=SimpleNamespace(
            prompt_token_count=20,
            thoughts_token_count=6,
            total_token_count=29,
        ),
    )
    classifier = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=_Models([total_fallback]))),
        max_retries=0,
        input_price_per_million=1.0,
        output_price_per_million=10.0,
    )

    result = await classifier.classify(
        _exchange(),
        policy_instructions="Test policy.",
        stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
    )

    assert result.metrics.output_tokens == 9
    assert result.metrics.output_token_attempts == 1
    assert result.metrics.estimated_cost_usd == pytest.approx(0.00011)
    assert result.metrics.cost_estimate_complete is True

    missing_thoughts = SimpleNamespace(
        parsed=_verdict(),
        usage_metadata=SimpleNamespace(
            prompt_token_count=20,
            candidates_token_count=4,
        ),
    )
    incomplete = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=_Models([missing_thoughts]))),
        max_retries=0,
        input_price_per_million=1.0,
        output_price_per_million=10.0,
    )

    incomplete_result = await incomplete.classify(
        _exchange(),
        policy_instructions="Test policy.",
        stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
    )

    assert incomplete_result.metrics.output_tokens == 0
    assert incomplete_result.metrics.output_token_attempts == 0
    assert incomplete_result.metrics.costed_attempts == 0
    assert incomplete_result.metrics.token_usage_complete is False
    assert incomplete_result.metrics.cost_estimate_complete is False


@pytest.mark.asyncio
async def test_gemini_rejects_negative_thought_usage_as_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_google(monkeypatch)
    response = SimpleNamespace(
        parsed=_verdict(),
        usage_metadata=SimpleNamespace(
            prompt_token_count=20,
            candidates_token_count=4,
            thoughts_token_count=-1,
        ),
    )
    classifier = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=_Models([response]))),
        max_retries=0,
        input_price_per_million=1.0,
        output_price_per_million=10.0,
    )

    result = await classifier.classify(
        _exchange(),
        policy_instructions="Test policy.",
        stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
    )

    assert result.metrics.output_tokens == 0
    assert result.metrics.output_token_attempts == 0
    assert result.metrics.costed_attempts == 0
    assert result.metrics.token_usage_complete is False
    assert result.metrics.cost_estimate_complete is False


@pytest.mark.asyncio
async def test_gemini_reports_partial_coverage_and_error_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_google(monkeypatch)
    success_models = _Models(
        [RuntimeError("transient"), _response(input_tokens=20, output_tokens=4)]
    )
    classifier = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=success_models)),
        max_retries=1,
        input_price_per_million=1.0,
        output_price_per_million=1.0,
    )

    result = await classifier.classify(
        _exchange(),
        policy_instructions="Test policy.",
        stage=EvaluationStage.EXPERT_CLASSIFIER,
    )

    assert result.metrics.attempts == 2
    assert result.metrics.input_token_attempts == 1
    assert result.metrics.costed_attempts == 1
    assert result.metrics.cost_estimate_complete is False

    failed_models = _Models([RuntimeError("one"), RuntimeError("two")])
    failed = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=failed_models)),
        max_retries=1,
    )
    with pytest.raises(ProviderError) as error:
        await failed.classify(
            _exchange(),
            policy_instructions="Test policy.",
            stage=EvaluationStage.EXPERT_CLASSIFIER,
        )
    assert error.value.metrics == ProviderMetrics(attempts=2)


@pytest.mark.asyncio
async def test_engine_aggregates_metrics_across_the_classifier_cascade() -> None:
    lightweight = ClassificationResult(
        _verdict(Outcome.REVIEW),
        ProviderMetrics(
            attempts=2,
            input_tokens=100,
            output_tokens=10,
            input_token_attempts=2,
            output_token_attempts=2,
            estimated_cost_usd=0.001,
            costed_attempts=2,
        ),
        provider_id="google-gemini",
    )
    expert = ClassificationResult(
        _verdict(),
        ProviderMetrics(
            attempts=1,
            input_tokens=80,
            output_tokens=8,
            input_token_attempts=1,
            output_token_attempts=1,
            estimated_cost_usd=0.002,
            costed_attempts=1,
        ),
        provider_id="google-gemini",
    )
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([lightweight]),
        expert_provider=ScriptedClassifier([expert]),
        audit_store=NullAuditStore(),
    )

    decision = await engine.scan_exchange(_exchange())

    assert decision.outcome is Outcome.ALLOW
    assert decision.provider_id == "google-gemini"
    assert decision.signals["model_calls"] == 3
    assert decision.signals["provider_attempts"] == 3
    assert decision.signals["lightweight_attempts"] == 2
    assert decision.signals["expert_attempts"] == 1
    assert decision.signals["input_tokens"] == 180
    assert decision.signals["output_tokens"] == 18
    assert decision.signals["estimated_cost_usd"] == pytest.approx(0.003)
    assert decision.signals["cost_estimate_complete"] is True


@pytest.mark.asyncio
async def test_engine_preserves_error_metrics_and_legacy_provider_compatibility() -> None:
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier(
            [ProviderError("first", metrics=ProviderMetrics(attempts=2))]
        ),
        expert_provider=ScriptedClassifier([RuntimeError("second")]),
        audit_store=NullAuditStore(),
    )

    failed = await engine.scan_exchange(_exchange())

    assert failed.status is DecisionStatus.ERROR
    assert failed.outcome is Outcome.REVIEW
    assert failed.signals["model_calls"] == 3
    assert failed.signals["cost_estimate_complete"] is False

    legacy = SentinelEngine(
        lightweight_provider=ScriptedClassifier([_verdict()]),
        expert_provider=ScriptedClassifier([]),
        audit_store=NullAuditStore(),
    )
    allowed = await legacy.scan_exchange(_exchange())
    assert allowed.outcome is Outcome.ALLOW
    assert allowed.signals["model_calls"] == 1
    assert allowed.signals["cost_estimate_complete"] is False


def test_evaluation_aggregates_token_and_cost_coverage() -> None:
    cases = list(load_benchmark().content[:2])
    predictions = [
        EvaluationPrediction(
            cases[0].id,
            cases[0].expected_outcome,
            model_calls=2,
            provider_attempts=2,
            input_tokens=100,
            output_tokens=10,
            input_token_attempts=2,
            output_token_attempts=2,
            estimated_cost_usd=0.001,
            costed_attempts=2,
        ),
        EvaluationPrediction(
            cases[1].id,
            cases[1].expected_outcome,
            model_calls=1,
            provider_attempts=1,
        ),
    ]

    report = evaluate_predictions(cases, predictions)

    assert report.model_calls["total"] == 3
    assert report.token_usage == {
        "attempts": 3,
        "input_tokens": 100,
        "output_tokens": 10,
        "input_token_attempts": 2,
        "output_token_attempts": 2,
        "input_coverage": pytest.approx(2 / 3),
        "output_coverage": pytest.approx(2 / 3),
        "complete": False,
    }
    assert report.estimated_cost_usd["total"] == pytest.approx(0.001)
    assert report.estimated_cost_usd["coverage"] == pytest.approx(2 / 3)
    assert report.estimated_cost_usd["complete"] is False


def test_full_release_gate_requires_complete_cost_when_models_were_called() -> None:
    base = dict(
        provenance_complete=True,
        error_rate=0.0,
        harmful_recall=0.95,
        benign_false_positive_rate=0.05,
        hard_negative_false_positive_rate=0.10,
        per_policy={"banking": {"harmful_recall": 0.90}},
        model_calls={"total": 1},
        pricing={"complete": True},
    )
    incomplete = SimpleNamespace(**base, estimated_cost_usd={"complete": False, "total": None})
    complete = SimpleNamespace(**base, estimated_cost_usd={"complete": True, "total": 0.001})

    assert _passes_release_gates(incomplete, full=True) is False
    assert _passes_release_gates(complete, full=True) is True
    incomplete_pricing = SimpleNamespace(
        **{**base, "pricing": {"complete": False}},
        estimated_cost_usd={"complete": True, "total": 0.001},
    )
    assert _passes_release_gates(incomplete_pricing, full=True) is False


def test_runtime_parses_prices_and_offline_mode_without_provider_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SENTINEL_OFFLINE", "1")
    monkeypatch.setenv("SENTINEL_SEMANTIC_ENABLED", "1")
    monkeypatch.setenv("SENTINEL_GOOGLE_API_KEY", "unused-test-key")
    monkeypatch.setenv("SENTINEL_LIGHTWEIGHT_INPUT_PRICE_PER_MILLION", "0.1")
    monkeypatch.setenv("SENTINEL_LIGHTWEIGHT_OUTPUT_PRICE_PER_MILLION", "0.4")
    monkeypatch.setenv("SENTINEL_EXPERT_INPUT_PRICE_PER_MILLION", "1.2")
    monkeypatch.setenv("SENTINEL_EXPERT_OUTPUT_PRICE_PER_MILLION", "4.8")

    settings = RuntimeSettings.from_env()
    monkeypatch.setitem(sys.modules, "sentinel_oss.providers.gemini", None)
    audit = NullAuditStore()
    engine = build_engine(settings, audit_store=audit)

    assert settings.offline is True
    assert settings.lightweight_input_price_per_million == 0.1
    assert settings.expert_output_price_per_million == 4.8
    assert isinstance(engine.lightweight_provider, UnavailableClassifier)
    assert isinstance(engine.expert_provider, UnavailableClassifier)
    assert isinstance(engine.semantic_router, NullSemanticRouter)
    assert engine.audit_store is audit

    with pytest.raises(ValueError, match="configured together"):
        RuntimeSettings(data_dir=tmp_path, expert_input_price_per_million=1.0)


@pytest.mark.asyncio
async def test_audit_persists_provider_and_model_identity(tmp_path: Path) -> None:
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    decision = SafetyDecision(
        decision_id="provider-metadata-test",
        status=DecisionStatus.COMPLETE,
        outcome=Outcome.ALLOW,
        reason_code="TEST",
        message="Safe metadata only.",
        policy_id="banking",
        policy_version="1.0.0",
        stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
        provider_id="google-gemini",
        model_id="gemini-test",
        latency_ms=1.0,
    )

    await store.record(decision)

    [row] = await store.recent()
    assert row["provider_id"] == "google-gemini"
    assert row["provider_model"] == "gemini-test"
