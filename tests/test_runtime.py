from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel_oss.audit import NullAuditStore
from sentinel_oss.contracts import (
    ActionRequest,
    DataLabel,
    DecisionStatus,
    EvaluationStage,
    ExchangeRequest,
    Outcome,
    ProviderVerdict,
    SourceKind,
    TrustLevel,
)
from sentinel_oss.engine import (
    EngineConfig,
    SentinelEngine,
    _as_provider_error,
    _find_denied_argument,
)
from sentinel_oss.policies import PolicyOutcome, default_policy_registry
from sentinel_oss.providers import (
    ProviderError,
    ScriptedClassifier,
    ScriptedEmbedder,
    UnavailableClassifier,
)
from sentinel_oss.runtime import (
    RuntimeSettings,
    build_engine,
    get_default_engine,
    reset_default_engine,
)
from sentinel_oss.semantic import NullSemanticRouter, SemanticMatch

_RUNTIME_ENV = (
    "SENTINEL_DATA_DIR",
    "SENTINEL_LIGHTWEIGHT_MODEL",
    "SENTINEL_EXPERT_MODEL",
    "SENTINEL_EMBEDDING_MODEL",
    "SENTINEL_PROVIDER_TIMEOUT",
    "SENTINEL_PROVIDER_RETRIES",
    "SENTINEL_LIGHTWEIGHT_ALLOW_THRESHOLD",
    "SENTINEL_EXPERT_ALLOW_THRESHOLD",
    "SENTINEL_SEMANTIC_THRESHOLD",
    "SENTINEL_SEMANTIC_ENABLED",
    "SENTINEL_OFFLINE",
    "SENTINEL_AUDIT_MAX_RECORDS",
    "SENTINEL_LIGHTWEIGHT_INPUT_PRICE_PER_MILLION",
    "SENTINEL_LIGHTWEIGHT_OUTPUT_PRICE_PER_MILLION",
    "SENTINEL_EXPERT_INPUT_PRICE_PER_MILLION",
    "SENTINEL_EXPERT_OUTPUT_PRICE_PER_MILLION",
    "SENTINEL_GOOGLE_API_KEY",
    "GOOGLE_API_KEY",
    "SENTINEL_USE_VERTEX",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
)


def _clear_runtime_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _RUNTIME_ENV:
        monkeypatch.delenv(name, raising=False)


def test_runtime_settings_have_credential_free_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_runtime_env(monkeypatch)
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))

    settings = RuntimeSettings.from_env()

    assert settings.data_dir == tmp_path
    assert settings.lightweight_model == "gemini-3.5-flash-lite"
    assert settings.expert_model == "gemini-3.7-flash"
    assert settings.embedding_model == "gemini-embedding-001"
    assert settings.provider_timeout_seconds == 15.0
    assert settings.provider_max_retries == 1
    assert settings.lightweight_allow_threshold == 0.90
    assert settings.expert_allow_threshold == 0.80
    assert settings.semantic_escalation_threshold == 0.80
    assert settings.semantic_enabled is False
    assert settings.offline is False
    assert settings.audit_max_records == 10_000
    assert settings.lightweight_input_price_per_million is None
    assert settings.lightweight_output_price_per_million is None
    assert settings.expert_input_price_per_million is None
    assert settings.expert_output_price_per_million is None
    assert settings.google_api_key is None
    assert settings.use_vertex is False


def test_runtime_settings_parse_all_supported_environment_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_runtime_env(monkeypatch)
    values = {
        "SENTINEL_DATA_DIR": str(tmp_path / "data"),
        "SENTINEL_LIGHTWEIGHT_MODEL": "tiny-test",
        "SENTINEL_EXPERT_MODEL": "expert-test",
        "SENTINEL_EMBEDDING_MODEL": "embed-test",
        "SENTINEL_PROVIDER_TIMEOUT": "2.5",
        "SENTINEL_PROVIDER_RETRIES": "3",
        "SENTINEL_LIGHTWEIGHT_ALLOW_THRESHOLD": "0.75",
        "SENTINEL_EXPERT_ALLOW_THRESHOLD": "0.72",
        "SENTINEL_SEMANTIC_THRESHOLD": "0.61",
        "SENTINEL_SEMANTIC_ENABLED": "YES",
        "SENTINEL_OFFLINE": "YES",
        "SENTINEL_AUDIT_MAX_RECORDS": "42",
        "SENTINEL_LIGHTWEIGHT_INPUT_PRICE_PER_MILLION": "0.10",
        "SENTINEL_LIGHTWEIGHT_OUTPUT_PRICE_PER_MILLION": "0.40",
        "SENTINEL_EXPERT_INPUT_PRICE_PER_MILLION": "1.20",
        "SENTINEL_EXPERT_OUTPUT_PRICE_PER_MILLION": "4.80",
        "GOOGLE_API_KEY": "test-only-key",
        "SENTINEL_USE_VERTEX": "true",
        "GOOGLE_GENAI_USE_VERTEXAI": "on",
        "GOOGLE_CLOUD_PROJECT": "test-project",
        "GOOGLE_CLOUD_LOCATION": "us-test1",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    settings = RuntimeSettings.from_env()

    assert settings.data_dir == tmp_path / "data"
    assert settings.lightweight_model == "tiny-test"
    assert settings.expert_model == "expert-test"
    assert settings.embedding_model == "embed-test"
    assert settings.provider_timeout_seconds == 2.5
    assert settings.provider_max_retries == 3
    assert settings.lightweight_allow_threshold == 0.75
    assert settings.expert_allow_threshold == 0.72
    assert settings.semantic_escalation_threshold == 0.61
    assert settings.semantic_enabled is True
    assert settings.offline is True
    assert settings.audit_max_records == 42
    assert settings.lightweight_input_price_per_million == 0.10
    assert settings.lightweight_output_price_per_million == 0.40
    assert settings.expert_input_price_per_million == 1.20
    assert settings.expert_output_price_per_million == 4.80
    assert settings.google_api_key == "test-only-key"
    assert settings.use_vertex is True
    assert settings.google_cloud_project == "test-project"
    assert settings.google_cloud_location == "us-test1"


@pytest.mark.parametrize(
    "name,value", [("SENTINEL_PROVIDER_RETRIES", "many"), ("SENTINEL_PROVIDER_TIMEOUT", "soon")]
)
def test_invalid_numeric_environment_is_reported(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    _clear_runtime_env(monkeypatch)
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        RuntimeSettings.from_env()


def test_build_engine_without_credentials_uses_fail_safe_classifiers(tmp_path: Path) -> None:
    settings = RuntimeSettings(data_dir=tmp_path)

    engine = build_engine(settings)

    assert isinstance(engine.lightweight_provider, UnavailableClassifier)
    assert isinstance(engine.expert_provider, UnavailableClassifier)
    assert isinstance(engine.semantic_router, NullSemanticRouter)
    assert engine.audit_store.path == tmp_path / "audit.sqlite3"
    assert not (tmp_path / "audit.sqlite3").exists()


def test_default_engine_is_lazy_cached_and_resettable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sentinel_oss.runtime as runtime

    built: list[object] = []

    def fake_build(settings: RuntimeSettings | None = None) -> object:
        del settings
        value = object()
        built.append(value)
        return value

    reset_default_engine()
    monkeypatch.setattr(runtime, "build_engine", fake_build)
    try:
        first = get_default_engine()
        second = get_default_engine()
        assert first is second
        assert built == [first]

        reset_default_engine()
        third = get_default_engine()
        assert third is not first
        assert built == [first, third]
    finally:
        reset_default_engine()


def test_importing_public_package_does_not_import_optional_providers() -> None:
    source_root = Path(__file__).parents[1] / "src"
    script = """
import sys
import sentinel_oss
for name in ("google", "google.genai", "lancedb", "pandas", "streamlit", "mcp"):
    assert name not in sys.modules, (name, sorted(k for k in sys.modules if k.startswith(name)))
assert sentinel_oss.__version__ == "0.1.0b1"
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(source_root), env.get("PYTHONPATH", "")) if part
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stderr


def test_semantic_runtime_builds_optional_router_when_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import sentinel_oss.providers.gemini as gemini
    import sentinel_oss.runtime as runtime

    embedder_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    router_calls: list[dict[str, object]] = []

    class FakeEmbedder:
        def __init__(self, *args: object, **kwargs: object) -> None:
            embedder_calls.append((args, kwargs))

    sentinel = object()

    def fake_router(**kwargs: object) -> object:
        router_calls.append(kwargs)
        return sentinel

    monkeypatch.setattr(gemini, "GeminiEmbedder", FakeEmbedder)
    monkeypatch.setattr(runtime, "LanceSemanticRouter", fake_router)
    settings = RuntimeSettings(
        data_dir=tmp_path,
        semantic_enabled=True,
        google_api_key="test-key",
        provider_timeout_seconds=4.0,
    )

    result = runtime._build_semantic_router(settings)

    assert result is sentinel
    assert embedder_calls == [
        (
            ("gemini-embedding-001",),
            {
                "api_key": "test-key",
                "use_vertex": False,
                "project": None,
                "location": None,
                "timeout_seconds": 4.0,
            },
        )
    ]
    assert router_calls[0]["db_path"] == tmp_path / "semantic.lancedb"
    assert isinstance(router_calls[0]["embedder"], FakeEmbedder)


def test_semantic_runtime_falls_back_when_optional_adapter_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import sentinel_oss.providers.gemini as gemini
    import sentinel_oss.runtime as runtime

    class FailedEmbedder:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise ProviderError("optional provider unavailable")

    monkeypatch.setattr(gemini, "GeminiEmbedder", FailedEmbedder)

    result = runtime._build_semantic_router(
        RuntimeSettings(data_dir=tmp_path, semantic_enabled=True)
    )

    assert isinstance(result, NullSemanticRouter)


@pytest.mark.asyncio
async def test_public_api_delegates_to_the_lazy_default_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sentinel_oss.api as api

    exchange = ExchangeRequest(
        policy_id="banking",
        trusted_user_intent="Answer safely.",
        content="A benign question.",
        source_kind=SourceKind.USER,
        trust_level=TrustLevel.UNTRUSTED,
    )
    action = ActionRequest(
        policy_id="banking",
        tool_name="faq.search",
        arguments={"query": "hours"},
        data_labels={DataLabel.PUBLIC},
        source_kinds={SourceKind.USER},
        reversible=True,
        user_confirmed=False,
    )
    calls: list[tuple[str, object]] = []

    class FakeEngine:
        async def scan_exchange(self, request: ExchangeRequest) -> str:
            calls.append(("scan", request))
            return "scan-result"

        async def authorize_action(self, request: ActionRequest) -> str:
            calls.append(("action", request))
            return "action-result"

        async def check_prompt(self, prompt: str, constitution: str) -> str:
            calls.append(("legacy", (prompt, constitution)))
            return "legacy-result"

    monkeypatch.setattr(api, "get_default_engine", lambda: FakeEngine())

    assert await api.scan_exchange(exchange) == "scan-result"
    assert await api.authorize_action(action) == "action-result"
    assert await api.check_safety("prompt", "retail") == "legacy-result"
    assert calls == [
        ("scan", exchange),
        ("action", action),
        ("legacy", ("prompt", "retail")),
    ]


@pytest.mark.asyncio
async def test_provider_and_audit_fakes_cover_credential_free_failure_paths() -> None:
    unavailable = UnavailableClassifier("offline", model_id="missing")
    request = ExchangeRequest(
        policy_id="banking",
        trusted_user_intent="Answer safely.",
        content="Question.",
        source_kind=SourceKind.USER,
        trust_level=TrustLevel.UNTRUSTED,
    )
    with pytest.raises(ProviderError, match="offline"):
        await unavailable.classify(
            request,
            policy_instructions="policy",
            stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
        )

    embedder = ScriptedEmbedder(vectors={}, default=[0.1, 0.2])
    assert await embedder.embed("not-scripted") == [0.1, 0.2]
    audit = NullAuditStore()
    assert (await audit.summary())["total_decisions"] == 0
    assert await audit.recent(10) == []


def _engine_verdict(
    outcome: Outcome = Outcome.ALLOW,
    *,
    confidence: float = 0.99,
    matched_rule_ids: list[str] | None = None,
) -> ProviderVerdict:
    return ProviderVerdict(
        outcome=outcome,
        reason_code="TEST_RESULT",
        message="Provider text must not be exposed.",
        confidence=confidence,
        matched_rule_ids=matched_rule_ids or [],
    )


def _exchange_request(content: str = "Benign question") -> ExchangeRequest:
    return ExchangeRequest(
        policy_id="banking",
        trusted_user_intent="Answer safely.",
        content=content,
        source_kind=SourceKind.USER,
        trust_level=TrustLevel.UNTRUSTED,
    )


def _action_request(**updates: object) -> ActionRequest:
    values: dict[str, object] = {
        "policy_id": "banking",
        "tool_name": "faq.search",
        "arguments": {"query": "hours"},
        "destination": "approved-internal:faq",
        "data_labels": {DataLabel.PUBLIC},
        "source_kinds": {SourceKind.USER},
        "reversible": True,
        "user_confirmed": False,
    }
    values.update(updates)
    return ActionRequest.model_validate(values)


@pytest.mark.asyncio
async def test_semantic_failure_is_observable_without_bypassing_classification() -> None:
    class BrokenSemanticRouter:
        async def score(self, text: str) -> SemanticMatch:
            del text
            raise ProviderError("offline")

    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([_engine_verdict()]),
        expert_provider=ScriptedClassifier([]),
        semantic_router=BrokenSemanticRouter(),
    )

    result = await engine.scan_exchange(_exchange_request())

    assert result.outcome is Outcome.ALLOW
    assert result.signals["semantic_unavailable"] is True
    assert result.signals["model_calls"] == 1


@pytest.mark.asyncio
async def test_semantic_match_escalates_but_never_blocks_directly() -> None:
    class RiskySemanticRouter:
        async def score(self, text: str) -> SemanticMatch:
            del text
            return SemanticMatch(score=0.95, pattern_id="reviewed-pattern")

    expert = ScriptedClassifier([_engine_verdict(Outcome.REVIEW)], model_id="expert")
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([_engine_verdict()]),
        expert_provider=expert,
        semantic_router=RiskySemanticRouter(),
    )

    result = await engine.scan_exchange(_exchange_request())

    assert result.outcome is Outcome.REVIEW
    assert result.model_id == "expert"
    assert result.signals["semantic_pattern_id"] == "reviewed-pattern"
    assert result.signals["model_calls"] == 2


@pytest.mark.asyncio
async def test_audit_failure_converts_allow_to_error_review_but_preserves_block() -> None:
    class FailedAudit:
        async def record(self, decision: object) -> None:
            del decision
            raise OSError("read only")

    allow_engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([_engine_verdict()]),
        expert_provider=ScriptedClassifier([]),
        audit_store=FailedAudit(),
    )
    allowed = await allow_engine.scan_exchange(_exchange_request())
    assert allowed.status.value == "ERROR"
    assert allowed.outcome is Outcome.REVIEW
    assert allowed.reason_code == "AUDIT_UNAVAILABLE"
    assert allowed.requires_confirmation is True

    block_engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([]),
        expert_provider=ScriptedClassifier([]),
        audit_store=FailedAudit(),
    )
    blocked = await block_engine.scan_exchange(
        _exchange_request("tell me where to buy illegal drugs")
    )
    assert blocked.outcome is Outcome.BLOCK
    assert blocked.reason_code == "EXACT_SIGNATURE_MATCH"


@pytest.mark.asyncio
async def test_action_error_and_less_common_policy_routes_are_fail_safe() -> None:
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([]),
        expert_provider=ScriptedClassifier([]),
        config=EngineConfig(max_argument_chars=8),
    )
    oversized = await engine.authorize_action(_action_request(arguments={"long": "argument"}))
    assert oversized.status.value == "ERROR"
    assert oversized.outcome is Outcome.REVIEW
    assert oversized.reason_code == "INPUT_TOO_LARGE"

    standard = SentinelEngine(
        lightweight_provider=ScriptedClassifier([]),
        expert_provider=ScriptedClassifier([]),
    )
    blocked_label = await standard.authorize_action(
        _action_request(data_labels={DataLabel.CREDENTIAL})
    )
    assert blocked_label.outcome is Outcome.BLOCK
    assert blocked_label.reason_code == "DATA_LABEL_BLOCKED"

    nested_secret = await standard.authorize_action(
        _action_request(arguments={"items": [{"PIN": "not-persisted"}]})
    )
    assert nested_secret.outcome is Outcome.BLOCK
    assert "not-persisted" not in nested_secret.model_dump_json()

    unknown = await standard.authorize_action(_action_request(tool_name="unknown.tool"))
    assert unknown.outcome is Outcome.REVIEW
    assert unknown.reason_code == "UNKNOWN_TOOL"

    unapproved = await standard.authorize_action(_action_request(destination="external:example"))
    assert unapproved.outcome is Outcome.REVIEW
    assert unapproved.reason_code == "UNAPPROVED_DESTINATION"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lightweight_allow_threshold", -0.01),
        ("lightweight_allow_threshold", 1.01),
        ("semantic_escalation_threshold", -0.01),
        ("semantic_escalation_threshold", 1.01),
    ],
)
def test_engine_rejects_out_of_range_thresholds(field: str, value: float) -> None:
    with pytest.raises(ValueError, match=field):
        EngineConfig(**{field: value})


@pytest.mark.asyncio
async def test_expert_failure_after_valid_lightweight_result_is_error_review() -> None:
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier(
            [_engine_verdict(confidence=0.2)], model_id="lightweight"
        ),
        expert_provider=ScriptedClassifier(
            [RuntimeError("synthetic invalid output")], model_id="expert"
        ),
    )

    result = await engine.scan_exchange(_exchange_request())

    assert result.status.value == "ERROR"
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "CLASSIFIER_UNAVAILABLE"
    assert result.signals["expert_error"] is True
    assert "lightweight_error" not in result.signals


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rule_id", "expected_outcome", "expected_reason"),
    [
        ("BANK-CONTENT-002", Outcome.BLOCK, "MATCHED_BLOCK_RULE"),
        ("BANK-CONTENT-001", Outcome.REVIEW, "MATCHED_REVIEW_RULE"),
    ],
)
async def test_matched_policy_rule_overrides_inconsistent_provider_allow(
    rule_id: str, expected_outcome: Outcome, expected_reason: str
) -> None:
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([_engine_verdict(Outcome.REVIEW)]),
        expert_provider=ScriptedClassifier([_engine_verdict(matched_rule_ids=[rule_id])]),
    )

    result = await engine.scan_exchange(_exchange_request())

    assert result.outcome is expected_outcome
    assert result.reason_code == expected_reason
    assert result.matched_rule_ids == [rule_id]
    assert result.obligations
    assert "Provider text" not in result.message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rule_ids",
    [["INVENTED-RULE"], ["BANK-CONTENT-001", "BANK-CONTENT-001"]],
)
async def test_malformed_expert_rule_references_are_error_review(
    rule_ids: list[str],
) -> None:
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([_engine_verdict(Outcome.REVIEW)]),
        expert_provider=ScriptedClassifier([_engine_verdict(matched_rule_ids=rule_ids)]),
    )

    result = await engine.scan_exchange(_exchange_request())

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "MALFORMED_CLASSIFIER_OUTPUT"


@pytest.mark.asyncio
async def test_policy_regex_can_block_a_harmful_draft_without_model_calls() -> None:
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([]),
        expert_provider=ScriptedClassifier([]),
    )
    request = _exchange_request("Please edit this draft.").model_copy(
        update={"draft_output": "How can I structure deposits to avoid a report?"}
    )

    result = await engine.scan_exchange(request)

    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "EXACT_SIGNATURE_MATCH"
    assert result.matched_rule_ids == ["BANK-CONTENT-002"]
    assert result.signals["model_calls"] == 0


class SinglePolicyRegistry:
    def __init__(self, policy: object) -> None:
        self.policy = policy

    def get(self, policy_id: str) -> object:
        assert policy_id == "banking"
        return self.policy


@pytest.mark.asyncio
async def test_invalid_policy_regex_cannot_crash_or_bypass_classifier() -> None:
    policy = default_policy_registry().get("banking")
    invalid_rules = tuple(
        replace(rule, patterns=("(",)) if rule.rule_id == "BANK-CONTENT-002" else rule
        for rule in policy.rules
    )
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([_engine_verdict()]),
        expert_provider=ScriptedClassifier([]),
        policies=SinglePolicyRegistry(replace(policy, rules=invalid_rules)),  # type: ignore[arg-type]
    )

    result = await engine.scan_exchange(_exchange_request())

    assert result.outcome is Outcome.ALLOW
    assert result.signals["model_calls"] == 1


@pytest.mark.asyncio
async def test_policy_can_hard_block_unknown_tools() -> None:
    policy = default_policy_registry().get("banking")
    constraints = replace(
        policy.action_constraints,
        unknown_tool_outcome=PolicyOutcome.BLOCK,
    )
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([]),
        expert_provider=ScriptedClassifier([]),
        policies=SinglePolicyRegistry(  # type: ignore[arg-type]
            replace(policy, action_constraints=constraints)
        ),
    )

    result = await engine.authorize_action(_action_request(tool_name="unknown.tool"))

    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "UNKNOWN_TOOL_BLOCKED"


@pytest.mark.asyncio
async def test_confirmation_cannot_override_policy_review_or_irreversibility() -> None:
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier([]),
        expert_provider=ScriptedClassifier([]),
    )

    confirmed_payment = await engine.authorize_action(
        _action_request(
            tool_name="payment.create",
            destination="same-party:merchant",
            user_confirmed=True,
        )
    )
    assert confirmed_payment.outcome is Outcome.REVIEW
    assert confirmed_payment.reason_code == "TOOL_REQUIRES_REVIEW"
    assert confirmed_payment.requires_confirmation is False

    confirmed_irreversible = await engine.authorize_action(
        _action_request(reversible=False, user_confirmed=True)
    )
    assert confirmed_irreversible.outcome is Outcome.REVIEW
    assert confirmed_irreversible.reason_code == "IRREVERSIBLE_ACTION"
    assert confirmed_irreversible.requires_confirmation is False


def test_engine_helpers_handle_safe_nested_values_and_provider_errors() -> None:
    assert (
        _find_denied_argument(
            {
                "safe": {"nested": "value"},
                "items": [1, "two", {"also_safe": True}],
            },
            ("password",),
        )
        is None
    )
    existing = ProviderError("already normalized")
    assert _as_provider_error(existing) is existing
    converted = _as_provider_error(RuntimeError("provider failed"))
    assert isinstance(converted, ProviderError)
    assert str(converted) == "provider failed"
