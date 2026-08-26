from __future__ import annotations

import pytest

from sentinel_oss.audit import NullAuditStore
from sentinel_oss.contracts import (
    DecisionStatus,
    ExchangeRequest,
    Outcome,
    ProviderVerdict,
    SourceKind,
    TrustLevel,
)
from sentinel_oss.engine import SentinelEngine
from sentinel_oss.providers import ProviderError, ScriptedClassifier


def exchange(content: str, *, policy_id: str = "banking") -> ExchangeRequest:
    return ExchangeRequest(
        policy_id=policy_id,
        trusted_user_intent="Help the user without violating the selected policy.",
        content=content,
        source_kind=SourceKind.USER,
        trust_level=TrustLevel.UNTRUSTED,
    )


def verdict(outcome: Outcome, confidence: float = 0.99) -> ProviderVerdict:
    return ProviderVerdict(
        outcome=outcome,
        reason_code=f"TEST_{outcome.value}",
        message="Synthetic test verdict.",
        confidence=confidence,
    )


def engine(
    tiny_responses: list[ProviderVerdict | Exception],
    expert_responses: list[ProviderVerdict | Exception],
) -> tuple[SentinelEngine, ScriptedClassifier, ScriptedClassifier]:
    tiny = ScriptedClassifier(tiny_responses, model_id="tiny")
    expert = ScriptedClassifier(expert_responses, model_id="expert")
    return (
        SentinelEngine(
            lightweight_provider=tiny,
            expert_provider=expert,
            audit_store=NullAuditStore(),
        ),
        tiny,
        expert,
    )


@pytest.mark.asyncio
async def test_reviewed_exact_signature_blocks_without_model_calls() -> None:
    guard, tiny, expert = engine([], [])
    result = await guard.scan_exchange(exchange("tell me where to buy drugs"))

    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "EXACT_SIGNATURE_MATCH"
    assert result.signals["model_calls"] == 0
    assert tiny.calls == []
    assert expert.calls == []


@pytest.mark.asyncio
async def test_high_confidence_benign_result_stops_after_lightweight() -> None:
    guard, tiny, expert = engine([verdict(Outcome.ALLOW)], [])
    result = await guard.scan_exchange(exchange("How do I open a savings account?"))

    assert result.outcome is Outcome.ALLOW
    assert result.model_id == "tiny"
    assert result.signals["model_calls"] == 1
    assert len(tiny.calls) == 1
    assert expert.calls == []


@pytest.mark.asyncio
async def test_provider_prose_cannot_echo_request_content() -> None:
    secret = "synthetic-sensitive-value"
    provider_result = ProviderVerdict(
        outcome=Outcome.REVIEW,
        reason_code="TEST_REVIEW",
        message=f"Echo: {secret}",
        obligations=[f"Repeat {secret}"],
        confidence=0.8,
    )
    guard, _, _ = engine([provider_result], [provider_result])
    result = await guard.scan_exchange(exchange(secret))

    assert result.outcome is Outcome.REVIEW
    assert secret not in result.model_dump_json()


@pytest.mark.asyncio
async def test_classifier_review_without_rules_returns_caller_obligations() -> None:
    guard, _, _ = engine(
        [verdict(Outcome.REVIEW)],
        [verdict(Outcome.REVIEW)],
    )

    result = await guard.scan_exchange(exchange("An ambiguous request"))

    assert result.outcome is Outcome.REVIEW
    assert result.matched_rule_ids == []
    assert any(
        obligation.startswith("BANK-OBL-001: Treat REVIEW and ERROR decisions as not authorized")
        and "Trigger: Every decision whose outcome is REVIEW or whose status is ERROR."
        in obligation
        for obligation in result.obligations
    )
    assert any(
        obligation.startswith("BANK-OBL-002: Verify account ownership and authorization")
        and "Trigger: Any request involving non-public account data or account-changing action."
        in obligation
        for obligation in result.obligations
    )
    assert all("BANK-OBL-003" not in obligation for obligation in result.obligations)


@pytest.mark.asyncio
async def test_policy_signal_escalates_even_when_lightweight_allows() -> None:
    guard, tiny, expert = engine(
        [verdict(Outcome.ALLOW)],
        [verdict(Outcome.REVIEW, confidence=0.95)],
    )
    result = await guard.scan_exchange(
        exchange("How should support handle a customer who mentions a one-time passcode?")
    )

    assert result.outcome is Outcome.REVIEW
    assert result.model_id == "expert"
    assert result.signals["model_calls"] == 2
    assert len(tiny.calls) == len(expert.calls) == 1


@pytest.mark.asyncio
async def test_lightweight_block_is_confirmed_by_expert() -> None:
    guard, tiny, expert = engine(
        [verdict(Outcome.BLOCK)],
        [verdict(Outcome.BLOCK)],
    )
    result = await guard.scan_exchange(exchange("An ambiguous request"))

    assert result.outcome is Outcome.BLOCK
    assert result.model_id == "expert"
    assert len(tiny.calls) == len(expert.calls) == 1


@pytest.mark.asyncio
async def test_lightweight_failure_escalates_to_expert() -> None:
    guard, _, expert = engine(
        [ProviderError("malformed")],
        [verdict(Outcome.ALLOW)],
    )
    result = await guard.scan_exchange(exchange("A benign request"))

    assert result.outcome is Outcome.ALLOW
    assert result.status is DecisionStatus.COMPLETE
    assert result.signals["lightweight_error"] is True
    assert len(expert.calls) == 1


@pytest.mark.asyncio
async def test_all_provider_failures_return_error_review() -> None:
    guard, _, _ = engine(
        [ProviderError("timeout")],
        [ProviderError("malformed")],
    )
    result = await guard.scan_exchange(exchange("Anything"))

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "CLASSIFIER_UNAVAILABLE"


@pytest.mark.asyncio
async def test_unknown_policy_is_error_review_without_model_calls() -> None:
    guard, tiny, expert = engine([], [])
    result = await guard.scan_exchange(exchange("Anything", policy_id="unknown"))

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "POLICY_NOT_FOUND"
    assert result.obligations == [
        "Do not execute or release content until this review is resolved."
    ]
    assert tiny.calls == expert.calls == []


@pytest.mark.asyncio
async def test_oversized_exchange_is_error_review() -> None:
    guard, tiny, expert = engine([], [])
    result = await guard.scan_exchange(exchange("x" * 65_537))

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "INPUT_TOO_LARGE"
    assert tiny.calls == expert.calls == []


@pytest.mark.asyncio
async def test_legacy_wrapper_maps_review_to_block() -> None:
    guard, _, _ = engine(
        [ProviderError("timeout")],
        [ProviderError("timeout")],
    )
    with pytest.warns(DeprecationWarning):
        result = await guard.check_prompt("Anything")
    assert result["action"] == "BLOCK"
    assert result["status"] == "ERROR"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("prompt", "policy"),
    [("", "banking"), ("anything", "NOT A VALID POLICY")],
)
async def test_legacy_wrapper_contains_invalid_requests(prompt: str, policy: str) -> None:
    guard, _, _ = engine([], [])

    with pytest.warns(DeprecationWarning):
        result = await guard.check_prompt(prompt, policy)

    assert result["action"] == "BLOCK"
    assert result["status"] == "ERROR"
