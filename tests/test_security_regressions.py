from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinel_oss.audit import NullAuditStore, SQLiteAuditStore
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
from sentinel_oss.engine import EngineConfig, SentinelEngine
from sentinel_oss.policies import default_policy_registry
from sentinel_oss.providers import ScriptedClassifier


def _action_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "policy_id": "banking",
        "tool_name": "faq.search",
        "arguments": {"query": "opening hours"},
        "destination": "approved-internal:knowledge-base",
        "data_labels": {DataLabel.PUBLIC},
        "source_kinds": {SourceKind.USER},
        "reversible": True,
        "user_confirmed": False,
    }
    payload.update(updates)
    return payload


def _action(**updates: object) -> ActionRequest:
    return ActionRequest.model_validate(_action_payload(**updates))


def _exchange(content: str) -> ExchangeRequest:
    return ExchangeRequest(
        policy_id="banking",
        trusted_user_intent="Answer the request while following the selected policy.",
        content=content,
        source_kind=SourceKind.USER,
        trust_level=TrustLevel.UNTRUSTED,
    )


def _engine(
    lightweight: list[ProviderVerdict | Exception] | None = None,
    expert: list[ProviderVerdict | Exception] | None = None,
    **kwargs: Any,
) -> SentinelEngine:
    return SentinelEngine(
        lightweight_provider=ScriptedClassifier(lightweight or [], model_id="lightweight"),
        expert_provider=ScriptedClassifier(expert or [], model_id="expert"),
        audit_store=kwargs.pop("audit_store", NullAuditStore()),
        **kwargs,
    )


def _verdict(
    outcome: Outcome = Outcome.ALLOW,
    *,
    reason_code: str = "SYNTHETIC_RESULT",
    message: str = "Synthetic provider result.",
    matched_rule_ids: list[str] | None = None,
    obligations: list[str] | None = None,
) -> ProviderVerdict:
    return ProviderVerdict(
        outcome=outcome,
        reason_code=reason_code,
        message=message,
        matched_rule_ids=matched_rule_ids or [],
        obligations=obligations or [],
        confidence=0.99,
    )


@pytest.mark.parametrize(
    ("field", "value", "remove"),
    [
        ("data_labels", None, True),
        ("data_labels", set(), False),
        ("source_kinds", None, True),
        ("source_kinds", set(), False),
        ("user_confirmed", None, True),
    ],
)
def test_action_security_declarations_are_required_and_nonempty(
    field: str, value: object, remove: bool
) -> None:
    payload = _action_payload()
    if remove:
        payload.pop(field)
    else:
        payload[field] = value

    with pytest.raises(ValidationError) as caught:
        ActionRequest.model_validate(payload)

    assert any(error["loc"] == (field,) for error in caught.value.errors())


def _fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if "!" <= character <= "~" else character
        for character in value
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("updates", "expected_reason"),
    [
        ({"tool_name": _fullwidth("credential.collect")}, "TOOL_DENIED"),
        ({"destination": _fullwidth("anonymous:dropbox")}, "DESTINATION_DENIED"),
        ({"arguments": {_fullwidth("pin"): "never-persist"}}, "ARGUMENT_DENIED"),
    ],
)
async def test_unicode_obfuscation_cannot_bypass_action_denies(
    updates: dict[str, object], expected_reason: str
) -> None:
    result = await _engine().authorize_action(_action(**updates))

    assert result.status is DecisionStatus.COMPLETE
    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == expected_reason
    assert "never-persist" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_denied_argument_is_found_through_deeply_nested_arrays() -> None:
    nested: object = {"pin": "deep-secret"}
    for _ in range(128):
        nested = [nested]

    result = await _engine().authorize_action(_action(arguments={"payload": nested}))

    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "ARGUMENT_DENIED"
    assert "deep-secret" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_mutated_action_payload_is_revalidated_at_engine_boundary() -> None:
    request = _action()
    request.arguments["not_json"] = object()

    result = await _engine().authorize_action(request)

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "INVALID_ACTION_REQUEST"


class _BrokenRegistry:
    def get(self, policy_id: str) -> object:
        del policy_id
        raise RuntimeError("synthetic registry failure")


@pytest.mark.asyncio
async def test_unexpected_internal_failures_are_contained() -> None:
    engine = _engine(policies=_BrokenRegistry())  # type: ignore[arg-type]

    exchange = await engine.scan_exchange(_exchange("Ordinary synthetic input."))
    action = await engine.authorize_action(_action())

    assert exchange.status is DecisionStatus.ERROR
    assert exchange.outcome is Outcome.REVIEW
    assert exchange.reason_code == "EXCHANGE_EVALUATION_FAILURE"
    assert action.status is DecisionStatus.ERROR
    assert action.outcome is Outcome.REVIEW
    assert action.reason_code == "ACTION_EVALUATION_FAILURE"


class _RawClassifier:
    model_id = "raw-provider"

    def __init__(self, result: object) -> None:
        self.result = result

    async def classify(
        self,
        request: ExchangeRequest,
        *,
        policy_instructions: str,
        stage: EvaluationStage,
    ) -> object:
        del request, policy_instructions, stage
        return self.result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "malformed_result",
    [
        {"outcome": "ALLOW", "reason_code": "MISSING_REQUIRED_FIELDS"},
        {"outcome": "NOT_AN_OUTCOME", "message": "invalid", "confidence": 1.0},
        object(),
    ],
)
async def test_malformed_provider_returns_fail_closed(malformed_result: object) -> None:
    engine = SentinelEngine(
        lightweight_provider=_RawClassifier(malformed_result),  # type: ignore[arg-type]
        expert_provider=_RawClassifier(malformed_result),  # type: ignore[arg-type]
        audit_store=NullAuditStore(),
    )

    result = await engine.scan_exchange(_exchange("Ordinary synthetic input."))

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "CLASSIFIER_UNAVAILABLE"
    assert result.requires_confirmation is True


@pytest.mark.asyncio
async def test_provider_and_request_strings_never_cross_decision_or_audit_boundary(
    tmp_path: Path,
) -> None:
    input_secret = "RAW_INPUT_SENTINEL_9321"
    provider_reason = "PROVIDER_REASON_SENTINEL_7145"
    provider = _verdict(
        reason_code=provider_reason,
        message=f"Provider echoed {input_secret}",
        obligations=[f"Persist {input_secret}"],
    )
    database = tmp_path / "audit.sqlite3"
    store = SQLiteAuditStore(database)
    engine = _engine([provider], audit_store=store)

    result = await engine.scan_exchange(_exchange(input_secret))

    assert result.outcome is Outcome.ALLOW
    serialized_decision = result.model_dump_json()
    assert input_secret not in serialized_decision
    assert provider_reason not in serialized_decision
    assert result.reason_code == "CLASSIFIER_ALLOW"

    with sqlite3.connect(database) as connection:
        persisted = " ".join(
            str(value)
            for row in connection.execute("SELECT * FROM decisions").fetchall()
            for value in row
        )
    assert input_secret not in persisted
    assert provider_reason not in persisted
    assert input_secret.encode() not in database.read_bytes()
    assert provider_reason.encode() not in database.read_bytes()


@pytest.mark.asyncio
async def test_unknown_policy_identifier_is_redacted_from_decisions_and_sqlite(
    tmp_path: Path,
) -> None:
    sensitive_policy_id = "secret_4111111111111111"
    database = tmp_path / "audit.sqlite3"
    store = SQLiteAuditStore(database)
    engine = _engine(audit_store=store)

    exchange_decision = await engine.scan_exchange(
        _exchange("Ordinary synthetic input.").model_copy(update={"policy_id": sensitive_policy_id})
    )
    action_decision = await engine.authorize_action(_action(policy_id=sensitive_policy_id))

    for decision in (exchange_decision, action_decision):
        assert decision.status is DecisionStatus.ERROR
        assert decision.outcome is Outcome.REVIEW
        assert decision.reason_code == "POLICY_NOT_FOUND"
        assert decision.policy_id == "unknown"
        assert sensitive_policy_id not in decision.model_dump_json()

    with sqlite3.connect(database) as connection:
        persisted = " ".join(
            str(value)
            for row in connection.execute("SELECT * FROM decisions").fetchall()
            for value in row
        )
    assert sensitive_policy_id not in persisted
    assert {row["policy_id"] for row in await store.recent()} == {"unknown"}
    for sqlite_file in database.parent.glob(f"{database.name}*"):
        assert sensitive_policy_id.encode() not in sqlite_file.read_bytes()


@pytest.mark.asyncio
async def test_nfkc_expansion_over_limit_fails_closed_after_normalization() -> None:
    lightweight = ScriptedClassifier([], model_id="lightweight")
    expert = ScriptedClassifier([], model_id="expert")
    engine = SentinelEngine(
        lightweight_provider=lightweight,
        expert_provider=expert,
        audit_store=NullAuditStore(),
        config=EngineConfig(max_content_chars=8),
    )
    expansion_character = "\ufdfa"
    assert len(expansion_character) == 1

    result = await engine.scan_exchange(_exchange(expansion_character))

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "NORMALIZED_INPUT_TOO_LARGE"
    assert lightweight.calls == expert.calls == []


@pytest.mark.asyncio
async def test_zero_width_only_content_fails_closed_after_normalization() -> None:
    lightweight = ScriptedClassifier([], model_id="lightweight")
    expert = ScriptedClassifier([], model_id="expert")
    engine = SentinelEngine(
        lightweight_provider=lightweight,
        expert_provider=expert,
        audit_store=NullAuditStore(),
    )

    result = await engine.scan_exchange(_exchange("\u200b\u200c\u200d\u2060\ufeff"))

    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "NORMALIZED_INPUT_EMPTY"
    assert lightweight.calls == expert.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "matched_rule_ids",
    [
        ["BANK-CONTENT-001", "BANK-CONTENT-002"],
        ["BANK-CONTENT-002", "BANK-CONTENT-001"],
    ],
)
async def test_matched_block_rule_precedes_review_regardless_of_provider_order(
    matched_rule_ids: list[str],
) -> None:
    provider = _verdict(Outcome.ALLOW, matched_rule_ids=matched_rule_ids)

    result = await _engine(
        [_verdict(Outcome.REVIEW)],
        [provider],
    ).scan_exchange(_exchange("Ordinary account question."))

    assert result.status is DecisionStatus.COMPLETE
    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "MATCHED_BLOCK_RULE"
    assert result.matched_rule_ids == matched_rule_ids


@pytest.mark.asyncio
async def test_confirmation_cannot_allow_an_irreversible_action() -> None:
    result = await _engine().authorize_action(_action(reversible=False, user_confirmed=True))

    assert result.status is DecisionStatus.COMPLETE
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "IRREVERSIBLE_ACTION"
    assert result.requires_confirmation is False


class _SinglePolicyRegistry:
    def __init__(self, policy: object) -> None:
        self.policy = policy

    def get(self, policy_id: str) -> object:
        assert policy_id == "banking"
        return self.policy


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "expected_outcome", "expected_reason", "expected_rule"),
    [
        ("credential.collect", Outcome.BLOCK, "TOOL_DENIED", "BANK-ACTION-001"),
        (
            "payment.create",
            Outcome.REVIEW,
            "TOOL_REQUIRES_REVIEW",
            "BANK-ACTION-002",
        ),
    ],
)
async def test_action_rule_patterns_remain_enforced_if_constraints_drift(
    tool_name: str,
    expected_outcome: Outcome,
    expected_reason: str,
    expected_rule: str,
) -> None:
    policy = default_policy_registry().get("banking")
    drifted_constraints = replace(
        policy.action_constraints,
        allowed_tools=(),
        denied_tools=(),
        review_tools=(),
        confirmation_required_tools=(),
    )
    drifted_policy = replace(policy, action_constraints=drifted_constraints)
    engine = _engine(
        policies=_SinglePolicyRegistry(drifted_policy),  # type: ignore[arg-type]
    )

    result = await engine.authorize_action(
        _action(
            tool_name=tool_name,
            destination="same-party:test",
            user_confirmed=True,
        )
    )

    assert result.outcome is expected_outcome
    assert result.reason_code == expected_reason
    assert result.matched_rule_ids == [expected_rule]


@pytest.mark.asyncio
async def test_action_block_rule_precedes_overlapping_review_rule() -> None:
    result = await _engine().authorize_action(
        ActionRequest(
            policy_id="telecom",
            tool_name="sim.clone",
            arguments={},
            destination="same-subscriber:test",
            data_labels={DataLabel.PUBLIC},
            source_kinds={SourceKind.USER},
            reversible=True,
            user_confirmed=True,
        )
    )

    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "TOOL_DENIED"
    assert result.matched_rule_ids == ["TEL-ACTION-001"]
    assert "TEL-ACTION-002" not in result.matched_rule_ids
