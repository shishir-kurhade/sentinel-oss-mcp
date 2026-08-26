from __future__ import annotations

import pytest

from sentinel_oss.contracts import (
    ActionRequest,
    DataLabel,
    DecisionStatus,
    Outcome,
    SourceKind,
)
from sentinel_oss.engine import SentinelEngine
from sentinel_oss.providers import ScriptedClassifier


def guard() -> SentinelEngine:
    return SentinelEngine(
        lightweight_provider=ScriptedClassifier([]),
        expert_provider=ScriptedClassifier([]),
    )


def action(**updates: object) -> ActionRequest:
    values: dict[str, object] = {
        "policy_id": "banking",
        "tool_name": "faq.search",
        "arguments": {"query": "opening hours"},
        "destination": "approved-internal:knowledge-base",
        "data_labels": {DataLabel.PUBLIC},
        "source_kinds": {SourceKind.USER},
        "reversible": True,
        "user_confirmed": False,
    }
    values.update(updates)
    return ActionRequest.model_validate(values)


@pytest.mark.asyncio
async def test_allowlisted_reversible_public_action_is_allowed() -> None:
    result = await guard().authorize_action(action())
    assert result.status is DecisionStatus.COMPLETE
    assert result.outcome is Outcome.ALLOW
    assert result.reason_code == "ACTION_ALLOWED"
    assert result.signals["model_calls"] == 0


@pytest.mark.asyncio
async def test_denied_tool_is_blocked_before_confirmation() -> None:
    result = await guard().authorize_action(
        action(tool_name="credential.collect", user_confirmed=True)
    )
    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "TOOL_DENIED"


@pytest.mark.asyncio
async def test_nested_denied_argument_is_blocked() -> None:
    result = await guard().authorize_action(action(arguments={"profile": {"pin": "not-persisted"}}))
    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "ARGUMENT_DENIED"
    assert "not-persisted" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_confirmation_required_action_requests_review() -> None:
    result = await guard().authorize_action(
        action(
            tool_name="payment.create",
            destination="same-party:merchant",
            reversible=False,
        )
    )
    assert result.outcome is Outcome.REVIEW
    assert result.requires_confirmation is True


@pytest.mark.asyncio
async def test_confirmation_does_not_override_sensitive_data_review() -> None:
    result = await guard().authorize_action(
        action(
            data_labels={DataLabel.PII},
            user_confirmed=True,
        )
    )
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "SENSITIVE_DATA"


@pytest.mark.asyncio
async def test_untrusted_provenance_requests_review() -> None:
    result = await guard().authorize_action(action(source_kinds={SourceKind.WEB}))
    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "UNTRUSTED_PROVENANCE"


@pytest.mark.asyncio
async def test_unknown_tool_review_returns_explicit_caller_obligations() -> None:
    result = await guard().authorize_action(action(tool_name="unregistered.lookup"))

    assert result.outcome is Outcome.REVIEW
    assert result.reason_code == "UNKNOWN_TOOL"
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
async def test_denied_destination_is_hard_block() -> None:
    result = await guard().authorize_action(
        action(destination="anonymous:dropbox", user_confirmed=True)
    )
    assert result.outcome is Outcome.BLOCK
    assert result.reason_code == "DESTINATION_DENIED"


@pytest.mark.asyncio
async def test_unknown_policy_is_error_review() -> None:
    result = await guard().authorize_action(action(policy_id="missing"))
    assert result.status is DecisionStatus.ERROR
    assert result.outcome is Outcome.REVIEW
    assert result.obligations == [
        "Do not execute or release content until this review is resolved."
    ]
