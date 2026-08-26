from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel_oss.contracts import ActionRequest


def valid_action_payload() -> dict[str, object]:
    return {
        "policy_id": "banking",
        "tool_name": "faq.search",
        "arguments": {},
        "data_labels": ["PUBLIC"],
        "source_kinds": ["USER"],
        "reversible": True,
        "user_confirmed": False,
    }


def test_action_arguments_must_be_json_serializable() -> None:
    with pytest.raises(ValidationError, match="JSON serializable"):
        ActionRequest(
            policy_id="banking",
            tool_name="faq.search",
            arguments={"object": object()},
            reversible=True,
        )


def test_public_contracts_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        ActionRequest.model_validate(
            {
                "policy_id": "banking",
                "tool_name": "faq.search",
                "reversible": True,
                "unexpected": "field",
            }
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_action_arguments_reject_non_json_numbers(value: float) -> None:
    payload = valid_action_payload()
    payload["arguments"] = {"amount": value}

    with pytest.raises(ValidationError, match="JSON serializable"):
        ActionRequest.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    ["arguments", "data_labels", "source_kinds", "reversible", "user_confirmed"],
)
def test_security_relevant_action_fields_are_required(field: str) -> None:
    payload = valid_action_payload()
    payload.pop(field)

    with pytest.raises(ValidationError) as error:
        ActionRequest.model_validate(payload)

    assert any(item["loc"] == (field,) for item in error.value.errors())
