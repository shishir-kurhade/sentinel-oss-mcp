from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel_oss.policies import (
    PolicyOutcome,
    PolicyRegistry,
    PolicyStage,
    PolicyValidationError,
    UnknownPolicyError,
    UnknownPolicyVersionError,
)

EXPECTED_POLICIES = {"banking", "healthcare", "telecom", "retail", "hr_it"}


def test_builtin_registry_exposes_all_versioned_illustrative_packs() -> None:
    registry = PolicyRegistry()

    assert set(registry.policy_ids()) == EXPECTED_POLICIES
    assert len(registry.list_policies()) == len(EXPECTED_POLICIES)

    for policy_id in EXPECTED_POLICIES:
        pack = registry.get(policy_id)
        assert pack.policy_id == policy_id
        assert pack.version == "1.0.0"
        assert pack.illustrative is True
        assert pack.disclaimer
        assert pack.classifier_instructions
        assert pack.rules_for_stage(PolicyStage.CONTENT)
        assert pack.rules_for_stage(PolicyStage.ACTION)
        assert len(pack.rules_by_id) == len(pack.rules)


def test_action_constraints_are_explicit_and_fail_safe() -> None:
    for summary in PolicyRegistry().list_policies():
        constraints = PolicyRegistry().get(summary.policy_id).action_constraints
        assert constraints.allowed_tools
        assert constraints.denied_tools
        assert constraints.allowed_destinations
        assert constraints.denied_destinations
        assert constraints.unknown_tool_outcome is PolicyOutcome.REVIEW
        assert constraints.review_if_irreversible is True
        assert constraints.review_if_untrusted_source is True
        assert "CREDENTIAL" in constraints.blocked_data_labels


def test_unknown_policy_has_no_fallback() -> None:
    registry = PolicyRegistry()

    with pytest.raises(UnknownPolicyError) as caught:
        registry.get("not_installed")

    assert caught.value.policy_id == "not_installed"
    assert set(caught.value.available_policy_ids) == EXPECTED_POLICIES


def test_unknown_policy_version_has_no_fallback() -> None:
    registry = PolicyRegistry()

    with pytest.raises(UnknownPolicyVersionError) as caught:
        registry.get("banking", "9.9.9")

    assert caught.value.version == "9.9.9"
    assert caught.value.available_versions == ("1.0.0",)


def test_registry_uses_highest_semantic_version_when_unpinned(tmp_path: Path) -> None:
    source = (
        Path(__file__).parents[1] / "src" / "sentinel_oss" / "policy_packs" / "banking-1.0.0.json"
    )
    original = json.loads(source.read_text(encoding="utf-8"))
    for version in ("1.2.0", "1.10.0"):
        candidate = dict(original)
        candidate["version"] = version
        (tmp_path / f"banking-{version}.json").write_text(json.dumps(candidate), encoding="utf-8")

    registry = PolicyRegistry(tmp_path)

    assert registry.get("banking").version == "1.10.0"
    assert registry.get("banking", "1.2.0").version == "1.2.0"


def test_registry_rejects_allow_for_unknown_tools(tmp_path: Path) -> None:
    source = (
        Path(__file__).parents[1] / "src" / "sentinel_oss" / "policy_packs" / "retail-1.0.0.json"
    )
    policy = json.loads(source.read_text(encoding="utf-8"))
    policy["action_constraints"]["unknown_tool_outcome"] = "ALLOW"
    (tmp_path / "unsafe.json").write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="must not be ALLOW"):
        PolicyRegistry(tmp_path)


def test_registry_rejects_nonillustrative_beta_pack(tmp_path: Path) -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "sentinel_oss"
        / "policy_packs"
        / "healthcare-1.0.0.json"
    )
    policy = json.loads(source.read_text(encoding="utf-8"))
    policy["illustrative"] = False
    (tmp_path / "compliance-claim.json").write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(PolicyValidationError, match="illustrative=true"):
        PolicyRegistry(tmp_path)
