from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from sentinel_oss.policies import (
    PolicyRegistry,
    PolicyStage,
    PolicyValidationError,
    UnknownPolicyError,
    default_policy_registry,
    load_policy_pack,
)

PACKS = Path(__file__).parents[1] / "src/sentinel_oss/policy_packs"


def _base_policy() -> dict[str, Any]:
    return json.loads((PACKS / "banking-1.0.0.json").read_text(encoding="utf-8"))


def _write_policy(directory: Path, policy: Any, name: str = "policy.json") -> None:
    (directory / name).write_text(json.dumps(policy), encoding="utf-8")


def test_registry_discovery_errors_and_invalid_json(tmp_path: Path) -> None:
    with pytest.raises(PolicyValidationError, match="does not exist"):
        PolicyRegistry(tmp_path / "missing")
    with pytest.raises(PolicyValidationError, match="No JSON policy packs"):
        PolicyRegistry(tmp_path)

    (tmp_path / "bad.json").write_text("{not-json}", encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="Unable to read policy pack"):
        PolicyRegistry(tmp_path)


def test_registry_rejects_duplicate_policy_and_version(tmp_path: Path) -> None:
    policy = _base_policy()
    _write_policy(tmp_path, policy, "one.json")
    _write_policy(tmp_path, policy, "two.json")
    with pytest.raises(PolicyValidationError, match="Duplicate policy pack"):
        PolicyRegistry(tmp_path)


def test_cached_registry_loader_and_public_aliases() -> None:
    default_policy_registry.cache_clear()
    registry = default_policy_registry()
    assert default_policy_registry() is registry
    pack = load_policy_pack("banking", "1.0.0")
    assert pack is registry.load("banking")
    assert registry.pack_dir == PACKS
    assert pack.rules_for_stage("CONTENT") == pack.rules_for_stage(PolicyStage.CONTENT)
    with pytest.raises(PolicyValidationError, match="stage must be one of"):
        pack.rules_for_stage("INVALID")
    with pytest.raises(UnknownPolicyError):
        registry.versions("missing")

    rule = pack.rules[0]
    assert rule.id == rule.rule_id
    assert rule.caller_obligations == rule.obligations
    constraints = pack.action_constraints
    assert constraints.allowed_tool_patterns == constraints.allowed_tools
    assert constraints.denied_tool_patterns == constraints.denied_tools
    assert constraints.review_tool_patterns == constraints.review_tools
    assert constraints.confirmation_tool_patterns == constraints.confirmation_required_tools
    assert constraints.allowed_destination_patterns == constraints.allowed_destinations
    assert constraints.denied_destination_patterns == constraints.denied_destinations
    assert constraints.review_data_labels == constraints.sensitive_labels_requiring_review


@pytest.mark.parametrize(
    ("kind", "match"),
    [
        ("root_not_object", "policy pack must be an object"),
        ("unknown_root", "policy pack contains unknown fields"),
        ("schema", "unsupported policy schema"),
        ("policy_id", "invalid policy_id"),
        ("version", "must use MAJOR.MINOR.PATCH"),
        ("missing_title", "title must be a non-empty string"),
        ("instructions_not_array", "classifier_instructions must be an array"),
        ("instructions_empty", "classifier_instructions must not be empty"),
        ("instructions_duplicate", "classifier_instructions values must be unique"),
        ("rules_not_array", "rules must be an array"),
        ("rules_empty", "rules must not be empty"),
        ("rules_duplicate", "rule IDs must be unique"),
        ("no_content_rule", "at least one CONTENT rule"),
        ("no_action_rule", "at least one ACTION rule"),
        ("obligations_duplicate", "obligation IDs must be unique"),
        ("obligation_not_object", "obligations\\[0\\] must be an object"),
        ("obligation_bad_stage", "stage must be one of"),
        ("constraint_not_object", "action_constraints must be an object"),
        ("constraint_unknown", "action_constraints contains unknown fields"),
        ("allowed_empty", "allowed_tools must not be empty"),
        ("label_overlap", "cannot be both blocked and review-only"),
        ("label_unsupported", "unsupported action data labels"),
        ("bool_type", "review_if_irreversible must be a boolean"),
    ],
)
def test_policy_pack_validation_rejects_malformed_top_level_and_constraints(
    tmp_path: Path, kind: str, match: str
) -> None:
    policy: Any = deepcopy(_base_policy())
    if kind == "root_not_object":
        policy = []
    elif kind == "unknown_root":
        policy["unexpected"] = True
    elif kind == "schema":
        policy["schema_version"] = "2.0"
    elif kind == "policy_id":
        policy["policy_id"] = "INVALID-ID"
    elif kind == "version":
        policy["version"] = "v1"
    elif kind == "missing_title":
        policy["title"] = ""
    elif kind == "instructions_not_array":
        policy["classifier_instructions"] = "instruction"
    elif kind == "instructions_empty":
        policy["classifier_instructions"] = []
    elif kind == "instructions_duplicate":
        first = policy["classifier_instructions"][0]
        policy["classifier_instructions"] = [first, first]
    elif kind == "rules_not_array":
        policy["rules"] = {}
    elif kind == "rules_empty":
        policy["rules"] = []
    elif kind == "rules_duplicate":
        policy["rules"][1]["rule_id"] = policy["rules"][0]["rule_id"]
    elif kind == "no_content_rule":
        policy["rules"] = [rule for rule in policy["rules"] if rule["stage"] != "CONTENT"]
    elif kind == "no_action_rule":
        policy["rules"] = [rule for rule in policy["rules"] if rule["stage"] != "ACTION"]
    elif kind == "obligations_duplicate":
        policy["obligations"][1]["obligation_id"] = policy["obligations"][0]["obligation_id"]
    elif kind == "obligation_not_object":
        policy["obligations"][0] = "bad"
    elif kind == "obligation_bad_stage":
        policy["obligations"][0]["stage"] = "INVALID"
    elif kind == "constraint_not_object":
        policy["action_constraints"] = []
    elif kind == "constraint_unknown":
        policy["action_constraints"]["unexpected"] = True
    elif kind == "allowed_empty":
        policy["action_constraints"]["allowed_tools"] = []
    elif kind == "label_overlap":
        policy["action_constraints"]["sensitive_labels_requiring_review"].append("CREDENTIAL")
    elif kind == "label_unsupported":
        policy["action_constraints"]["blocked_data_labels"].append("SECRET")
    elif kind == "bool_type":
        policy["action_constraints"]["review_if_irreversible"] = "true"

    _write_policy(tmp_path, policy)
    with pytest.raises(PolicyValidationError, match=match):
        PolicyRegistry(tmp_path)


@pytest.mark.parametrize(
    ("kind", "match"),
    [
        ("not_object", "rules\\[0\\] must be an object"),
        ("unknown", "rules\\[0\\] contains unknown fields"),
        ("caller", "stage must be CONTENT or ACTION"),
        ("classifier_type", "classifier_instruction must be a string or null"),
        ("classifier_missing", "classifier_instruction is required"),
        ("bad_id", "rule_id is invalid"),
        ("action_patterns", "patterns is required for ACTION"),
        ("invalid_regex", "contains invalid regex"),
        ("bad_severity", "severity must be one of"),
        ("bad_outcome", "outcome must be one of"),
        ("patterns_not_array", "patterns must be an array"),
        ("patterns_empty_string", "patterns must contain only non-empty strings"),
        ("patterns_duplicate", "patterns values must be unique"),
    ],
)
def test_policy_rule_validation_rejects_malformed_rules(
    tmp_path: Path, kind: str, match: str
) -> None:
    policy = deepcopy(_base_policy())
    rule: Any = policy["rules"][0]
    if kind == "not_object":
        policy["rules"][0] = "bad"
    elif kind == "unknown":
        rule["unexpected"] = True
    elif kind == "caller":
        rule["stage"] = "CALLER"
    elif kind == "classifier_type":
        rule["classifier_instruction"] = 1
    elif kind == "classifier_missing":
        rule["classifier_instruction"] = ""
    elif kind == "bad_id":
        rule["rule_id"] = "bad"
    elif kind == "action_patterns":
        action_rule = next(item for item in policy["rules"] if item["stage"] == "ACTION")
        action_rule["patterns"] = []
    elif kind == "invalid_regex":
        rule["patterns"] = ["("]
    elif kind == "bad_severity":
        rule["severity"] = "EXTREME"
    elif kind == "bad_outcome":
        rule["outcome"] = "MAYBE"
    elif kind == "patterns_not_array":
        rule["patterns"] = "pattern"
    elif kind == "patterns_empty_string":
        rule["patterns"] = [""]
    elif kind == "patterns_duplicate":
        rule["patterns"] = ["a", "a"]

    _write_policy(tmp_path, policy)
    with pytest.raises(PolicyValidationError, match=match):
        PolicyRegistry(tmp_path)
