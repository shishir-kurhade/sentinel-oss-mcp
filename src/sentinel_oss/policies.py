"""Versioned, illustrative policy packs used by Sentinel.

Policy packs are data, not compliance certifications.  The loader deliberately
has no default-policy fallback: callers must name an installed policy and may
optionally pin its exact version.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

POLICY_PACK_SCHEMA_VERSION = "1.0"
_BUILTIN_PACK_DIR = Path(__file__).with_name("policy_packs")
_POLICY_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9_-]{2,127}$")
_VERSION_PATTERN = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)$"
)
_SUPPORTED_DATA_LABELS = frozenset(
    {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII", "PHI", "PAYMENT", "CREDENTIAL"}
)


class PolicyError(ValueError):
    """Base exception for policy lookup and validation failures."""


class PolicyValidationError(PolicyError):
    """Raised when a policy pack is malformed or internally inconsistent."""


class UnknownPolicyError(PolicyError):
    """Raised when the caller asks for a policy that is not installed."""

    def __init__(self, policy_id: str, available_policy_ids: Iterable[str]) -> None:
        self.policy_id = policy_id
        self.available_policy_ids = tuple(sorted(available_policy_ids))
        available = ", ".join(self.available_policy_ids) or "none"
        super().__init__(f"Unknown policy {policy_id!r}. Available policy IDs: {available}.")


class UnknownPolicyVersionError(UnknownPolicyError):
    """Raised when a policy exists but the requested version is not installed."""

    def __init__(self, policy_id: str, version: str, available_versions: Iterable[str]) -> None:
        self.policy_id = policy_id
        self.available_policy_ids = (policy_id,)
        self.version = version
        self.available_versions = tuple(sorted(available_versions, key=_semantic_version_key))
        available = ", ".join(self.available_versions) or "none"
        PolicyError.__init__(
            self,
            f"Unknown version {version!r} for policy {policy_id!r}. "
            f"Available versions: {available}.",
        )


class PolicyStage(StrEnum):
    """Evaluation point at which a rule or obligation applies."""

    CONTENT = "CONTENT"
    ACTION = "ACTION"
    CALLER = "CALLER"


class PolicySeverity(StrEnum):
    """Policy-author supplied impact, not a model confidence score."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyOutcome(StrEnum):
    """Decision requested when a policy rule is conclusively matched."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """A stable, auditable rule for content or action evaluation."""

    rule_id: str
    stage: PolicyStage
    severity: PolicySeverity
    outcome: PolicyOutcome
    description: str
    classifier_instruction: str | None = None
    patterns: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    obligations: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        """Short public alias used in decision ``matched_rule_ids`` fields."""

        return self.rule_id

    @property
    def caller_obligations(self) -> tuple[str, ...]:
        """Compatibility alias for integrations using the longer name."""

        return self.obligations


@dataclass(frozen=True, slots=True)
class PolicyObligation:
    """Behavior Sentinel requires from the application integrating it."""

    obligation_id: str
    stage: PolicyStage
    description: str
    trigger: str


@dataclass(frozen=True, slots=True)
class ActionConstraints:
    """Deterministic action-policy inputs.

    Tool and destination patterns use :mod:`fnmatch` syntax.  An action engine
    should check deny patterns before review and allow patterns.  An exact
    argument-name match is case-insensitive.  Unknown tools must use
    ``unknown_tool_outcome`` and never inherit permission from another policy.
    """

    allowed_tools: tuple[str, ...]
    denied_tools: tuple[str, ...]
    review_tools: tuple[str, ...]
    confirmation_required_tools: tuple[str, ...]
    allowed_destinations: tuple[str, ...]
    denied_destinations: tuple[str, ...]
    denied_argument_names: tuple[str, ...]
    blocked_data_labels: tuple[str, ...]
    sensitive_labels_requiring_review: tuple[str, ...]
    unknown_tool_outcome: PolicyOutcome = PolicyOutcome.REVIEW
    review_if_irreversible: bool = True
    review_if_untrusted_source: bool = True

    # Pattern-oriented aliases make the matching semantics explicit while the
    # shorter field names keep the public policy contract pleasant to consume.
    @property
    def allowed_tool_patterns(self) -> tuple[str, ...]:
        return self.allowed_tools

    @property
    def denied_tool_patterns(self) -> tuple[str, ...]:
        return self.denied_tools

    @property
    def review_tool_patterns(self) -> tuple[str, ...]:
        return self.review_tools

    @property
    def confirmation_tool_patterns(self) -> tuple[str, ...]:
        return self.confirmation_required_tools

    @property
    def allowed_destination_patterns(self) -> tuple[str, ...]:
        return self.allowed_destinations

    @property
    def denied_destination_patterns(self) -> tuple[str, ...]:
        return self.denied_destinations

    @property
    def review_data_labels(self) -> tuple[str, ...]:
        return self.sensitive_labels_requiring_review


@dataclass(frozen=True, slots=True)
class PolicyPack:
    """A validated immutable policy pack."""

    schema_version: str
    policy_id: str
    version: str
    title: str
    description: str
    illustrative: bool
    disclaimer: str
    classifier_instructions: tuple[str, ...]
    rules: tuple[PolicyRule, ...]
    action_constraints: ActionConstraints
    obligations: tuple[PolicyObligation, ...]

    @property
    def rules_by_id(self) -> Mapping[str, PolicyRule]:
        """Return an immutable rule lookup keyed by stable rule ID."""

        return MappingProxyType({rule.rule_id: rule for rule in self.rules})

    def rules_for_stage(self, stage: PolicyStage | str) -> tuple[PolicyRule, ...]:
        """Return rules for exactly one evaluation stage."""

        normalized_stage = _enum_value(PolicyStage, stage, "stage")
        return tuple(rule for rule in self.rules if rule.stage is normalized_stage)


@dataclass(frozen=True, slots=True)
class PolicySummary:
    """Non-sensitive metadata suitable for discovery interfaces."""

    policy_id: str
    version: str
    title: str
    illustrative: bool


class PolicyRegistry:
    """Load and resolve strict, versioned JSON policy packs.

    The registry eagerly validates every JSON file so deployment errors are
    discovered during initialization rather than during a security decision.
    When no version is supplied, the highest installed semantic version is
    returned.  There is intentionally no fallback policy.
    """

    def __init__(self, pack_dir: str | Path | None = None) -> None:
        self._pack_dir = Path(pack_dir) if pack_dir is not None else _BUILTIN_PACK_DIR
        self._packs = self._load_directory(self._pack_dir)

    @property
    def pack_dir(self) -> Path:
        return self._pack_dir

    def policy_ids(self) -> tuple[str, ...]:
        return tuple(sorted({policy_id for policy_id, _ in self._packs}))

    def versions(self, policy_id: str) -> tuple[str, ...]:
        if policy_id not in self.policy_ids():
            raise UnknownPolicyError(policy_id, self.policy_ids())
        return tuple(
            sorted(
                (version for candidate_id, version in self._packs if candidate_id == policy_id),
                key=_semantic_version_key,
            )
        )

    def list_policies(self) -> tuple[PolicySummary, ...]:
        return tuple(
            PolicySummary(
                policy_id=pack.policy_id,
                version=pack.version,
                title=pack.title,
                illustrative=pack.illustrative,
            )
            for pack in sorted(
                self._packs.values(),
                key=lambda item: (item.policy_id, _semantic_version_key(item.version)),
            )
        )

    def get(self, policy_id: str, version: str | None = None) -> PolicyPack:
        if policy_id not in self.policy_ids():
            raise UnknownPolicyError(policy_id, self.policy_ids())
        resolved_version = version or self.versions(policy_id)[-1]
        try:
            return self._packs[(policy_id, resolved_version)]
        except KeyError as exc:
            raise UnknownPolicyVersionError(
                policy_id, resolved_version, self.versions(policy_id)
            ) from exc

    # ``load`` reads naturally at call sites and keeps compatibility with code
    # written while this subsystem was being designed.
    load = get

    @staticmethod
    def _load_directory(pack_dir: Path) -> dict[tuple[str, str], PolicyPack]:
        if not pack_dir.is_dir():
            raise PolicyValidationError(f"Policy pack directory does not exist: {pack_dir}")

        packs: dict[tuple[str, str], PolicyPack] = {}
        paths = sorted(pack_dir.glob("*.json"))
        if not paths:
            raise PolicyValidationError(f"No JSON policy packs found in {pack_dir}")

        for path in paths:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise PolicyValidationError(f"Unable to read policy pack {path}: {exc}") from exc
            pack = _parse_policy_pack(raw, source=path)
            key = (pack.policy_id, pack.version)
            if key in packs:
                raise PolicyValidationError(
                    f"Duplicate policy pack {pack.policy_id!r} version {pack.version!r}"
                )
            packs[key] = pack
        return packs


@lru_cache(maxsize=1)
def default_policy_registry() -> PolicyRegistry:
    """Return the process-wide registry for bundled policy packs."""

    return PolicyRegistry()


def load_policy_pack(policy_id: str, version: str | None = None) -> PolicyPack:
    """Resolve one bundled policy pack, raising on any unknown identifier."""

    return default_policy_registry().get(policy_id, version)


def _parse_policy_pack(raw: Any, *, source: Path) -> PolicyPack:
    data = _mapping(raw, source, "policy pack")
    _reject_unknown_keys(
        data,
        {
            "schema_version",
            "policy_id",
            "version",
            "title",
            "description",
            "illustrative",
            "disclaimer",
            "classifier_instructions",
            "rules",
            "action_constraints",
            "obligations",
        },
        source,
        "policy pack",
    )

    schema_version = _required_string(data, "schema_version", source)
    if schema_version != POLICY_PACK_SCHEMA_VERSION:
        raise PolicyValidationError(
            f"{source}: unsupported policy schema {schema_version!r}; "
            f"expected {POLICY_PACK_SCHEMA_VERSION!r}"
        )

    policy_id = _required_string(data, "policy_id", source)
    if not _POLICY_ID_PATTERN.fullmatch(policy_id):
        raise PolicyValidationError(f"{source}: invalid policy_id {policy_id!r}")

    version = _required_string(data, "version", source)
    _semantic_version_key(version, source=source)

    illustrative = data.get("illustrative")
    if illustrative is not True:
        raise PolicyValidationError(
            f"{source}: public beta policy packs must declare illustrative=true"
        )

    classifier_instructions = _string_tuple(
        data.get("classifier_instructions"), source, "classifier_instructions"
    )
    if not classifier_instructions:
        raise PolicyValidationError(f"{source}: classifier_instructions must not be empty")

    rules_raw = _sequence(data.get("rules"), source, "rules")
    rules = tuple(_parse_rule(item, source, index) for index, item in enumerate(rules_raw))
    if not rules:
        raise PolicyValidationError(f"{source}: rules must not be empty")
    rule_ids = [rule.rule_id for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise PolicyValidationError(f"{source}: rule IDs must be unique")
    if not any(rule.stage is PolicyStage.CONTENT for rule in rules):
        raise PolicyValidationError(f"{source}: at least one CONTENT rule is required")
    if not any(rule.stage is PolicyStage.ACTION for rule in rules):
        raise PolicyValidationError(f"{source}: at least one ACTION rule is required")

    obligations_raw = _sequence(data.get("obligations"), source, "obligations")
    obligations = tuple(
        _parse_obligation(item, source, index) for index, item in enumerate(obligations_raw)
    )
    obligation_ids = [item.obligation_id for item in obligations]
    if len(obligation_ids) != len(set(obligation_ids)):
        raise PolicyValidationError(f"{source}: obligation IDs must be unique")

    return PolicyPack(
        schema_version=schema_version,
        policy_id=policy_id,
        version=version,
        title=_required_string(data, "title", source),
        description=_required_string(data, "description", source),
        illustrative=illustrative,
        disclaimer=_required_string(data, "disclaimer", source),
        classifier_instructions=classifier_instructions,
        rules=rules,
        action_constraints=_parse_action_constraints(data.get("action_constraints"), source),
        obligations=obligations,
    )


def _parse_rule(raw: Any, source: Path, index: int) -> PolicyRule:
    field = f"rules[{index}]"
    data = _mapping(raw, source, field)
    _reject_unknown_keys(
        data,
        {
            "rule_id",
            "stage",
            "severity",
            "outcome",
            "description",
            "classifier_instruction",
            "patterns",
            "keywords",
            "obligations",
        },
        source,
        field,
    )
    stage = _enum_value(
        PolicyStage, _required_string(data, "stage", source, field), f"{field}.stage"
    )
    if stage is PolicyStage.CALLER:
        raise PolicyValidationError(f"{source}: {field}.stage must be CONTENT or ACTION")
    classifier_instruction = data.get("classifier_instruction")
    if classifier_instruction is not None and not isinstance(classifier_instruction, str):
        raise PolicyValidationError(
            f"{source}: {field}.classifier_instruction must be a string or null"
        )
    if stage is PolicyStage.CONTENT and not classifier_instruction:
        raise PolicyValidationError(
            f"{source}: {field}.classifier_instruction is required for CONTENT rules"
        )
    rule_id = _required_string(data, "rule_id", source, field)
    if not _RULE_ID_PATTERN.fullmatch(rule_id):
        raise PolicyValidationError(f"{source}: {field}.rule_id is invalid: {rule_id!r}")
    patterns = _string_tuple(data.get("patterns", []), source, f"{field}.patterns")
    if stage is PolicyStage.ACTION and not patterns:
        raise PolicyValidationError(f"{source}: {field}.patterns is required for ACTION rules")
    if stage is PolicyStage.CONTENT:
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise PolicyValidationError(
                    f"{source}: {field}.patterns contains invalid regex {pattern!r}: {exc}"
                ) from exc

    return PolicyRule(
        rule_id=rule_id,
        stage=stage,
        severity=_enum_value(
            PolicySeverity,
            _required_string(data, "severity", source, field),
            f"{field}.severity",
        ),
        outcome=_enum_value(
            PolicyOutcome,
            _required_string(data, "outcome", source, field),
            f"{field}.outcome",
        ),
        description=_required_string(data, "description", source, field),
        classifier_instruction=classifier_instruction,
        patterns=patterns,
        keywords=_string_tuple(data.get("keywords", []), source, f"{field}.keywords"),
        obligations=_string_tuple(data.get("obligations", []), source, f"{field}.obligations"),
    )


def _parse_obligation(raw: Any, source: Path, index: int) -> PolicyObligation:
    field = f"obligations[{index}]"
    data = _mapping(raw, source, field)
    _reject_unknown_keys(
        data,
        {"obligation_id", "stage", "description", "trigger"},
        source,
        field,
    )
    return PolicyObligation(
        obligation_id=_required_string(data, "obligation_id", source, field),
        stage=_enum_value(
            PolicyStage,
            _required_string(data, "stage", source, field),
            f"{field}.stage",
        ),
        description=_required_string(data, "description", source, field),
        trigger=_required_string(data, "trigger", source, field),
    )


def _parse_action_constraints(raw: Any, source: Path) -> ActionConstraints:
    field = "action_constraints"
    data = _mapping(raw, source, field)
    keys = {
        "allowed_tools",
        "denied_tools",
        "review_tools",
        "confirmation_required_tools",
        "allowed_destinations",
        "denied_destinations",
        "denied_argument_names",
        "blocked_data_labels",
        "sensitive_labels_requiring_review",
        "unknown_tool_outcome",
        "review_if_irreversible",
        "review_if_untrusted_source",
    }
    _reject_unknown_keys(data, keys, source, field)

    outcome = _enum_value(
        PolicyOutcome,
        _required_string(data, "unknown_tool_outcome", source, field),
        f"{field}.unknown_tool_outcome",
    )
    if outcome is PolicyOutcome.ALLOW:
        raise PolicyValidationError(f"{source}: unknown_tool_outcome must not be ALLOW")

    kwargs: dict[str, Any] = {}
    for name in (
        "allowed_tools",
        "denied_tools",
        "review_tools",
        "confirmation_required_tools",
        "allowed_destinations",
        "denied_destinations",
        "denied_argument_names",
        "blocked_data_labels",
        "sensitive_labels_requiring_review",
    ):
        kwargs[name] = _string_tuple(data.get(name, []), source, f"{field}.{name}")

    if not kwargs["allowed_tools"]:
        raise PolicyValidationError(f"{source}: action_constraints.allowed_tools must not be empty")
    if set(kwargs["blocked_data_labels"]) & set(kwargs["sensitive_labels_requiring_review"]):
        raise PolicyValidationError(
            f"{source}: a data label cannot be both blocked and review-only"
        )
    configured_labels = set(kwargs["blocked_data_labels"]) | set(
        kwargs["sensitive_labels_requiring_review"]
    )
    unsupported_labels = sorted(configured_labels - _SUPPORTED_DATA_LABELS)
    if unsupported_labels:
        raise PolicyValidationError(
            f"{source}: unsupported action data labels: {', '.join(unsupported_labels)}"
        )

    return ActionConstraints(
        **kwargs,
        unknown_tool_outcome=outcome,
        review_if_irreversible=_required_bool(data, "review_if_irreversible", source, field),
        review_if_untrusted_source=_required_bool(
            data, "review_if_untrusted_source", source, field
        ),
    )


def _mapping(raw: Any, source: Path, field: str) -> Mapping[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyValidationError(f"{source}: {field} must be an object")
    return raw


def _sequence(raw: Any, source: Path, field: str) -> Sequence[Any]:
    if not isinstance(raw, list):
        raise PolicyValidationError(f"{source}: {field} must be an array")
    return raw


def _string_tuple(raw: Any, source: Path, field: str) -> tuple[str, ...]:
    values = _sequence(raw, source, field)
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise PolicyValidationError(f"{source}: {field} must contain only non-empty strings")
    if len(values) != len(set(values)):
        raise PolicyValidationError(f"{source}: {field} values must be unique")
    return tuple(values)


def _required_string(
    data: Mapping[str, Any], key: str, source: Path, parent: str = "policy pack"
) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicyValidationError(f"{source}: {parent}.{key} must be a non-empty string")
    return value


def _required_bool(data: Mapping[str, Any], key: str, source: Path, parent: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise PolicyValidationError(f"{source}: {parent}.{key} must be a boolean")
    return value


def _reject_unknown_keys(
    data: Mapping[str, Any],
    allowed: set[str],
    source: Path,
    field: str,
) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyValidationError(
            f"{source}: {field} contains unknown fields: {', '.join(unknown)}"
        )


def _enum_value(enum_type: type[StrEnum], raw: Any, field: str) -> Any:
    if isinstance(raw, enum_type):
        return raw
    try:
        return enum_type(raw)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise PolicyValidationError(f"{field} must be one of: {allowed}; received {raw!r}") from exc


def _semantic_version_key(version: str, *, source: Path | None = None) -> tuple[int, int, int]:
    match = _VERSION_PATTERN.fullmatch(version)
    if match is None:
        prefix = f"{source}: " if source is not None else ""
        raise PolicyValidationError(f"{prefix}version {version!r} must use MAJOR.MINOR.PATCH")
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )


__all__ = [
    "POLICY_PACK_SCHEMA_VERSION",
    "ActionConstraints",
    "PolicyError",
    "PolicyObligation",
    "PolicyOutcome",
    "PolicyPack",
    "PolicyRegistry",
    "PolicyRule",
    "PolicySeverity",
    "PolicyStage",
    "PolicySummary",
    "PolicyValidationError",
    "UnknownPolicyError",
    "UnknownPolicyVersionError",
    "default_policy_registry",
    "load_policy_pack",
]
