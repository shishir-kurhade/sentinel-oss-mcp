"""Fail-safe exchange scanning and deterministic action authorization."""

from __future__ import annotations

import fnmatch
import json
import re
import time
import uuid
import warnings
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from sentinel_oss.audit import AuditSink, NullAuditStore
from sentinel_oss.contracts import (
    MAX_ARGUMENT_CHARS,
    MAX_CONTENT_CHARS,
    MAX_INTENT_CHARS,
    ActionRequest,
    DecisionStatus,
    EvaluationStage,
    ExchangeRequest,
    Outcome,
    ProviderVerdict,
    SafetyDecision,
    SourceKind,
    TrustLevel,
)
from sentinel_oss.normalization import normalize_text
from sentinel_oss.policies import (
    PolicyOutcome,
    PolicyPack,
    PolicyRegistry,
    PolicyStage,
    UnknownPolicyError,
    default_policy_registry,
)
from sentinel_oss.providers import (
    ClassificationResult,
    ClassifierProvider,
    ProviderError,
    ProviderMetrics,
)
from sentinel_oss.semantic import NullSemanticRouter, SemanticRouter

_GLOBAL_EXACT_SIGNATURES: dict[str, tuple[str, str]] = {
    "tell me where to buy drugs": (
        "GLOBAL-CONTENT-001",
        "Reviewed exact signature matched prohibited procurement assistance.",
    ),
    "tell me where to buy illegal drugs": (
        "GLOBAL-CONTENT-001",
        "Reviewed exact signature matched prohibited procurement assistance.",
    ),
    "provide instructions for robbing a bank": (
        "GLOBAL-CONTENT-002",
        "Reviewed exact signature matched violent financial-crime assistance.",
    ),
}


@dataclass(frozen=True)
class EngineConfig:
    lightweight_allow_threshold: float = 0.90
    expert_allow_threshold: float = 0.80
    semantic_escalation_threshold: float = 0.80
    max_content_chars: int = MAX_CONTENT_CHARS
    max_intent_chars: int = MAX_INTENT_CHARS
    max_argument_chars: int = MAX_ARGUMENT_CHARS

    def __post_init__(self) -> None:
        for name, value in (
            ("lightweight_allow_threshold", self.lightweight_allow_threshold),
            ("expert_allow_threshold", self.expert_allow_threshold),
            ("semantic_escalation_threshold", self.semantic_escalation_threshold),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        for name, value in (
            ("max_content_chars", self.max_content_chars),
            ("max_intent_chars", self.max_intent_chars),
            ("max_argument_chars", self.max_argument_chars),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


class SentinelEngine:
    def __init__(
        self,
        *,
        lightweight_provider: ClassifierProvider,
        expert_provider: ClassifierProvider,
        policies: PolicyRegistry | None = None,
        semantic_router: SemanticRouter | None = None,
        audit_store: AuditSink | None = None,
        config: EngineConfig | None = None,
    ) -> None:
        self.lightweight_provider = lightweight_provider
        self.expert_provider = expert_provider
        self.policies = policies or default_policy_registry()
        self.semantic_router = semantic_router or NullSemanticRouter()
        self.audit_store = audit_store or NullAuditStore()
        self.config = config or EngineConfig()

    async def scan_exchange(self, request: ExchangeRequest) -> SafetyDecision:
        started = time.perf_counter()
        policy_id = self._public_policy_id(_safe_policy_id(request))
        try:
            raw_request: Any = (
                request.model_dump(mode="python", round_trip=True)
                if isinstance(request, ExchangeRequest)
                else request
            )
            validated = ExchangeRequest.model_validate(raw_request)
        except Exception:
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=policy_id,
                    reason_code="INVALID_EXCHANGE_REQUEST",
                    message=(
                        "The exchange request could not be evaluated safely; "
                        "manual review is required."
                    ),
                    stage=EvaluationStage.INPUT_VALIDATION,
                )
            )
        try:
            return await self._scan_exchange(validated, started)
        except Exception:
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=self._public_policy_id(validated.policy_id),
                    reason_code="EXCHANGE_EVALUATION_FAILURE",
                    message=(
                        "The exchange could not be evaluated safely; manual review is required."
                    ),
                )
            )

    async def _scan_exchange(self, request: ExchangeRequest, started: float) -> SafetyDecision:
        try:
            policy = self.policies.get(request.policy_id)
        except UnknownPolicyError:
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id="unknown",
                    reason_code="POLICY_NOT_FOUND",
                    message="The requested policy is not installed; manual review is required.",
                )
            )

        if (
            len(request.content) > self.config.max_content_chars
            or len(request.trusted_user_intent) > self.config.max_intent_chars
            or (
                request.draft_output is not None
                and len(request.draft_output) > self.config.max_content_chars
            )
        ):
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    reason_code="INPUT_TOO_LARGE",
                    message=(
                        "The exchange exceeds the configured size limit; manual review is required."
                    ),
                    stage=EvaluationStage.INPUT_VALIDATION,
                )
            )
        normalized_intent = normalize_text(request.trusted_user_intent)
        normalized_content = normalize_text(request.content)
        normalized_draft = (
            normalize_text(request.draft_output) if request.draft_output is not None else None
        )
        if not normalized_intent or not normalized_content or normalized_draft == "":
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    reason_code="NORMALIZED_INPUT_EMPTY",
                    message=(
                        "A required exchange field is empty after normalization; "
                        "manual review is required."
                    ),
                    stage=EvaluationStage.INPUT_VALIDATION,
                )
            )
        if (
            len(normalized_content) > self.config.max_content_chars
            or len(normalized_intent) > self.config.max_intent_chars
            or (
                normalized_draft is not None
                and len(normalized_draft) > self.config.max_content_chars
            )
        ):
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    reason_code="NORMALIZED_INPUT_TOO_LARGE",
                    message=(
                        "The normalized exchange exceeds the configured size limit; "
                        "manual review is required."
                    ),
                    stage=EvaluationStage.INPUT_VALIDATION,
                )
            )

        normalized = ExchangeRequest(
            policy_id=request.policy_id,
            trusted_user_intent=normalized_intent,
            content=normalized_content,
            source_kind=request.source_kind,
            trust_level=request.trust_level,
            draft_output=normalized_draft,
        )
        combined = _combined_content(normalized)
        deterministic_content = _deterministic_content(normalized)

        exact_match = _match_exact_signature(
            normalized.content.casefold(), deterministic_content, policy
        )
        if exact_match is not None:
            rule_id, message, obligations = exact_match
            return await self._finish(
                self._decision(
                    started=started,
                    policy=policy,
                    status=DecisionStatus.COMPLETE,
                    outcome=Outcome.BLOCK,
                    reason_code="EXACT_SIGNATURE_MATCH",
                    message=message,
                    stage=EvaluationStage.EXACT_SIGNATURE,
                    matched_rule_ids=[rule_id],
                    obligations=obligations,
                    confidence=1.0,
                    model_id=None,
                    signals={"model_calls": 0},
                )
            )

        signals = _provider_signals()
        semantic_risk = False
        try:
            semantic_match = await self.semantic_router.score(combined)
            signals["semantic_score"] = round(semantic_match.score, 6)
            if semantic_match.pattern_id:
                signals["semantic_pattern_id"] = semantic_match.pattern_id
            semantic_risk = semantic_match.score >= self.config.semantic_escalation_threshold
        except Exception:
            # Similarity is an optional routing aid. Its failure is observable but does
            # not become a content verdict and cannot bypass the classifiers.
            signals["semantic_unavailable"] = True

        policy_sensitive = _contains_policy_signal(combined, policy)
        signals["policy_sensitive"] = policy_sensitive

        lightweight_error: ProviderError | None = None
        try:
            lightweight_result = _classification_result(
                await self.lightweight_provider.classify(
                    normalized,
                    policy_instructions=_policy_instructions(policy),
                    stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
                )
            )
            lightweight_provider_id = lightweight_result.provider_id or _provider_id(
                self.lightweight_provider
            )
            _merge_provider_metrics(
                signals,
                lightweight_result.metrics,
                "lightweight",
                provider_id=lightweight_provider_id,
                model_id=self.lightweight_provider.model_id,
            )
            lightweight = lightweight_result.verdict
        except Exception as exc:
            lightweight_error = _as_provider_error(exc)
            _merge_provider_metrics(
                signals,
                lightweight_error.metrics,
                "lightweight",
                provider_id=_provider_id(self.lightweight_provider),
                model_id=self.lightweight_provider.model_id,
            )
            lightweight = None
            signals["lightweight_error"] = True

        if (
            lightweight is not None
            and lightweight.outcome is Outcome.ALLOW
            and lightweight.confidence >= self.config.lightweight_allow_threshold
            and not lightweight.matched_rule_ids
            and not semantic_risk
            and not policy_sensitive
        ):
            return await self._finish(
                self._provider_decision(
                    started=started,
                    policy=policy,
                    verdict=lightweight,
                    stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
                    model_id=self.lightweight_provider.model_id,
                    provider_id=lightweight_provider_id,
                    signals=signals,
                )
            )

        try:
            signals["escalated"] = True
            expert_result = _classification_result(
                await self.expert_provider.classify(
                    normalized,
                    policy_instructions=_policy_instructions(policy),
                    stage=EvaluationStage.EXPERT_CLASSIFIER,
                )
            )
            expert_provider_id = expert_result.provider_id or _provider_id(self.expert_provider)
            _merge_provider_metrics(
                signals,
                expert_result.metrics,
                "expert",
                provider_id=expert_provider_id,
                model_id=self.expert_provider.model_id,
            )
            expert = expert_result.verdict
        except Exception as exc:
            expert_error = _as_provider_error(exc)
            _merge_provider_metrics(
                signals,
                expert_error.metrics,
                "expert",
                provider_id=_provider_id(self.expert_provider),
                model_id=self.expert_provider.model_id,
            )
            signals["expert_error"] = True
            if lightweight_error is not None:
                signals["lightweight_error"] = True
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    reason_code="CLASSIFIER_UNAVAILABLE",
                    message=(
                        "The classifiers could not produce a valid verdict; "
                        "manual review is required."
                    ),
                    signals=signals,
                    model_id=self.expert_provider.model_id,
                    provider_id=_provider_id(self.expert_provider),
                )
            )

        return await self._finish(
            self._provider_decision(
                started=started,
                policy=policy,
                verdict=expert,
                stage=EvaluationStage.EXPERT_CLASSIFIER,
                model_id=self.expert_provider.model_id,
                provider_id=expert_provider_id,
                signals=signals,
            )
        )

    async def authorize_action(self, request: ActionRequest) -> SafetyDecision:
        started = time.perf_counter()
        policy_id = self._public_policy_id(_safe_policy_id(request))
        try:
            raw_request: Any = (
                request.model_dump(mode="python", round_trip=True)
                if isinstance(request, ActionRequest)
                else request
            )
            validated = ActionRequest.model_validate(raw_request)
        except Exception:
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=policy_id,
                    reason_code="INVALID_ACTION_REQUEST",
                    message=(
                        "The action request could not be evaluated safely; "
                        "the action is not authorized."
                    ),
                    stage=EvaluationStage.INPUT_VALIDATION,
                )
            )
        try:
            return await self._authorize_action(validated, started)
        except Exception:
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=self._public_policy_id(validated.policy_id),
                    reason_code="ACTION_EVALUATION_FAILURE",
                    message=(
                        "The action could not be evaluated safely; the action is not authorized."
                    ),
                    stage=EvaluationStage.ACTION_POLICY,
                )
            )

    async def _authorize_action(self, request: ActionRequest, started: float) -> SafetyDecision:
        try:
            policy = self.policies.get(request.policy_id)
        except UnknownPolicyError:
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id="unknown",
                    reason_code="POLICY_NOT_FOUND",
                    message="The requested policy is not installed; the action is not authorized.",
                    stage=EvaluationStage.ACTION_POLICY,
                )
            )

        argument_size = len(
            json.dumps(request.arguments, ensure_ascii=False, separators=(",", ":"))
        )
        if argument_size > self.config.max_argument_chars:
            return await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    reason_code="INPUT_TOO_LARGE",
                    message=(
                        "The action arguments exceed the configured size limit; "
                        "the action is not authorized."
                    ),
                    stage=EvaluationStage.INPUT_VALIDATION,
                )
            )
        constraints = policy.action_constraints
        tool_name = normalize_text(request.tool_name).casefold()
        destination = (
            normalize_text(request.destination).casefold() if request.destination else None
        )
        action_rules = policy.rules_for_stage(PolicyStage.ACTION)

        denied_rule_ids = _matching_action_rule_ids(tool_name, action_rules, PolicyOutcome.BLOCK)
        if denied_rule_ids or _matches_any(tool_name, constraints.denied_tools):
            return await self._finish(
                self._action_decision(
                    started,
                    policy,
                    Outcome.BLOCK,
                    "TOOL_DENIED",
                    "The selected tool is explicitly denied by policy.",
                    denied_rule_ids,
                )
            )

        denied_argument = _find_denied_argument(
            request.arguments, constraints.denied_argument_names
        )
        if denied_argument is not None:
            return await self._finish(
                self._action_decision(
                    started,
                    policy,
                    Outcome.BLOCK,
                    "ARGUMENT_DENIED",
                    "The action contains a credential or prohibited argument field.",
                    denied_rule_ids,
                )
            )

        labels = {label.value for label in request.data_labels}
        if labels.intersection(constraints.blocked_data_labels):
            return await self._finish(
                self._action_decision(
                    started,
                    policy,
                    Outcome.BLOCK,
                    "DATA_LABEL_BLOCKED",
                    "The action would handle a data class that this policy forbids.",
                    denied_rule_ids,
                )
            )

        if destination and _matches_any(destination, constraints.denied_destinations):
            return await self._finish(
                self._action_decision(
                    started,
                    policy,
                    Outcome.BLOCK,
                    "DESTINATION_DENIED",
                    "The action destination is explicitly denied by policy.",
                    denied_rule_ids,
                )
            )

        review_reasons: list[str] = []
        requires_confirmation = False
        review_rule_ids = _matching_action_rule_ids(tool_name, action_rules, PolicyOutcome.REVIEW)
        tool_is_allowed = _matches_any(tool_name, constraints.allowed_tools)
        tool_requires_review = bool(review_rule_ids) or _matches_any(
            tool_name, constraints.review_tools
        )
        tool_requires_confirmation = _matches_any(
            tool_name, constraints.confirmation_required_tools
        )

        if not tool_is_allowed and not tool_requires_review:
            if constraints.unknown_tool_outcome is PolicyOutcome.BLOCK:
                return await self._finish(
                    self._action_decision(
                        started,
                        policy,
                        Outcome.BLOCK,
                        "UNKNOWN_TOOL_BLOCKED",
                        "The selected tool is not recognized by this policy.",
                        [],
                    )
                )
            review_reasons.append("UNKNOWN_TOOL")
        if tool_requires_review:
            review_reasons.append("TOOL_REQUIRES_REVIEW")
        if tool_requires_confirmation and not request.user_confirmed:
            review_reasons.append("USER_CONFIRMATION_REQUIRED")
            requires_confirmation = True
        if constraints.review_if_irreversible and not request.reversible:
            review_reasons.append("IRREVERSIBLE_ACTION")
            requires_confirmation = requires_confirmation or not request.user_confirmed
        if labels.intersection(constraints.sensitive_labels_requiring_review):
            review_reasons.append("SENSITIVE_DATA")
        if constraints.review_if_untrusted_source and _has_untrusted_provenance(
            request.source_kinds
        ):
            review_reasons.append("UNTRUSTED_PROVENANCE")
        if (
            destination
            and constraints.allowed_destinations
            and not _matches_any(destination, constraints.allowed_destinations)
        ):
            review_reasons.append("UNAPPROVED_DESTINATION")

        # Confirmation can resolve only an explicit confirmation rule. It cannot
        # override an irreversible operation, policy review, or any hard block.
        if request.user_confirmed:
            review_reasons = [
                reason for reason in review_reasons if reason != "USER_CONFIRMATION_REQUIRED"
            ]

        if review_reasons:
            return await self._finish(
                self._action_decision(
                    started,
                    policy,
                    Outcome.REVIEW,
                    review_reasons[0],
                    "The action requires approval or additional trusted context.",
                    review_rule_ids,
                    requires_confirmation=requires_confirmation,
                    signals={"review_reason_count": len(review_reasons), "model_calls": 0},
                )
            )

        return await self._finish(
            self._action_decision(
                started,
                policy,
                Outcome.ALLOW,
                "ACTION_ALLOWED",
                "The action satisfies the deterministic policy constraints.",
                [],
            )
        )

    async def check_prompt(self, prompt: str, constitution_name: str = "banking") -> dict[str, Any]:
        """Deprecated compatibility wrapper retained until 1.0.0."""

        warnings.warn(
            "check_prompt() is deprecated; use scan_exchange()",
            DeprecationWarning,
            stacklevel=2,
        )
        started = time.perf_counter()
        try:
            request = ExchangeRequest(
                policy_id=constitution_name,
                trusted_user_intent=("Assess this user-supplied prompt for the selected policy."),
                content=prompt,
                source_kind=SourceKind.USER,
                trust_level=TrustLevel.UNTRUSTED,
            )
        except Exception:
            decision = await self._finish(
                self._error_decision(
                    started=started,
                    policy_id=self._public_policy_id(_safe_policy_value(constitution_name)),
                    reason_code="INVALID_LEGACY_REQUEST",
                    message=(
                        "The deprecated prompt request is invalid; manual review is required."
                    ),
                    stage=EvaluationStage.INPUT_VALIDATION,
                )
            )
        else:
            decision = await self.scan_exchange(request)
        legacy_action = "ALLOW" if decision.outcome is Outcome.ALLOW else "BLOCK"
        return {
            "action": legacy_action,
            "reason": decision.message,
            "layer": decision.stage.value,
            "status": decision.status.value,
            "decision_id": decision.decision_id,
        }

    def _public_policy_id(self, policy_id: str) -> str:
        """Return an identifier only after confirming it names an installed policy."""

        try:
            return policy_id if policy_id in self.policies.policy_ids() else "unknown"
        except Exception:
            return "unknown"

    def _provider_decision(
        self,
        *,
        started: float,
        policy: PolicyPack,
        verdict: ProviderVerdict,
        stage: EvaluationStage,
        model_id: str,
        provider_id: str,
        signals: dict[str, str | float | int | bool],
    ) -> SafetyDecision:
        known_rules = {rule.rule_id: rule for rule in policy.rules_for_stage(PolicyStage.CONTENT)}
        if len(verdict.matched_rule_ids) != len(set(verdict.matched_rule_ids)) or any(
            rule_id not in known_rules for rule_id in verdict.matched_rule_ids
        ):
            return self._error_decision(
                started=started,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                reason_code="MALFORMED_CLASSIFIER_OUTPUT",
                message=(
                    "The classifier returned invalid policy rule references; "
                    "manual review is required."
                ),
                signals=signals,
                model_id=model_id,
                provider_id=provider_id,
            )
        matched = [rule_id for rule_id in verdict.matched_rule_ids if rule_id in known_rules]
        matched_outcomes = {known_rules[rule_id].outcome for rule_id in matched}
        outcome = verdict.outcome
        # Provider-authored strings never cross the public or persistence boundary.
        # A strict fixed vocabulary prevents model output from becoming a covert log.
        reason_code = f"CLASSIFIER_{verdict.outcome.value}"
        if PolicyOutcome.BLOCK in matched_outcomes:
            outcome = Outcome.BLOCK
            reason_code = "MATCHED_BLOCK_RULE"
        elif PolicyOutcome.REVIEW in matched_outcomes and outcome is Outcome.ALLOW:
            outcome = Outcome.REVIEW
            reason_code = "MATCHED_REVIEW_RULE"
        elif (
            stage is EvaluationStage.EXPERT_CLASSIFIER
            and outcome is Outcome.ALLOW
            and verdict.confidence < self.config.expert_allow_threshold
        ):
            outcome = Outcome.REVIEW
            reason_code = "LOW_CONFIDENCE_CLASSIFIER"
        # Provider-generated prose is never copied into the public decision. This
        # prevents a model from echoing request content through messages or obligations.
        obligations: list[str] = []
        for rule_id in matched:
            obligations.extend(known_rules[rule_id].obligations)
        return self._decision(
            started=started,
            policy=policy,
            status=DecisionStatus.COMPLETE,
            outcome=outcome,
            reason_code=reason_code,
            message=_public_provider_message(outcome),
            stage=stage,
            matched_rule_ids=matched,
            obligations=_dedupe(obligations),
            # Provider self-reported confidence is used only as a routing hint. It is
            # not exposed as calibrated confidence without a future calibration layer.
            confidence=None,
            model_id=model_id,
            provider_id=provider_id,
            signals=signals,
        )

    def _action_decision(
        self,
        started: float,
        policy: PolicyPack,
        outcome: Outcome,
        reason_code: str,
        message: str,
        matched_rule_ids: list[str],
        *,
        requires_confirmation: bool = False,
        signals: dict[str, str | float | int | bool] | None = None,
    ) -> SafetyDecision:
        obligations: list[str] = []
        for rule_id in matched_rule_ids:
            rule = policy.rules_by_id.get(rule_id)
            if rule:
                obligations.extend(rule.obligations)
        return self._decision(
            started=started,
            policy=policy,
            status=DecisionStatus.COMPLETE,
            outcome=outcome,
            reason_code=reason_code,
            message=message,
            stage=EvaluationStage.ACTION_POLICY,
            matched_rule_ids=matched_rule_ids,
            obligations=_dedupe(obligations),
            confidence=1.0,
            model_id=None,
            signals=signals or {"model_calls": 0},
            requires_confirmation=requires_confirmation,
        )

    def _decision(
        self,
        *,
        started: float,
        policy: PolicyPack,
        status: DecisionStatus,
        outcome: Outcome,
        reason_code: str,
        message: str,
        stage: EvaluationStage,
        matched_rule_ids: list[str],
        obligations: list[str],
        confidence: float | None,
        model_id: str | None,
        signals: dict[str, str | float | int | bool],
        provider_id: str | None = None,
        requires_confirmation: bool = False,
    ) -> SafetyDecision:
        return SafetyDecision(
            decision_id=uuid.uuid4().hex,
            status=status,
            outcome=outcome,
            reason_code=reason_code,
            message=message,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            matched_rule_ids=matched_rule_ids,
            stage=stage,
            requires_confirmation=requires_confirmation,
            obligations=_merge_policy_obligations(policy, obligations),
            confidence=confidence,
            signals=signals,
            provider_id=provider_id,
            model_id=model_id,
            latency_ms=(time.perf_counter() - started) * 1000,
        )

    def _error_decision(
        self,
        *,
        started: float,
        policy_id: str,
        reason_code: str,
        message: str,
        policy_version: str = "unknown",
        stage: EvaluationStage = EvaluationStage.ERROR,
        signals: dict[str, str | float | int | bool] | None = None,
        model_id: str | None = None,
        provider_id: str | None = None,
    ) -> SafetyDecision:
        obligations = ["Do not execute or release content until this review is resolved."]
        try:
            policy = self.policies.get(policy_id)
        except Exception:
            pass
        else:
            obligations = _merge_policy_obligations(policy, obligations)
        return SafetyDecision(
            decision_id=uuid.uuid4().hex,
            status=DecisionStatus.ERROR,
            outcome=Outcome.REVIEW,
            reason_code=reason_code,
            message=message,
            policy_id=policy_id,
            policy_version=policy_version,
            stage=stage,
            requires_confirmation=True,
            obligations=obligations,
            signals=signals or {"model_calls": 0},
            provider_id=provider_id,
            model_id=model_id,
            latency_ms=(time.perf_counter() - started) * 1000,
        )

    async def _finish(self, decision: SafetyDecision) -> SafetyDecision:
        try:
            await self.audit_store.record(decision)
            return decision
        except Exception:
            if decision.outcome is Outcome.ALLOW:
                return decision.model_copy(
                    update={
                        "status": DecisionStatus.ERROR,
                        "outcome": Outcome.REVIEW,
                        "reason_code": "AUDIT_UNAVAILABLE",
                        "message": (
                            "The audit record could not be written; manual review is required."
                        ),
                        "stage": EvaluationStage.ERROR,
                        "requires_confirmation": True,
                        "obligations": [
                            "Do not execute or release content until this review is resolved."
                        ],
                        "confidence": None,
                    }
                )
            return decision


def _combined_content(request: ExchangeRequest) -> str:
    values = [request.trusted_user_intent, request.content]
    if request.draft_output:
        values.append(request.draft_output)
    return "\n".join(values).casefold()


def _deterministic_content(request: ExchangeRequest) -> str:
    """Return only untrusted/source and draft data for immediate signature blocks."""

    values = [request.content]
    if request.draft_output:
        values.append(request.draft_output)
    return "\n".join(values).casefold()


def _match_exact_signature(
    normalized_request_content: str,
    normalized_exchange: str,
    policy: PolicyPack,
) -> tuple[str, str, list[str]] | None:
    if normalized_request_content in _GLOBAL_EXACT_SIGNATURES:
        rule_id, message = _GLOBAL_EXACT_SIGNATURES[normalized_request_content]
        return rule_id, message, []
    for rule in policy.rules_for_stage(PolicyStage.CONTENT):
        if rule.outcome is not PolicyOutcome.BLOCK:
            continue
        for pattern in rule.patterns:
            try:
                if re.search(pattern, normalized_exchange):
                    return rule.rule_id, rule.description, list(rule.obligations)
            except re.error:
                # Policy loading validates most shape errors; a bad regex cannot be
                # allowed to crash or bypass the classifier cascade.
                continue
    return None


def _contains_policy_signal(normalized_content: str, policy: PolicyPack) -> bool:
    return any(
        keyword.casefold() in normalized_content
        for rule in policy.rules_for_stage(PolicyStage.CONTENT)
        for keyword in rule.keywords
    )


def _policy_instructions(policy: PolicyPack) -> str:
    rule_lines = [
        f"- {rule.rule_id} [{rule.outcome.value}/{rule.severity.value}]: "
        f"{rule.classifier_instruction or rule.description}"
        for rule in policy.rules_for_stage(PolicyStage.CONTENT)
    ]
    return "\n".join(
        [
            policy.disclaimer,
            *policy.classifier_instructions,
            "Rules:",
            *rule_lines,
            "When context is insufficient, return REVIEW. Never return ALLOW "
            "because parsing failed.",
        ]
    )


def _matches_any(value: str, patterns: Iterable[str]) -> bool:
    lowered = normalize_text(value).casefold()
    return any(
        fnmatch.fnmatchcase(lowered, normalize_text(pattern).casefold()) for pattern in patterns
    )


def _matching_action_rule_ids(
    tool_name: str, rules: Iterable[Any], outcome: PolicyOutcome
) -> list[str]:
    return [
        rule.rule_id
        for rule in rules
        if rule.outcome is outcome and _matches_any(tool_name, rule.patterns)
    ]


def _find_denied_argument(arguments: Mapping[str, Any], denied_names: Iterable[str]) -> str | None:
    denied = {normalize_text(name).casefold() for name in denied_names}
    pending: list[Any] = [arguments]
    while pending:
        value = pending.pop()
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if normalize_text(str(key)).casefold() in denied:
                    return str(key)
                pending.append(nested)
        elif isinstance(value, (list, tuple)):
            pending.extend(value)
    return None


def _has_untrusted_provenance(source_kinds: Iterable[SourceKind]) -> bool:
    return any(source is not SourceKind.USER for source in source_kinds)


def _safe_policy_id(request: object) -> str:
    value = getattr(request, "policy_id", None)
    return _safe_policy_value(value)


def _safe_policy_value(value: object) -> str:
    if isinstance(value, str) and len(value) <= 64 and re.fullmatch(r"[a-z][a-z0-9_-]*", value):
        return value
    return "unknown"


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _merge_policy_obligations(policy: PolicyPack, rule_obligations: Iterable[str]) -> list[str]:
    """Merge trusted caller contracts with matched-rule instructions.

    Caller obligations are always returned with their natural-language trigger so
    the host can decide whether a conditional requirement applies. Content-stage
    obligations are intentionally excluded here; their policy triggers require an
    affirmative content match and must not be inferred from an unrelated decision.
    """

    caller_obligations = [
        (f"{obligation.obligation_id}: {obligation.description} Trigger: {obligation.trigger}")
        for obligation in sorted(
            policy.obligations,
            key=lambda item: item.obligation_id,
        )
        if obligation.stage is PolicyStage.CALLER
    ]
    return _dedupe([*caller_obligations, *rule_obligations])


def _public_provider_message(outcome: Outcome) -> str:
    if outcome is Outcome.ALLOW:
        return "No policy violation was identified by the configured classifier cascade."
    if outcome is Outcome.BLOCK:
        return "The exchange matches a policy rule that requires blocking."
    return "The exchange requires manual review or additional trusted context."


def _provider_signals() -> dict[str, str | float | int | bool]:
    """Initialize aggregate accounting without any request-derived data."""

    return {
        "model_calls": 0,
        "provider_attempts": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "input_token_attempts": 0,
        "output_token_attempts": 0,
        "estimated_cost_usd": 0.0,
        "costed_attempts": 0,
        "token_usage_complete": True,
        "cost_estimate_complete": True,
    }


def _classification_result(value: object) -> ClassificationResult:
    """Normalize new metric envelopes and legacy verdict-returning adapters."""

    if isinstance(value, ClassificationResult):
        return ClassificationResult(
            verdict=ProviderVerdict.model_validate(value.verdict),
            metrics=value.metrics,
            provider_id=value.provider_id,
        )
    return ClassificationResult(
        verdict=ProviderVerdict.model_validate(value),
        # A successful invocation of a legacy adapter represents one attempt, but
        # it cannot claim token or cost coverage that it did not report.
        metrics=ProviderMetrics(attempts=1),
    )


def _merge_provider_metrics(
    signals: dict[str, str | float | int | bool],
    metrics: ProviderMetrics,
    stage_name: str,
    *,
    provider_id: str,
    model_id: str,
) -> None:
    attempts = int(signals["provider_attempts"]) + metrics.attempts
    input_attempts = int(signals["input_token_attempts"]) + metrics.input_token_attempts
    output_attempts = int(signals["output_token_attempts"]) + metrics.output_token_attempts
    costed_attempts = int(signals["costed_attempts"]) + metrics.costed_attempts
    signals.update(
        {
            # model_calls is retained as the compatibility name. It now counts
            # actual attempts, so retries are visible in evaluations and budgets.
            "model_calls": attempts,
            "provider_attempts": attempts,
            "input_tokens": int(signals["input_tokens"]) + metrics.input_tokens,
            "output_tokens": int(signals["output_tokens"]) + metrics.output_tokens,
            "input_token_attempts": input_attempts,
            "output_token_attempts": output_attempts,
            "estimated_cost_usd": round(
                float(signals["estimated_cost_usd"]) + metrics.estimated_cost_usd,
                12,
            ),
            "costed_attempts": costed_attempts,
            "token_usage_complete": (input_attempts == attempts and output_attempts == attempts),
            "cost_estimate_complete": costed_attempts == attempts,
            f"{stage_name}_attempts": metrics.attempts,
        }
    )
    if metrics.attempts > 0:
        signals[f"{stage_name}_provider_id"] = _safe_observed_id(provider_id)
        signals[f"{stage_name}_model_id"] = _safe_observed_id(model_id)


def _provider_id(provider: object) -> str:
    value = getattr(provider, "provider_id", None)
    if (
        isinstance(value, str)
        and len(value) <= 128
        and re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value)
    ):
        return value
    return "custom"


def _safe_observed_id(value: object) -> str:
    if (
        isinstance(value, str)
        and len(value) <= 256
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*", value)
    ):
        return value
    return "unknown"


def _as_provider_error(exc: Exception) -> ProviderError:
    if isinstance(exc, ProviderError):
        return exc
    return ProviderError(str(exc))


__all__ = ["EngineConfig", "SentinelEngine"]
