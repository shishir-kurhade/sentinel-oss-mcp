from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sentinel_oss import __version__
from sentinel_oss.audit import NullAuditStore
from sentinel_oss.contracts import (
    ActionRequest,
    ExchangeRequest,
    Outcome,
    ProviderVerdict,
    SafetyDecision,
)
from sentinel_oss.engine import SentinelEngine
from sentinel_oss.evaluation import (
    REPORT_SCHEMA_VERSION,
    DatasetValidationError,
    EvaluationPrediction,
    default_benchmark_dir,
    evaluate_predictions,
    load_benchmark,
    load_dataset,
    run_evaluation,
)
from sentinel_oss.providers import ScriptedClassifier, UnavailableClassifier

EVALS = default_benchmark_dir()


def test_release_benchmark_has_exact_promised_composition() -> None:
    benchmark = load_benchmark()

    assert len(benchmark.content) == 300
    assert len(benchmark.actions) == 100
    assert len({case.id for case in benchmark.cases}) == 400
    assert all(isinstance(case.request, ExchangeRequest) for case in benchmark.content)
    assert all(isinstance(case.request, ActionRequest) for case in benchmark.actions)

    domain = [case for case in benchmark.content if "domain_boundary" in case.tags]
    assert Counter("harmful" if "harmful" in case.tags else "benign" for case in domain) == {
        "harmful": 75,
        "benign": 75,
    }
    assert Counter(case.expected_outcome for case in domain) == {
        Outcome.ALLOW: 75,
        Outcome.BLOCK: 50,
        Outcome.REVIEW: 25,
    }
    assert all(
        sum(case.policy_id == policy and label in case.tags for case in domain) == 15
        for policy in {"banking", "healthcare", "telecom", "retail", "hr_it"}
        for label in {"harmful", "benign"}
    )
    adversarial = [case for case in benchmark.content if "adversarial" in case.tags]
    assert len(adversarial) == 100
    assert {case.expected_outcome for case in adversarial} == {Outcome.BLOCK}
    assert Counter(
        tag
        for case in adversarial
        for tag in case.tags
        if tag
        in {
            "direct",
            "indirect",
            "unicode",
            "roleplay",
            "obfuscation",
            "multilingual",
            "reconstruction",
            "cache_evasion",
        }
    ) == {
        "direct": 13,
        "indirect": 13,
        "unicode": 13,
        "roleplay": 13,
        "obfuscation": 12,
        "multilingual": 12,
        "reconstruction": 12,
        "cache_evasion": 12,
    }
    hard_benign = [case for case in benchmark.content if "hard_benign" in case.tags]
    assert len(hard_benign) == 50
    assert {case.expected_outcome for case in hard_benign} == {Outcome.ALLOW}
    assert Counter(case.expected_outcome for case in benchmark.actions) == {
        Outcome.ALLOW: 30,
        Outcome.REVIEW: 35,
        Outcome.BLOCK: 35,
    }
    assert (
        benchmark.content_sha256
        == hashlib.sha256((EVALS / "content.jsonl").read_bytes()).hexdigest()
    )
    assert (
        benchmark.actions_sha256
        == hashlib.sha256((EVALS / "actions.jsonl").read_bytes()).hexdigest()
    )


def test_dataset_loader_rejects_duplicate_ids(tmp_path: Path) -> None:
    first_row = next(line for line in (EVALS / "content.jsonl").read_text().splitlines() if line)
    duplicate_path = tmp_path / "duplicate.jsonl"
    duplicate_path.write_text(f"{first_row}\n{first_row}\n", encoding="utf-8")

    with pytest.raises(DatasetValidationError, match="duplicate case id"):
        load_dataset(duplicate_path, expected_request_type="exchange")


def test_dataset_loader_reports_line_for_contract_error(tmp_path: Path) -> None:
    row = json.loads(
        next(line for line in (EVALS / "content.jsonl").read_text().splitlines() if line)
    )
    row["request"]["source_kind"] = "NOT_A_SOURCE"
    invalid_path = tmp_path / "invalid.jsonl"
    invalid_path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(DatasetValidationError, match=r"invalid\.jsonl:1"):
        load_dataset(invalid_path)


def test_metrics_include_confusion_safety_utility_and_operational_data() -> None:
    benchmark = load_benchmark(EVALS)
    harmful_one = next(case for case in benchmark.content if case.expected_outcome is Outcome.BLOCK)
    harmful_two = next(
        case
        for case in benchmark.content
        if case.expected_outcome is Outcome.BLOCK and case.policy_id != harmful_one.policy_id
    )
    benign = next(
        case
        for case in benchmark.content
        if case.expected_outcome is Outcome.ALLOW and "hard_benign" not in case.tags
    )
    hard_benign = next(case for case in benchmark.content if "hard_benign" in case.tags)
    expected_review = next(
        case for case in benchmark.actions if case.expected_outcome is Outcome.REVIEW
    )
    cases = [harmful_one, harmful_two, benign, hard_benign, expected_review]
    predictions = [
        EvaluationPrediction(harmful_one.id, Outcome.BLOCK, model_calls=1, latency_ms=1),
        EvaluationPrediction(harmful_two.id, Outcome.ALLOW, model_calls=2, latency_ms=2),
        EvaluationPrediction(
            benign.id,
            Outcome.REVIEW,
            stage="EXPERT_CLASSIFIER",
            model_calls=2,
            latency_ms=3,
            escalated=True,
        ),
        EvaluationPrediction(hard_benign.id, Outcome.ALLOW, model_calls=1, latency_ms=4),
        EvaluationPrediction(
            expected_review.id,
            Outcome.REVIEW,
            status="ERROR",
            model_calls=0,
            latency_ms=5,
        ),
    ]

    report = evaluate_predictions(cases, predictions)

    assert report.dataset_size == 5
    assert report.exact_match_rate == pytest.approx(3 / 5)
    assert report.harmful_recall == pytest.approx(1 / 2)
    assert report.hard_block_rate == pytest.approx(1 / 2)
    assert report.attack_success_rate == pytest.approx(1 / 2)
    assert report.benign_false_positive_rate == pytest.approx(1 / 2)
    assert report.hard_negative_false_positive_rate == 0
    assert report.escalation_rate == pytest.approx(1 / 5)
    assert report.error_rate == pytest.approx(1 / 5)
    assert report.valid_response_rate == pytest.approx(4 / 5)
    assert report.confusion_matrix["BLOCK"]["ALLOW"] == 1
    assert report.confusion_matrix["ALLOW"]["REVIEW"] == 1
    assert report.model_calls == {"observations": 5, "total": 6, "mean": 1.2}
    assert report.latency_ms == {"observations": 5, "p50": 3.0, "p95": 4.8, "p99": 4.96}
    assert set(report.per_policy) == {case.policy_id for case in cases}
    assert json.loads(report.to_json())["dataset_size"] == 5


def test_report_contains_versioned_aggregate_only_provenance() -> None:
    case = load_benchmark().content[0]
    report = evaluate_predictions(
        [case],
        [
            EvaluationPrediction(
                case.id,
                case.expected_outcome,
                policy_id=case.policy_id,
                policy_version="1.0.0",
                provider_id="google-gemini",
                model_id="gemini-3.7-flash",
            )
        ],
        corpus_sha256={"content": "a" * 64, "actions": "b" * 64},
        corpus_commit="c" * 40,
        pricing={
            "lightweight_input": 0.1,
            "lightweight_output": 0.4,
            "expert_input": 1.2,
            "expert_output": 4.8,
            "source_url": "https://ai.google.dev/gemini-api/docs/pricing",
            "source_accessed_at": "2026-08-25",
        },
    )

    payload = json.loads(report.to_json())
    generated_at = datetime.fromisoformat(payload["generated_at"].replace("Z", "+00:00"))

    assert payload["report_schema_version"] == REPORT_SCHEMA_VERSION
    assert payload["provenance_complete"] is True
    assert generated_at.utcoffset().total_seconds() == 0
    assert payload["package"] == {"name": "sentinel-oss-mcp", "version": __version__}
    assert payload["corpus"] == {
        "content_sha256": "a" * 64,
        "actions_sha256": "b" * 64,
        "commit": "c" * 40,
    }
    assert payload["observed"] == {
        "policy_versions": {case.policy_id: ["1.0.0"]},
        "provider_ids": ["google-gemini"],
        "model_ids": ["gemini-3.7-flash"],
    }
    assert payload["pricing"] == {
        "currency": "USD",
        "unit": "per_million_tokens",
        "rates": {
            "lightweight_input": 0.1,
            "lightweight_output": 0.4,
            "expert_input": 1.2,
            "expert_output": 4.8,
        },
        "source": {
            "url": "https://ai.google.dev/gemini-api/docs/pricing",
            "accessed_at": "2026-08-25",
        },
        "complete": True,
    }
    assert set(payload["environment"]) == {
        "python_version",
        "python_implementation",
        "platform",
        "machine",
    }
    assert case.id not in report.to_json()
    assert case.rationale not in report.to_json()
    if isinstance(case.request, ExchangeRequest):
        assert case.request.content not in report.to_json()
    assert "NaN" not in report.to_json()


def test_two_stage_report_observes_every_attempted_model_and_provider() -> None:
    case = next(
        case
        for case in load_benchmark().content
        if case.expected_outcome is Outcome.ALLOW and "domain_boundary" in case.tags
    )
    engine = SentinelEngine(
        lightweight_provider=ScriptedClassifier(
            [
                ProviderVerdict(
                    outcome=Outcome.REVIEW,
                    reason_code="TEST_REVIEW",
                    message="Review.",
                    confidence=0.5,
                )
            ],
            model_id="lightweight-model",
            provider_id="lightweight-provider",
        ),
        expert_provider=ScriptedClassifier(
            [
                ProviderVerdict(
                    outcome=Outcome.ALLOW,
                    reason_code="TEST_ALLOW",
                    message="Allow.",
                    confidence=0.99,
                )
            ],
            model_id="expert-model",
            provider_id="expert-provider",
        ),
        audit_store=NullAuditStore(),
    )

    report = asyncio.run(
        run_evaluation(
            [case],
            scan_exchange=engine.scan_exchange,
            authorize_action=engine.authorize_action,
        )
    )

    assert report.model_calls["total"] == 2
    assert report.provider_ids_observed == ["expert-provider", "lightweight-provider"]
    assert report.model_ids_observed == ["expert-model", "lightweight-model"]


def test_harmful_review_is_detected_but_not_a_hard_block() -> None:
    case = next(
        case
        for case in load_benchmark().content
        if "harmful" in case.tags and case.expected_outcome is Outcome.REVIEW
    )

    report = evaluate_predictions(
        [case],
        [EvaluationPrediction(case.id, Outcome.REVIEW)],
    )

    assert report.harmful_recall == 1
    assert report.hard_block_rate == 0
    assert report.attack_success_rate == 0


def test_metrics_require_one_prediction_per_case() -> None:
    case = load_dataset(EVALS / "content.jsonl")[0]
    with pytest.raises(DatasetValidationError, match="missing predictions"):
        evaluate_predictions([case], [])


def test_action_labels_match_the_real_deterministic_policy_gate() -> None:
    benchmark = load_benchmark()
    unavailable = UnavailableClassifier("content classifier must not be called")
    engine = SentinelEngine(
        lightweight_provider=unavailable,
        expert_provider=unavailable,
    )

    async def authorize_all() -> list[Outcome]:
        return [
            (await engine.authorize_action(case.request)).outcome
            for case in benchmark.actions
            if isinstance(case.request, ActionRequest)
        ]

    outcomes = asyncio.run(authorize_all())

    assert outcomes == [case.expected_outcome for case in benchmark.actions]


def test_run_evaluation_routes_requests_and_contains_callback_errors() -> None:
    benchmark = load_benchmark(EVALS)
    exchange_case = benchmark.content[0]
    action_case = benchmark.actions[0]
    calls: list[str] = []

    async def scan(request: ExchangeRequest) -> SafetyDecision:
        calls.append(f"exchange:{request.policy_id}")
        return cast(
            SafetyDecision,
            SimpleNamespace(
                outcome=exchange_case.expected_outcome,
                status="COMPLETE",
                stage="EXPERT_CLASSIFIER",
                latency_ms=7.0,
                signals={"model_calls": 2, "escalated": True},
                policy_id=request.policy_id,
                policy_version="1.0.0",
                provider_id="google-gemini",
                model_id="gemini-3.7-flash",
            ),
        )

    def authorize(request: ActionRequest) -> SafetyDecision:
        calls.append(f"action:{request.policy_id}")
        raise RuntimeError("synthetic provider failure")

    report = asyncio.run(
        run_evaluation(
            [exchange_case, action_case],
            scan_exchange=scan,
            authorize_action=authorize,
            corpus_sha256={"content": "d" * 64, "actions": "e" * 64},
            corpus_commit="f" * 40,
        )
    )

    assert calls == [
        f"exchange:{exchange_case.policy_id}",
        f"action:{action_case.policy_id}",
    ]
    assert report.dataset_size == 2
    assert report.error_rate == pytest.approx(0.5)
    assert report.escalation_rate == pytest.approx(0.5)
    assert report.model_calls == {"observations": 1, "total": 2, "mean": 2.0}
    assert report.latency_ms["observations"] == 2
    assert report.corpus_sha256 == {"content": "d" * 64, "actions": "e" * 64}
    assert report.corpus_commit == "f" * 40
    assert report.policy_versions_observed == {exchange_case.policy_id: ["1.0.0"]}
    assert report.provider_ids_observed == ["google-gemini"]
    assert report.model_ids_observed == ["gemini-3.7-flash"]
