from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from sentinel_oss import cli
from sentinel_oss.audit import NullAuditStore


class FakeMCP:
    def __init__(self) -> None:
        self.calls = 0

    def run(self) -> None:
        self.calls += 1


def test_parser_and_version_are_credential_free(capsys: pytest.CaptureFixture[str]) -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["redteam", "generate", "--category", "injection"])
    assert args.command == "redteam"
    assert args.redteam_command == "generate"
    assert args.style == "standard"

    with pytest.raises(SystemExit, match="0"):
        cli.main(["--version"])
    assert capsys.readouterr().out.strip() == "0.1.0b1"


def test_serve_dispatches_to_local_stdio_mcp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_mcp = FakeMCP()
    module = ModuleType("sentinel_oss.mcp_server")
    module.mcp = fake_mcp  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentinel_oss.mcp_server", module)

    assert cli.main(["serve"]) == 0
    assert fake_mcp.calls == 1


@pytest.mark.parametrize("live,expected_cases", [(False, "actions"), (True, "all")])
def test_eval_dispatches_bundled_or_live_case_partition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    live: bool,
    expected_cases: str,
) -> None:
    import sentinel_oss.evaluation as evaluation
    import sentinel_oss.runtime as runtime

    benchmark = SimpleNamespace(
        actions="actions",
        cases="all",
        content_sha256="a" * 64,
        actions_sha256="b" * 64,
    )
    report = SimpleNamespace(
        exact_match_rate=1.0,
        error_rate=0.0,
        harmful_recall=1.0,
        benign_false_positive_rate=0.0,
        hard_negative_false_positive_rate=0.0,
        per_policy={"banking": {"harmful_recall": 1.0}},
        to_json=lambda: '{"dataset_size": 1}',
    )
    loaded: list[Path] = []
    calls: list[tuple[object, Any, Any, object, object, object]] = []

    def fake_load(path: Path) -> object:
        loaded.append(path)
        return benchmark

    async def fake_run(
        cases: object,
        *,
        scan_exchange: Any,
        authorize_action: Any,
        corpus_sha256: object,
        corpus_commit: object,
        pricing: object,
    ) -> object:
        calls.append(
            (cases, scan_exchange, authorize_action, corpus_sha256, corpus_commit, pricing)
        )
        return report

    class FakeEngine:
        async def scan_exchange(self, request: object) -> None:
            del request

        async def authorize_action(self, request: object) -> None:
            del request

    engine = FakeEngine()
    audit_stores: list[object] = []

    def fake_build(*, settings: object, audit_store: object) -> FakeEngine:
        del settings
        audit_stores.append(audit_store)
        return engine

    monkeypatch.setattr(evaluation, "load_benchmark", fake_load)
    monkeypatch.setattr(evaluation, "run_evaluation", fake_run)
    monkeypatch.setattr(runtime, "build_engine", fake_build)
    monkeypatch.setenv("SENTINEL_EVAL_CORPUS_COMMIT", "c" * 40)
    monkeypatch.setenv("SENTINEL_LIGHTWEIGHT_INPUT_PRICE_PER_MILLION", "0.1")
    monkeypatch.setenv("SENTINEL_LIGHTWEIGHT_OUTPUT_PRICE_PER_MILLION", "0.4")
    monkeypatch.setenv("SENTINEL_EXPERT_INPUT_PRICE_PER_MILLION", "1.2")
    monkeypatch.setenv("SENTINEL_EXPERT_OUTPUT_PRICE_PER_MILLION", "4.8")
    monkeypatch.setenv("SENTINEL_EVAL_PRICE_SOURCE_URL", "https://example.com/pricing")
    monkeypatch.setenv("SENTINEL_EVAL_PRICE_ACCESSED_AT", "2026-08-25")
    arguments = ["eval", "--evals-dir", str(tmp_path)]
    if live:
        arguments.append("--live")

    assert cli.main(arguments) == 0

    assert loaded == [tmp_path]
    assert len(audit_stores) == 1
    assert isinstance(audit_stores[0], NullAuditStore)
    assert calls == [
        (
            expected_cases,
            engine.scan_exchange,
            engine.authorize_action,
            {"content": "a" * 64, "actions": "b" * 64},
            "c" * 40,
            {
                "lightweight_input": 0.1,
                "lightweight_output": 0.4,
                "expert_input": 1.2,
                "expert_output": 4.8,
                "source_url": "https://example.com/pricing",
                "source_accessed_at": "2026-08-25",
            },
        )
    ]
    assert json.loads(capsys.readouterr().out)["dataset_size"] == 1


def test_eval_writes_report_and_enforces_failed_gates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sentinel_oss.evaluation as evaluation
    import sentinel_oss.runtime as runtime

    report = SimpleNamespace(
        exact_match_rate=0.5,
        error_rate=0.5,
        to_json=lambda: '{"error_rate": 0.5}',
    )
    monkeypatch.setattr(
        evaluation,
        "load_benchmark",
        lambda path: SimpleNamespace(
            actions=(),
            cases=(),
            content_sha256="a" * 64,
            actions_sha256="b" * 64,
        ),
    )

    async def fake_run(*args: object, **kwargs: object) -> object:
        del args, kwargs
        return report

    monkeypatch.setattr(evaluation, "run_evaluation", fake_run)
    monkeypatch.setattr(
        runtime,
        "build_engine",
        lambda **kwargs: SimpleNamespace(scan_exchange=None, authorize_action=None),
    )
    output = tmp_path / "nested" / "report.json"

    result = cli.main(
        [
            "eval",
            "--evals-dir",
            str(tmp_path),
            "--output",
            str(output),
            "--enforce-gates",
        ]
    )

    assert result == 1
    assert output.read_text(encoding="utf-8") == '{"error_rate": 0.5}\n'
    captured = capsys.readouterr()
    assert "release gates were not met" in captured.err


def test_release_gate_logic_covers_offline_and_full_reports() -> None:
    offline = SimpleNamespace(exact_match_rate=1.0, error_rate=0.0)
    assert cli._passes_release_gates(offline, full=False) is True
    assert (
        cli._passes_release_gates(
            SimpleNamespace(exact_match_rate=0.99, error_rate=0.0), full=False
        )
        is False
    )

    full = SimpleNamespace(
        provenance_complete=True,
        error_rate=0.0,
        harmful_recall=0.95,
        benign_false_positive_rate=0.05,
        hard_negative_false_positive_rate=0.10,
        per_policy={
            "banking": {"harmful_recall": 0.90},
            "retail": {"harmful_recall": None},
        },
        pricing={"complete": True},
    )
    assert cli._passes_release_gates(full, full=True) is True
    full.per_policy["banking"]["harmful_recall"] = 0.89
    assert cli._passes_release_gates(full, full=True) is False


def test_redteam_dispatch_prints_warning_and_generated_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sentinel_oss.redteam as redteam

    calls: list[tuple[str, str]] = []

    async def fake_generate(category: str, style: str) -> str:
        calls.append((category, style))
        return "Synthetic adversarial prompt"

    monkeypatch.setattr(redteam, "generate_attack", fake_generate)

    assert (
        cli.main(
            [
                "redteam",
                "generate",
                "--category",
                "indirect injection",
                "--style",
                "roleplay",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert calls == [("indirect injection", "roleplay")]
    assert captured.out.strip() == "Synthetic adversarial prompt"
    assert "Authorized testing only" in captured.err


def test_dashboard_dispatch_uses_current_python_and_propagates_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[list[str], bool]] = []

    def fake_run(command: list[str], *, check: bool) -> SimpleNamespace:
        commands.append((command, check))
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.main(["dashboard"]) == 7
    command, check = commands[0]
    assert command[:4] == [sys.executable, "-m", "streamlit", "run"]
    assert Path(command[4]).name == "dashboard.py"
    assert check is False


def test_dashboard_dispatch_reports_missing_optional_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise FileNotFoundError("synthetic")

    monkeypatch.setattr(cli.subprocess, "run", missing)
    with pytest.raises(SystemExit, match=r"sentinel-oss-mcp\[dashboard\]"):
        cli.main(["dashboard"])
