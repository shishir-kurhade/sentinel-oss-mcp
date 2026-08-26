from __future__ import annotations

import importlib
import json
import sys
from types import ModuleType
from typing import Any

import pytest

from sentinel_oss.contracts import (
    ActionRequest,
    DataLabel,
    DecisionStatus,
    EvaluationStage,
    ExchangeRequest,
    Outcome,
    SafetyDecision,
    SourceKind,
    TrustLevel,
)
from sentinel_oss.policies import PolicySummary, default_policy_registry


class FakeFastMCP:
    def __init__(self, name: str) -> None:
        self.name = name
        self.tools: dict[str, Any] = {}
        self.resources: dict[str, Any] = {}
        self.run_calls = 0

    def tool(self) -> Any:
        def register(function: Any) -> Any:
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, uri: str) -> Any:
        def register(function: Any) -> Any:
            self.resources[uri] = function
            return function

        return register

    def run(self) -> None:
        self.run_calls += 1


@pytest.fixture
def mcp_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    mcp_package = ModuleType("mcp")
    mcp_package.__path__ = []  # type: ignore[attr-defined]
    server_package = ModuleType("mcp.server")
    server_package.__path__ = []  # type: ignore[attr-defined]
    fastmcp_module = ModuleType("mcp.server.fastmcp")
    fastmcp_module.FastMCP = FakeFastMCP  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mcp", mcp_package)
    monkeypatch.setitem(sys.modules, "mcp.server", server_package)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp_module)

    import sentinel_oss.runtime as runtime

    initialization_calls: list[None] = []

    def forbidden_initialization() -> Any:
        initialization_calls.append(None)
        raise AssertionError("the default engine must remain lazy during import")

    monkeypatch.setattr(runtime, "get_default_engine", forbidden_initialization)
    sys.modules.pop("sentinel_oss.mcp_server", None)
    module = importlib.import_module("sentinel_oss.mcp_server")
    assert initialization_calls == []
    yield module
    sys.modules.pop("sentinel_oss.mcp_server", None)


def decision(outcome: Outcome = Outcome.REVIEW) -> SafetyDecision:
    return SafetyDecision(
        decision_id="decision-test",
        status=DecisionStatus.COMPLETE,
        outcome=outcome,
        reason_code="TEST_DECISION",
        message="Synthetic decision.",
        policy_id="banking",
        policy_version="1.0.0",
        stage=EvaluationStage.ACTION_POLICY,
        latency_ms=1.25,
        signals={"model_calls": 0},
    )


class FakeAuditStore:
    async def summary(self) -> dict[str, int | float | str]:
        return {
            "total_decisions": 2,
            "blocked_decisions": 1,
            "review_decisions": 1,
            "error_decisions": 0,
            "average_latency_ms": 1.25,
            "last_updated": "2026-08-25T00:00:00+00:00",
        }


class FakeEngine:
    def __init__(self, policies: Any | None = None) -> None:
        self.audit_store = FakeAuditStore()
        self.policies = policies if policies is not None else default_policy_registry()
        self.exchange_requests: list[ExchangeRequest] = []
        self.action_requests: list[ActionRequest] = []
        self.prompt_requests: list[tuple[str, str]] = []

    async def scan_exchange(self, request: ExchangeRequest) -> SafetyDecision:
        self.exchange_requests.append(request)
        return decision()

    async def authorize_action(self, request: ActionRequest) -> SafetyDecision:
        self.action_requests.append(request)
        return decision()

    async def check_prompt(self, prompt: str, constitution: str) -> dict[str, str]:
        self.prompt_requests.append((prompt, constitution))
        return {
            "action": "BLOCK",
            "reason": "Manual review is required.",
            "layer": "ERROR",
            "status": "ERROR",
            "decision_id": "legacy-test",
        }


@pytest.mark.asyncio
async def test_mcp_exposes_only_public_guard_tools_and_aggregate_resources(
    mcp_module: Any,
) -> None:
    engine = FakeEngine()
    server = mcp_module.create_mcp_server(lambda: engine)

    assert server.name == "Sentinel OSS"
    assert set(server.tools) == {"scan_exchange", "authorize_action", "check_safety"}
    assert set(server.resources) == {
        "sentinel://analytics/summary",
        "sentinel://policies",
    }
    assert "generate_attack" not in server.tools
    assert "add_to_cache" not in server.tools
    assert all("raw" not in uri for uri in server.resources)


@pytest.mark.asyncio
async def test_mcp_tools_return_machine_readable_contracts(mcp_module: Any) -> None:
    engine = FakeEngine()
    server = mcp_module.create_mcp_server(lambda: engine)
    exchange = ExchangeRequest(
        policy_id="banking",
        trusted_user_intent="Answer a support question.",
        content="Untrusted retrieved content.",
        source_kind=SourceKind.RETRIEVAL,
        trust_level=TrustLevel.UNTRUSTED,
    )
    action = ActionRequest(
        policy_id="banking",
        tool_name="faq.search",
        arguments={"query": "hours"},
        data_labels={DataLabel.PUBLIC},
        source_kinds={SourceKind.USER},
        reversible=True,
        user_confirmed=False,
    )

    scan_result = await server.tools["scan_exchange"](exchange)
    action_result = await server.tools["authorize_action"](action)

    assert scan_result.outcome is Outcome.REVIEW
    assert scan_result.status is DecisionStatus.COMPLETE
    assert scan_result.schema_version == "1"
    assert action_result.outcome is Outcome.REVIEW
    assert engine.exchange_requests == [exchange]
    assert engine.action_requests == [action]


@pytest.mark.asyncio
async def test_legacy_mcp_tool_formats_review_as_non_authorized_block(mcp_module: Any) -> None:
    engine = FakeEngine()
    server = mcp_module.create_mcp_server(lambda: engine)

    rendered = await server.tools["check_safety"]("untrusted", "healthcare")

    assert rendered == (
        "Verdict: BLOCK\n"
        "Reason: Manual review is required.\n"
        "Layer: ERROR\n"
        "Status: ERROR\n"
        "Decision-ID: legacy-test"
    )
    assert engine.prompt_requests == [("untrusted", "healthcare")]


@pytest.mark.asyncio
async def test_mcp_resources_are_content_free_and_list_versioned_policies(
    mcp_module: Any,
) -> None:
    engine = FakeEngine()
    server = mcp_module.create_mcp_server(lambda: engine)

    summary = json.loads(await server.resources["sentinel://analytics/summary"]())
    policies = json.loads(server.resources["sentinel://policies"]())

    assert summary["total_decisions"] == 2
    assert "prompt" not in json.dumps(summary).casefold()
    assert {item["policy_id"] for item in policies} == {
        "banking",
        "healthcare",
        "hr_it",
        "retail",
        "telecom",
    }
    assert all(item["illustrative"] is True for item in policies)
    assert all(item["version"] == "1.0.0" for item in policies)


def test_mcp_policy_resource_uses_injected_engine_registry(mcp_module: Any) -> None:
    class CustomRegistry:
        def list_policies(self) -> tuple[PolicySummary, ...]:
            return (
                PolicySummary(
                    policy_id="custom_policy",
                    version="7.2.1",
                    title="Custom Test Policy",
                    illustrative=False,
                ),
            )

    engine = FakeEngine(policies=CustomRegistry())
    server = mcp_module.create_mcp_server(lambda: engine)

    assert json.loads(server.resources["sentinel://policies"]()) == [
        {
            "policy_id": "custom_policy",
            "version": "7.2.1",
            "title": "Custom Test Policy",
            "illustrative": False,
        }
    ]


def test_mcp_entrypoint_help_version_and_stdio_dispatch(
    mcp_module: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["sentinel-oss-mcp", "--help"])
    mcp_module.main()
    assert "local Sentinel OSS MCP stdio server" in capsys.readouterr().out
    assert mcp_module.mcp.run_calls == 0

    monkeypatch.setattr(sys, "argv", ["sentinel-oss-mcp", "--version"])
    mcp_module.main()
    assert capsys.readouterr().out.strip() == "0.1.0b1"
    assert mcp_module.mcp.run_calls == 0

    monkeypatch.setattr(sys, "argv", ["sentinel-oss-mcp"])
    mcp_module.main()
    assert mcp_module.mcp.run_calls == 1

    monkeypatch.setattr(sys, "argv", ["sentinel-oss-mcp", "--http"])
    with pytest.raises(SystemExit, match="unsupported arguments: --http"):
        mcp_module.main()
