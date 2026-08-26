from __future__ import annotations

from typing import Any

import pytest

from sentinel_oss import api
from sentinel_oss.evaluation import load_benchmark


@pytest.mark.asyncio
async def test_public_convenience_functions_delegate_to_lazy_default_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exchange = load_benchmark().content[0].request
    action = load_benchmark().actions[0].request
    calls: list[tuple[str, Any]] = []

    class FakeEngine:
        async def scan_exchange(self, request: object) -> str:
            calls.append(("scan", request))
            return "scan-result"

        async def authorize_action(self, request: object) -> str:
            calls.append(("authorize", request))
            return "action-result"

        async def check_prompt(self, prompt: str, constitution: str) -> dict[str, str]:
            calls.append(("legacy", (prompt, constitution)))
            return {"result": "legacy-result"}

    engine = FakeEngine()
    monkeypatch.setattr(api, "get_default_engine", lambda: engine)

    assert await api.scan_exchange(exchange) == "scan-result"  # type: ignore[arg-type, comparison-overlap]
    assert await api.authorize_action(action) == "action-result"  # type: ignore[arg-type, comparison-overlap]
    assert await api.check_safety("prompt") == {"result": "legacy-result"}
    assert calls == [
        ("scan", exchange),
        ("authorize", action),
        ("legacy", ("prompt", "banking")),
    ]
