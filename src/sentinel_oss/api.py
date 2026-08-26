"""Convenience functions backed by the lazily constructed default engine."""

from __future__ import annotations

from typing import Any

from sentinel_oss.contracts import ActionRequest, ExchangeRequest, SafetyDecision
from sentinel_oss.runtime import get_default_engine


async def scan_exchange(request: ExchangeRequest) -> SafetyDecision:
    return await get_default_engine().scan_exchange(request)


async def authorize_action(request: ActionRequest) -> SafetyDecision:
    return await get_default_engine().authorize_action(request)


async def check_safety(prompt: str, constitution: str = "banking") -> dict[str, Any]:
    """Deprecated compatibility wrapper; use scan_exchange instead."""

    return await get_default_engine().check_prompt(prompt, constitution)


__all__ = ["authorize_action", "check_safety", "scan_exchange"]
