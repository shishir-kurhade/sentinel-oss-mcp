"""Local stdio MCP interface for Sentinel OSS."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from sentinel_oss.contracts import ActionRequest, ExchangeRequest, SafetyDecision
from sentinel_oss.engine import SentinelEngine
from sentinel_oss.runtime import get_default_engine


def create_mcp_server(
    engine_factory: Callable[[], SentinelEngine] = get_default_engine,
) -> FastMCP:
    server = FastMCP("Sentinel OSS")

    @server.tool()
    async def scan_exchange(request: ExchangeRequest) -> SafetyDecision:
        """Scan sourced content and an optional draft output against a versioned policy."""

        return await engine_factory().scan_exchange(request)

    @server.tool()
    async def authorize_action(request: ActionRequest) -> SafetyDecision:
        """Authorize a proposed tool action using deterministic policy constraints."""

        return await engine_factory().authorize_action(request)

    @server.tool()
    async def check_safety(prompt: str, constitution: str = "banking") -> str:
        """Deprecated compatibility wrapper; REVIEW and ERROR are returned as BLOCK."""

        result = await engine_factory().check_prompt(prompt, constitution)
        return (
            f"Verdict: {result['action']}\n"
            f"Reason: {result['reason']}\n"
            f"Layer: {result['layer']}\n"
            f"Status: {result['status']}\n"
            f"Decision-ID: {result['decision_id']}"
        )

    @server.resource("sentinel://analytics/summary")
    async def analytics_summary() -> str:
        """Return aggregate, content-free decision metadata."""

        return json.dumps(await engine_factory().audit_store.summary(), indent=2)

    @server.resource("sentinel://policies")
    def policies() -> str:
        """List installed illustrative policy IDs and versions."""

        rows = [
            {
                "policy_id": item.policy_id,
                "version": item.version,
                "title": item.title,
                "illustrative": item.illustrative,
            }
            for item in engine_factory().policies.list_policies()
        ]
        return json.dumps(rows, indent=2)

    return server


mcp = create_mcp_server()


def main() -> None:
    """Start the supported local stdio transport."""

    if any(argument in {"-h", "--help"} for argument in sys.argv[1:]):
        print("usage: sentinel-oss-mcp\n\nStart the local Sentinel OSS MCP stdio server.")
        return
    if "--version" in sys.argv[1:]:
        from sentinel_oss import __version__

        print(__version__)
        return
    if sys.argv[1:]:
        raise SystemExit(f"unsupported arguments: {' '.join(sys.argv[1:])}")
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()


__all__ = ["create_mcp_server", "main", "mcp"]
