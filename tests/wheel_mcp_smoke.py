"""Credential-free stdio handshake used against an isolated wheel installation."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import timedelta

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    environment = os.environ.copy()
    environment.pop("GOOGLE_API_KEY", None)
    environment.pop("SENTINEL_GOOGLE_API_KEY", None)
    environment["SENTINEL_OFFLINE"] = "1"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sentinel_oss.mcp_server"],
        env=environment,
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=10),
        ) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()

    discovered = {tool.name: tool for tool in tools.tools}
    expected = {"scan_exchange", "authorize_action", "check_safety"}
    if set(discovered) != expected:
        raise RuntimeError(f"unexpected MCP tools: {sorted(discovered)}")
    for name in ("scan_exchange", "authorize_action"):
        schema = discovered[name].outputSchema
        if schema is None or "outcome" not in schema.get("properties", {}):
            raise RuntimeError(f"{name} does not advertise a SafetyDecision output schema")


if __name__ == "__main__":
    asyncio.run(main())
