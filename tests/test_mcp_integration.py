from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_real_mcp_stdio_handshake_and_typed_discovery(tmp_path: Path) -> None:
    environment = os.environ.copy()
    for name in ("GOOGLE_API_KEY", "SENTINEL_GOOGLE_API_KEY"):
        environment.pop(name, None)
    environment.update(
        {
            "SENTINEL_DATA_DIR": str(tmp_path),
            "SENTINEL_OFFLINE": "1",
            "GOOGLE_GENAI_USE_VERTEXAI": "false",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sentinel_oss.mcp_server"],
        cwd=Path(__file__).parents[1],
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
        initialized = await session.initialize()
        discovered = await session.list_tools()
        review_result = await session.call_tool(
            "authorize_action",
            {
                "request": {
                    "policy_id": "banking",
                    "tool_name": "unknown.tool",
                    "arguments": {},
                    "data_labels": ["PUBLIC"],
                    "source_kinds": ["USER"],
                    "reversible": True,
                    "user_confirmed": False,
                }
            },
        )

    assert initialized.serverInfo.name == "Sentinel OSS"
    tools = {tool.name: tool for tool in discovered.tools}
    assert set(tools) == {"scan_exchange", "authorize_action", "check_safety"}
    assert review_result.isError is False
    assert review_result.structuredContent is not None
    assert review_result.structuredContent["status"] == "COMPLETE"
    assert review_result.structuredContent["outcome"] == "REVIEW"
    for name in ("scan_exchange", "authorize_action"):
        output_schema = tools[name].outputSchema
        assert output_schema is not None
        assert output_schema.get("additionalProperties") is False
        assert {
            "decision_id",
            "status",
            "outcome",
            "reason_code",
            "policy_id",
            "policy_version",
            "stage",
            "latency_ms",
        }.issubset(output_schema["required"])

    action_schema = tools["authorize_action"].inputSchema
    action_request = action_schema["$defs"]["ActionRequest"]
    assert {"arguments", "data_labels", "source_kinds", "user_confirmed"}.issubset(
        action_request["required"]
    )
