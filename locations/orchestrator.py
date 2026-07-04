# -*- coding: utf-8 -*-
"""
오케스트레이터: 팀원별로 만드는 MCP 서버들을 서브프로세스로 띄워 호출하고
결과를 돌려주는 역할. 새 MCP 서버가 생기면 MCP_SERVERS에 이름과 스크립트
경로만 추가하면 된다.
"""

import asyncio
from pathlib import Path

from fastmcp import Client

MCP_DIR = Path(__file__).resolve().parent / "mcp"

MCP_SERVERS = {
    "transit": MCP_DIR / "bus_mcp.py",
}


class McpCallError(Exception):
    """MCP 서버 호출 자체가 실패했을 때 (프로세스 실행 오류, 알 수 없는 MCP 이름 등)"""


async def _call_tool_async(script_path: Path, tool_name: str, arguments: dict):
    async with Client(str(script_path)) as client:
        result = await client.call_tool(tool_name, arguments)
        return result.data


def call_mcp_tool(mcp_name: str, tool_name: str, **arguments) -> dict:
    """
    MCP_SERVERS에 등록된 mcp_name의 MCP 서버를 서브프로세스로 띄워
    tool_name 도구를 호출하고 결과 dict를 반환한다.
    """
    if mcp_name not in MCP_SERVERS:
        raise McpCallError(f"등록되지 않은 MCP입니다: {mcp_name}")

    script_path = MCP_SERVERS[mcp_name]
    try:
        return asyncio.run(_call_tool_async(script_path, tool_name, arguments))
    except Exception as e:
        raise McpCallError(f"{mcp_name} MCP 호출 실패: {e}") from e
