"""Async MCP client for the Red Arsenal server.

Thin wrapper around fastmcp.Client that opens a fresh SSE session per
operation and provides `call_tool_and_wait()` — submit a tool, poll
`job_status` until done, fetch `job_result`. Each red_service call
gets its own short-lived session so there's no long-running connection
to manage across FastAPI request lifecycles.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from fastmcp import Client
from loguru import logger

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8765/sse")

POLL_INTERVAL_S = 2.0
DEFAULT_POLL_TIMEOUT_S = 900.0


def _extract(res: Any) -> dict:
    """Pull the structured content out of a fastmcp CallToolResult."""
    if hasattr(res, "data") and res.data is not None:
        return res.data
    if hasattr(res, "structured_content") and res.structured_content is not None:
        return res.structured_content
    if hasattr(res, "content"):
        for item in res.content:
            text = getattr(item, "text", None)
            if text:
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    return {"raw": text}
    return {"raw": repr(res)}


async def call_tool_and_wait(
    name: str,
    args: dict[str, Any],
    *,
    poll_timeout_s: float = DEFAULT_POLL_TIMEOUT_S,
) -> dict:
    """Submit an MCP tool call and block until the job finishes.

    Opens a new SSE session per call. If the tool returns an inline
    result (no job_id), returns it directly. Otherwise polls job_status
    until done/error, then fetches job_result.
    """
    async with Client(MCP_SERVER_URL) as client:
        submit_raw = await client.call_tool(name, args)
        submit = _extract(submit_raw)

        job_id = submit.get("job_id")
        if not job_id:
            # Either inline result or an error dict — return as-is.
            return submit

        logger.info("mcp job {} submitted id={}", name, job_id)

        deadline = time.monotonic() + poll_timeout_s
        while time.monotonic() < deadline:
            status = _extract(await client.call_tool("job_status", {"job_id": job_id}))
            if status.get("status") in ("done", "error"):
                break
            await asyncio.sleep(POLL_INTERVAL_S)
        else:
            logger.warning("mcp job {} poll timeout id={}", name, job_id)
            # Best-effort cancel so we don't orphan a Kali process.
            try:
                await client.call_tool("job_cancel", {"job_id": job_id})
            except Exception:
                pass
            return {
                "tool": name,
                "ok": False,
                "error": f"poll timeout after {poll_timeout_s}s",
                "job_id": job_id,
            }

        result = _extract(
            await client.call_tool("job_result", {"job_id": job_id, "wait": True})
        )
        return result


async def list_installed_tools() -> dict:
    """One-shot call to the server's `list_tools` endpoint.

    Useful at startup to log which Kali binaries the arsenal sees.
    """
    async with Client(MCP_SERVER_URL) as client:
        return _extract(await client.call_tool("list_tools", {}))


async def ping() -> bool:
    """Return True if the MCP server responds to `ping`."""
    try:
        async with Client(MCP_SERVER_URL) as client:
            res = _extract(await client.call_tool("ping", {}))
        return bool(res.get("ok"))
    except Exception as exc:
        logger.warning("mcp ping failed: {}", exc)
        return False
