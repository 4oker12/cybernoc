"""Register MCP Events RPCs on the original MCP 2.0 server.

SDK mcp==2.3.0 supports custom handlers but does not expose an events capability.
For server/discover, return a raw dict to preserve capabilities.events on the wire.
The private Secure MCP Tunnel is a single-user authenticated connection.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp import types
from pydantic import Field

SCRIPT = "/workspace/cybernova-mcp-addon/events_core.py"
PYTHON = "/venv/main/bin/python"
RUNUSER = "/usr/sbin/runuser"

class ListParams(types.RequestParams):
    cursor: str | None = None

class SubscriptionParams(types.RequestParams):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    delivery: dict[str, Any]
    cursor: str | None = None
    ttl_ms: int | None = Field(default=None, alias="ttlMs")

class UnsubscribeParams(types.RequestParams):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    delivery: dict[str, Any]

async def _invoke(method: str, data: dict) -> dict:
    if method not in ("list", "subscribe", "unsubscribe"):
        raise ValueError("Invalid RPC")
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    if len(payload) > 6000:
        raise ValueError("Subscription arguments too large")
    proc = await asyncio.create_subprocess_exec(
        RUNUSER, "-u", "cybernova", "--",
        PYTHON, SCRIPT, method,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(payload), timeout=25)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError("Event handler timed out") from None
    if len(stdout) > 20_000:
        raise RuntimeError("Event result oversized")
    try:
        result = json.loads(stdout)
    except ValueError:
        raise RuntimeError("Event handler returned invalid JSON") from None
    if proc.returncode != 0 or not isinstance(result, dict) or result.get("error"):
        # Do not leak callback URL, signing secret or internal file paths.
        reason = str(result.get("error", "EventHandlerFailed"))[:100] if isinstance(result, dict) else "EventHandlerFailed"
        raise RuntimeError("MCP Events request failed: " + reason)
    return result

def register(server):
    ll = getattr(server, "_lowlevel_server", None)
    if ll is None or not callable(getattr(ll, "add_request_handler", None)):
        raise RuntimeError("MCP 2.x low-level handler registration required")

    original_discover = ll._handle_discover

    async def discover(ctx, params):
        result = await original_discover(ctx, params)
        # Raw dict avoids SDK 2.3.0 closed ServerCapabilities losing events.
        data = result.model_dump(by_alias=True, exclude_none=True, mode="json")
        if ctx.protocol_version == "2026-07-28":
            data.setdefault("capabilities", {})["events"] = {}
        return data

    async def list_events(ctx, params: ListParams):
        if ctx.protocol_version != "2026-07-28":
            raise RuntimeError("MCP Events requires protocol 2026-07-28")
        if params.cursor is not None:
            raise ValueError("Pagination not supported")
        return await _invoke("list", {})

    async def subscribe(ctx, params: SubscriptionParams):
        if ctx.protocol_version != "2026-07-28":
            raise RuntimeError("MCP Events requires protocol 2026-07-28")
        data = params.model_dump(by_alias=True, exclude_none=True)
        data.pop("_meta", None)
        return await _invoke("subscribe", data)

    async def unsubscribe(ctx, params: UnsubscribeParams):
        if ctx.protocol_version != "2026-07-28":
            raise RuntimeError("MCP Events requires protocol 2026-07-28")
        data = params.model_dump(by_alias=True, exclude_none=True)
        data.pop("_meta", None)
        return await _invoke("unsubscribe", data)

    ll.add_request_handler("server/discover", types.RequestParams, discover)
    ll.add_request_handler("events/list", ListParams, list_events)
    ll.add_request_handler("events/subscribe", SubscriptionParams, subscribe)
    ll.add_request_handler("events/unsubscribe", UnsubscribeParams, unsubscribe)
