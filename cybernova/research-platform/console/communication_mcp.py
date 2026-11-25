"""Dedicated ChatGPT <-> Cybernova communication MCP server.

This server reads/writes a shared SQLite task/message store. It is not an LLM,
scheduler, scanner, notification push channel, or ChatGPT wake-up mechanism.

MCP transport: streamable HTTP on 127.0.0.1:18796, or local stdio.
A connected ChatGPT MCP plugin is required for ChatGPT to invoke its tools.
Do not publish the loopback HTTP endpoint without an authenticated connector.
"""
from __future__ import annotations

import os
import time
from functools import wraps

from mcp.server.fastmcp import FastMCP

try:
    from .diagnostics import (
        configure as configure_diagnostics, diagnostic_context,
        event as diagnostic_event,
    )
except ImportError:
    from diagnostics import (
        configure as configure_diagnostics, diagnostic_context,
        event as diagnostic_event,
    )

try:
    from .communication import CommunicationStore
    from .evidence import EvidenceJournal
except ImportError:
    from communication import CommunicationStore
    from evidence import EvidenceJournal

store = CommunicationStore()
evidence = EvidenceJournal(store)


def _observe_tool(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        task_id = kwargs.get("task_id")
        started = time.monotonic()
        with diagnostic_context(task_id=task_id, agent="chatgpt", mode="communication"):
            fields = {"tool": func.__name__, "source": "communication_mcp"}
            diagnostic_event("communication_mcp_tool_start", kind="action", **fields)
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                diagnostic_event(
                    "communication_mcp_tool_failed", kind="error", **fields,
                    status="failed", error_type=type(exc).__name__,
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
                raise
            resolved_task = task_id or (result.get("task_id") if isinstance(result, dict) else None)
            if resolved_task and not task_id:
                with diagnostic_context(task_id=resolved_task):
                    diagnostic_event(
                        "communication_mcp_tool_completed", kind="action", **fields,
                        status="ok", duration_ms=round((time.monotonic() - started) * 1000),
                    )
            else:
                diagnostic_event(
                    "communication_mcp_tool_completed", kind="action", **fields,
                    status="failed" if isinstance(result, dict) and result.get("ok") is False else "ok",
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
            return result
    return wrapped
mcp = FastMCP(
    "Cybernova Communication",
    host="127.0.0.1",
    port=18796,
    stateless_http=True,
    json_response=True,
    instructions=(
        "Shared task inbox for ChatGPT and local Qwen. "
        "Read pending review requests, evaluate findings and send feedback. "
        "Tools are data exchange, not instant notifications; Qwen worker "
        "continues queued tasks independently when the Cybernova console is running."
    ),
)


@mcp.tool()
@_observe_tool
def cybernova_create_task(title: str, instruction: str) -> dict:
    """Create a durable Cybernova research task and queue Qwen's first instruction."""
    task = store.create_task(title, origin="chatgpt")
    message = store.append(task["task_id"], "chatgpt", "instruction",
                           instruction, status="queued")
    return {"task_id": task["task_id"], "status": "queued",
            "message_seq": message["seq"], "note": "Qwen worker will process this when online"}


@mcp.tool()
@_observe_tool
def cybernova_list_tasks(status: str = "", limit: int = 20) -> dict:
    """List active or historical shared Cybernova research tasks."""
    tasks = store.list_tasks(status=status or None, limit=limit)
    return {"count": len(tasks), "tasks": tasks}


@mcp.tool()
@_observe_tool
def cybernova_task_status(task_id: str) -> dict:
    """Read durable status of a single Cybernova task."""
    return store.get_task(task_id)


@mcp.tool()
@_observe_tool
def cybernova_read_dialog(task_id: str, after_seq: int = 0,
                          limit: int = 30) -> dict:
    """Read task conversation with cursor; includes ChatGPT and Qwen messages."""
    return store.read_dialog(task_id, after=after_seq, limit=limit)


@mcp.tool()
@_observe_tool
def cybernova_pending_reviews(after_seq: int = 0, limit: int = 30) -> dict:
    """Read pending requests from Qwen asking ChatGPT for independent analysis."""
    return store.events(after=after_seq, limit=limit, review_only=True)


@mcp.tool()
@_observe_tool
def cybernova_new_events(after_seq: int = 0, limit: int = 30) -> dict:
    """Read events added since a cursor; supports scheduled polling, not push."""
    return store.events(after=after_seq, limit=limit)


@mcp.tool()
@_observe_tool
def cybernova_send_feedback(task_id: str, message: str,
                             event_key: str = "") -> dict:
    """Send ChatGPT's feedback and queue exactly one Qwen continuation."""
    event = store.send_feedback(task_id, message, event_key=event_key or None)
    return {"task_id": task_id, "event_seq": event["seq"],
            "status": store.get_task(task_id)["status"],
            "note": "Qwen will continue when its worker is running"}


@mcp.tool()
@_observe_tool
def cybernova_evidence_index(task_id: str) -> dict:
    """Return evidence reference IDs from messages, without raw files or secrets."""
    dialog = store.read_dialog(task_id, limit=100)
    refs = list(dict.fromkeys(
        ref for item in dialog["messages"] for ref in item["evidence_refs"]
    ))
    records = evidence.list_evidence(task_id, limit=100)
    refs.extend(r["evidence_id"] for r in records if r["evidence_id"] not in refs)
    return {"task_id": task_id, "evidence_refs": refs[:100],
            "note": "Qwen claims can be fetched with cybernova_get_evidence; tool receipts contain only cryptographic digests"}



@mcp.tool()
@_observe_tool
def cybernova_get_evidence(task_id: str, evidence_id: str) -> dict:
    """Read one Qwen-reported, unverified, source-attributed evidence entry.

    The entry is not proof that the named tool was executed. Cross-check the
    controller's separately generated tool receipts before confirming facts.
    """
    return evidence.get_evidence(task_id, evidence_id)


@mcp.tool()
@_observe_tool
def cybernova_tool_receipts(task_id: str, limit: int = 50) -> dict:
    """Read controller-generated tool execution metadata and SHA256 digests.

    No tool results, credentials, captured traffic or raw payloads are returned.
    """
    rows = evidence.list_tool_receipts(task_id, limit=limit)
    return {"task_id": task_id, "count": len(rows), "receipts": rows}


if __name__ == "__main__":
    transport = os.environ.get("CYBERNOVA_COMM_TRANSPORT", "streamable-http")
    if transport not in {"streamable-http", "stdio"}:
        raise SystemExit("CYBERNOVA_COMM_TRANSPORT must be streamable-http or stdio")
    configure_diagnostics("communication-mcp")
    mcp.run(transport=transport)
