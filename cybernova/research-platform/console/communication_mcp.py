"""Dedicated ChatGPT <-> Cybernova communication MCP server.

This server reads/writes a shared SQLite task/message store. It is not an LLM,
scheduler, scanner, notification push channel, or ChatGPT wake-up mechanism.

MCP transport: streamable HTTP on 127.0.0.1:18796, or local stdio.
A connected ChatGPT MCP plugin is required for ChatGPT to invoke its tools.
Do not publish the loopback HTTP endpoint without an authenticated connector.
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

try:
    from .communication import CommunicationStore
except ImportError:
    from communication import CommunicationStore

store = CommunicationStore()
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
def cybernova_create_task(title: str, instruction: str) -> dict:
    """Create a durable Cybernova research task and queue Qwen's first instruction."""
    task = store.create_task(title, origin="chatgpt")
    message = store.append(task["task_id"], "chatgpt", "instruction",
                           instruction, status="queued")
    return {"task_id": task["task_id"], "status": "queued",
            "message_seq": message["seq"], "note": "Qwen worker will process this when online"}


@mcp.tool()
def cybernova_list_tasks(status: str = "", limit: int = 20) -> dict:
    """List active or historical shared Cybernova research tasks."""
    tasks = store.list_tasks(status=status or None, limit=limit)
    return {"count": len(tasks), "tasks": tasks}


@mcp.tool()
def cybernova_task_status(task_id: str) -> dict:
    """Read durable status of a single Cybernova task."""
    return store.get_task(task_id)


@mcp.tool()
def cybernova_read_dialog(task_id: str, after_seq: int = 0,
                          limit: int = 30) -> dict:
    """Read task conversation with cursor; includes ChatGPT and Qwen messages."""
    return store.read_dialog(task_id, after=after_seq, limit=limit)


@mcp.tool()
def cybernova_pending_reviews(after_seq: int = 0, limit: int = 30) -> dict:
    """Read pending requests from Qwen asking ChatGPT for independent analysis."""
    return store.events(after=after_seq, limit=limit, review_only=True)


@mcp.tool()
def cybernova_new_events(after_seq: int = 0, limit: int = 30) -> dict:
    """Read events added since a cursor; supports scheduled polling, not push."""
    return store.events(after=after_seq, limit=limit)


@mcp.tool()
def cybernova_send_feedback(task_id: str, message: str,
                             event_key: str = "") -> dict:
    """Send ChatGPT's feedback and queue exactly one Qwen continuation."""
    event = store.send_feedback(task_id, message, event_key=event_key or None)
    return {"task_id": task_id, "event_seq": event["seq"],
            "status": store.get_task(task_id)["status"],
            "note": "Qwen will continue when its worker is running"}


@mcp.tool()
def cybernova_evidence_index(task_id: str) -> dict:
    """Return evidence reference IDs from messages, without raw files or secrets."""
    dialog = store.read_dialog(task_id, limit=100)
    refs = list(dict.fromkeys(
        ref for item in dialog["messages"] for ref in item["evidence_refs"]
    ))
    return {"task_id": task_id, "evidence_refs": refs[:100],
            "note": "Reference index only; evidence payload retrieval requires a separate artifact provider"}


if __name__ == "__main__":
    transport = os.environ.get("CYBERNOVA_COMM_TRANSPORT", "streamable-http")
    if transport not in {"streamable-http", "stdio"}:
        raise SystemExit("CYBERNOVA_COMM_TRANSPORT must be streamable-http or stdio")
    mcp.run(transport=transport)
