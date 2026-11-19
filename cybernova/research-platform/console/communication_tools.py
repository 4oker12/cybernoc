"""Session-bound Qwen communication tools.

All messages are persisted in the shared SQLite store. Qwen can request an
independent ChatGPT review, post a status update or read its task dialog, but
cannot impersonate ChatGPT or choose another task ID.
"""
from __future__ import annotations

try:
    from .communication import CommunicationStore, CommunicationError
except ImportError:
    from communication import CommunicationStore, CommunicationError


COMMUNICATION_TOOLS = [
    {
        "name": "comm_request_review",
        "description": "Ask ChatGPT to independently review a result or hypothesis. "
                       "The question and evidence reference IDs are queued for the "
                       "shared Cybernova MCP inbox; ChatGPT is not woken instantly.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "question": {"type": "string"},
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["question"],
            "additionalProperties": False,
        },
    },
    {
        "name": "comm_post_progress",
        "description": "Record a short, factual investigation progress update "
                       "in the durable task timeline. Does not request review.",
        "inputSchema": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
            "additionalProperties": False,
        },
    },
    {
        "name": "comm_read_dialog",
        "description": "Read recent human, Qwen and ChatGPT messages from the "
                       "current task. Only this task is available.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]
COMMUNICATION_NAMES = frozenset(t["name"] for t in COMMUNICATION_TOOLS)


class CommunicationToolClient:
    def __init__(self, upstream, store: CommunicationStore, task_id: str):
        self.upstream = upstream
        self.store = store
        self.task_id = store.get_task(task_id)["task_id"]

    def initialize(self) -> list[dict]:
        return self.upstream.initialize() + COMMUNICATION_TOOLS

    def call(self, name: str, arguments: dict) -> tuple[dict, bool]:
        if name not in COMMUNICATION_NAMES:
            return self.upstream.call(name, arguments)
        try:
            if not isinstance(arguments, dict):
                raise CommunicationError("invalid_arguments")
            if name == "comm_request_review":
                result = self.store.mark_review(
                    self.task_id,
                    arguments["question"],
                    evidence_refs=arguments.get("evidence_refs"),
                )
                return {
                    "ok": True, "status": "needs_review",
                    "event_seq": result["seq"],
                    "note": "Queued for ChatGPT review; no instant ChatGPT wake-up",
                }, False
            if name == "comm_post_progress":
                result = self.store.append(
                    self.task_id, "qwen", "progress", arguments["summary"],
                )
                return {"ok": True, "event_seq": result["seq"]}, False
            if name == "comm_read_dialog":
                result = self.store.read_dialog(self.task_id, limit=30)
                return {
                    "ok": True,
                    "status": result["task"]["status"],
                    "messages": result["messages"][-20:],
                }, False
        except (ValueError, TypeError, KeyError) as exc:
            return {"ok": False, "error": str(exc)[:180]}, True
        return {"ok": False, "error": "unknown_communication_tool"}, True
