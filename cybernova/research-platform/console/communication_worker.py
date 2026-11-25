"""Single-worker durable ChatGPT-feedback -> Qwen continuation.

The worker is started by the Cybernova console (one process). It polls its
local SQLite inbox, claims a task atomically, invokes the existing Qwen agent,
and writes the answer back into the *same* dialog. It cannot wake ChatGPT;
ChatGPT reads it using the Communication MCP or a scheduled check.
"""
from __future__ import annotations

import json
import threading
import time

try:
    from .diagnostics import event as diagnostic_event
except ImportError:
    from diagnostics import event as diagnostic_event

try:
    from .agent import Agent, MCPClient
    from .communication import CommunicationStore
    from .communication_tools import CommunicationToolClient
    from .evidence import EvidenceJournal
    from .traffic_tools import TrafficToolClient
    from .research_scope import ResearchScopeStore
    from .gpt_tool_runtime import runtime as shared_local_tool_runtime
except ImportError:
    from agent import Agent, MCPClient
    from communication import CommunicationStore
    from communication_tools import CommunicationToolClient
    from evidence import EvidenceJournal
    from traffic_tools import TrafficToolClient
    from research_scope import ResearchScopeStore
    from gpt_tool_runtime import runtime as shared_local_tool_runtime


def _history_from_dialog(messages: list[dict]) -> tuple[list[dict], str] | None:
    """Messages are data; last queued ChatGPT instruction becomes user turn."""
    contexts = []
    for message in messages:
        if message["actor"] in {"chatgpt", "human"} and message["kind"] in {
                "instruction", "feedback"}:
            contexts.append({"role": "user", "content":
                             "[" + message["actor"] + "] " + message["body"][:7000]})
        elif message["actor"] == "qwen" and message["kind"] == "result":
            contexts.append({"role": "assistant", "content": message["body"][:11000]})
    if not contexts or contexts[-1]["role"] != "user":
        return None
    return contexts[-17:-1], contexts[-1]["content"]


class CommunicationWorker:
    def __init__(self, store: CommunicationStore, *, agent_factory=None,
                 interval_seconds: float = 5.0, model_factory=None, text_workers: int = 2):
        self.store = store
        self.agent_factory = agent_factory
        self.interval = interval_seconds
        self._stop = threading.Event()
        self._thread = None
        self._text_threads = []
        self.model_factory = model_factory
        self.text_workers = max(0, min(2, text_workers))

    def _agent_for(self, task_id: str):
        if self.agent_factory is not None:
            return self.agent_factory(task_id)
        return Agent(
            ollama=self.model_factory() if self.model_factory else None,
            mcp_factory=lambda: CommunicationToolClient(
                TrafficToolClient(MCPClient(), {},
                                  scope=ResearchScopeStore().load(task_id)),
                self.store, task_id
            ),
            local_tool_runtime=shared_local_tool_runtime,
        )

    def run_once(self, *, text_only=False) -> dict | None:
        task = self.store.claim_queued(text_only=text_only)
        if task is None:
            return None
        task_id = task["task_id"]
        diagnostic_event("background_task_start", mode="researcher")
        started = time.monotonic()
        try:
            dialog = self.store.recent_dialog(task_id, limit=100)
            current = _history_from_dialog(dialog["messages"])
            if current is None:
                self.store.append(task_id, "controller", "system",
                                  "No queued instruction available for Qwen",
                                  status="blocked")
                return {"task_id": task_id, "status": "blocked"}
            history, prompt = current
            options = {"public_get": True, "force_tools": True}
            # Third-party/test agent factories retain their prior run API.
            # The default research agent always receives its persisted scope.
            if self.agent_factory is None:
                options["scope"] = ResearchScopeStore().load(task_id)
                options["session_id"] = task_id
                try:
                    from .profile_settings import ProfileSettingsStore, user_context_for, mode_instructions_for, relevant_memory
                except ImportError:
                    from profile_settings import ProfileSettingsStore, user_context_for, mode_instructions_for, relevant_memory
                profile = ProfileSettingsStore().load()
                options["user_context"] = user_context_for(profile, "researcher")
                options["profile_instructions"] = mode_instructions_for(profile, "researcher")
                options["input_budget"] = profile["researcher"]["input_budget"]
                options["memory_context"] = relevant_memory(profile, prompt)
                if text_only:
                    options.update(tools_enabled=False, force_tools=False, public_get=False, scope={})
            outcome = self._agent_for(task_id).run(history, prompt, **options)
            if not isinstance(outcome, dict):
                raise ValueError("unexpected_agent_output")
            answer = str(outcome.get("answer") or "").strip()[:12000]
            if not answer:
                answer = "Qwen did not produce an answer."
            receipts = EvidenceJournal(self.store).record_tool_events(
                task_id, outcome.get("events") or [],
            )
            needs_approval = bool(outcome.get("approval_requests"))
            # Qwen may have called comm_request_review to mark the task needs_review.
            current_status = self.store.get_task(task_id)["status"]
            new_status = (
                "blocked" if needs_approval or outcome.get("execution_failed") else
                "needs_review" if current_status == "needs_review" else
                "completed"
            )
            result = self.store.append(
                task_id, "qwen", "result", answer, status=new_status,
            )
            if needs_approval:
                self.store.append(
                    task_id, "controller", "system",
                    "Qwen requested a tool requiring further approval; "
                    "inspect the result in the Web UI before proceeding.",
                )
            diagnostic_event("background_task_finished", mode="researcher",
                             status=new_status,
                             duration_ms=round((time.monotonic() - started) * 1000),
                             tool_calls=outcome.get("tool_calls", 0))
            return {"task_id": task_id, "status": new_status,
                    "message_seq": result["seq"],
                    "tool_calls": outcome.get("tool_calls", 0),
                    "receipts": len(receipts)}
        except Exception as exc:
            diagnostic_event("background_task_failed", mode="researcher",
                             status="failed", error_type=type(exc).__name__,
                             duration_ms=round((time.monotonic() - started) * 1000))
            self.store.append(
                task_id, "controller", "system",
                "Qwen worker stopped: " + type(exc).__name__,
                status="blocked",
            )
            return {"task_id": task_id, "status": "blocked",
                    "error": type(exc).__name__}

    def _loop(self, text_only=False) -> None:
        while not self._stop.is_set():
            try:
                self.run_once(text_only=text_only)
            except Exception as exc:
                diagnostic_event("background_worker_failed",
                                 status="failed", error_type=type(exc).__name__)
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        # Fail closed: a prior process might have died after an active tool.
        self.store.recover_interrupted()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="cybernova-communication-worker",
        )
        self._thread.start()
        self._text_threads = [threading.Thread(target=self._loop, args=(True,), daemon=True,
                                               name=f"cybernova-text-worker-{i}")
                              for i in range(self.text_workers)]
        for thread in self._text_threads:
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        for thread in self._text_threads:
            thread.join(timeout=2)
        self._text_threads = []
