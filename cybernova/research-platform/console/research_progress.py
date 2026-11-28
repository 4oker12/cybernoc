"""Session observation and model-declared research state.

Architecture:
  - The model decides phase, sub-goals, hypotheses and findings.
  - Runtime records verifiable observations (tool outcomes, errors, usage,
    last page URL from tool results) and stores model-declared state when the
    model explicitly updates it.
  - Tool *names* never imply research meaning: browser_snapshot is not
    "investigation", browser_click is not "goal achieved".

Operational context (model prompt), this store, EvidenceJournal proofs and the
technical timeline are separate layers; this module must not merge them.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from threading import RLock
from typing import Any
import re

MAX_SESSIONS = 64
MAX_LIST = 10
MAX_NOTE_CHARS = 420
MAX_ITEM = 140
MAX_LABEL = 80
# Model-declared phases only — Runtime never assigns these from tool names.
MODEL_PHASES = frozenset({
    "explore", "act", "verify", "blocked", "done", "unknown",
})

_SAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clip(value: Any, limit: int) -> str:
    text = _SAFE.sub("", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


@dataclass
class ResearchProgress:
    """Per-session store: observed facts + optional model-declared semantics."""

    session_key: str
    # User task text (trusted input), not inferred from tools.
    goal: str = ""
    # --- model-declared (only via explicit update) ---
    phase: str = "unknown"
    model_summary: str = ""
    open_items: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    # --- runtime-observed (facts only) ---
    last_tool: str = ""
    last_tool_ok: bool | None = None
    last_error: str = ""
    recent_errors: list[str] = field(default_factory=list)
    last_page_url: str = ""
    pages_observed: int = 0
    tools_ok: int = 0
    tools_failed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    updated_at: str = field(default_factory=_now)

    def set_goal(self, goal: str) -> None:
        """Record the user task once; does not interpret research stage."""
        if goal and not self.goal:
            self.goal = _clip(goal, 160)
        self.touch()

    def apply_model_update(
        self,
        *,
        phase: str | None = None,
        summary: str | None = None,
        open_items: list[str] | None = None,
        findings: list[str] | None = None,
        hypotheses: list[str] | None = None,
        resolve_open: list[str] | None = None,
    ) -> dict:
        """Apply fields explicitly declared by the model. Runtime does not invent them."""
        if phase is not None:
            key = str(phase).strip().lower()
            if key not in MODEL_PHASES:
                raise ValueError("research_phase_invalid")
            self.phase = key
        if summary is not None:
            self.model_summary = _clip(summary, 200)
        if open_items is not None:
            self.open_items = [_clip(x, MAX_ITEM) for x in open_items if _clip(x, MAX_ITEM)][-MAX_LIST:]
        if findings is not None:
            self.findings = [_clip(x, MAX_ITEM) for x in findings if _clip(x, MAX_ITEM)][-MAX_LIST:]
        if hypotheses is not None:
            self.hypotheses = [_clip(x, MAX_ITEM) for x in hypotheses if _clip(x, MAX_ITEM)][-MAX_LIST:]
        if resolve_open:
            drop = {_clip(x, MAX_ITEM) for x in resolve_open}
            self.open_items = [x for x in self.open_items if x not in drop]
        self.touch()
        return self.ui_card()

    def record_observation(
        self,
        *,
        tool: str = "",
        ok: bool | None = None,
        error: str = "",
        page_url: str = "",
    ) -> None:
        """Record a verifiable tool outcome. Does not set research phase or findings."""
        if tool:
            self.last_tool = _clip(tool, MAX_LABEL)
        if ok is True:
            self.tools_ok += 1
            self.last_tool_ok = True
        elif ok is False:
            self.tools_failed += 1
            self.last_tool_ok = False
            code = _clip(error or tool, MAX_LABEL)
            if code:
                self.last_error = code
                self.recent_errors.append(code)
                self.recent_errors = self.recent_errors[-6:]
        if page_url:
            url = _clip(page_url, 140)
            if url and url != self.last_page_url:
                self.pages_observed += 1
            self.last_page_url = url
        self.touch()

    def record_usage(self, usage: dict | None) -> None:
        if not isinstance(usage, dict):
            return
        for key, attr in (
            ("input_tokens", "input_tokens"),
            ("output_tokens", "output_tokens"),
            ("prompt_tokens", "input_tokens"),
            ("completion_tokens", "output_tokens"),
        ):
            value = usage.get(key)
            if isinstance(value, int) and value >= 0 and value > getattr(self, attr):
                setattr(self, attr, value)
        self.touch()

    def touch(self) -> None:
        self.updated_at = _now()

    def system_note(self) -> str:
        """Bounded note for the model: observed facts + model-declared state only."""
        parts = []
        if self.goal:
            parts.append("goal=" + self.goal)
        # Model-declared block
        parts.append("model_phase=" + (self.phase or "unknown"))
        if self.model_summary:
            parts.append("model_summary=" + self.model_summary)
        if self.open_items:
            parts.append("open=[" + "; ".join(self.open_items[-4:]) + "]")
        if self.findings:
            parts.append("findings=[" + "; ".join(self.findings[-4:]) + "]")
        if self.hypotheses:
            parts.append("hyp=[" + "; ".join(self.hypotheses[-3:]) + "]")
        # Observed block — no semantic interpretation
        obs = [
            f"last_tool={self.last_tool or '-'}",
            f"last_ok={self.last_tool_ok if self.last_tool_ok is not None else '-'}",
            f"pages={self.pages_observed}",
            f"ok={self.tools_ok}",
            f"fail={self.tools_failed}",
            f"in={self.input_tokens}",
            f"out={self.output_tokens}",
        ]
        if self.last_page_url:
            obs.append("url=" + self.last_page_url)
        if self.recent_errors:
            obs.append("errors=[" + "; ".join(self.recent_errors[-3:]) + "]")
        parts.append("observed{" + " ".join(obs) + "}")
        note = " | ".join(parts)
        return _clip(note, MAX_NOTE_CHARS)

    def ui_card(self) -> dict:
        """Facts for UI/API — not a simulated chain-of-thought."""
        return {
            "goal": self.goal,
            "model": {
                "phase": self.phase,
                "summary": self.model_summary,
                "open_items": list(self.open_items[-6:]),
                "findings": list(self.findings[-6:]),
                "hypotheses": list(self.hypotheses[-6:]),
            },
            "observed": {
                "last_tool": self.last_tool,
                "last_tool_ok": self.last_tool_ok,
                "last_error": self.last_error,
                "recent_errors": list(self.recent_errors[-4:]),
                "last_page_url": self.last_page_url,
                "pages_observed": self.pages_observed,
                "tools_ok": self.tools_ok,
                "tools_failed": self.tools_failed,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
            "updated_at": self.updated_at,
            "note": self.system_note(),
        }


class ResearchProgressStore:
    def __init__(self, max_sessions: int = MAX_SESSIONS):
        self._max = max_sessions
        self._items: OrderedDict[str, ResearchProgress] = OrderedDict()
        self._lock = RLock()

    def get(self, session_key: str) -> ResearchProgress:
        key = _clip(session_key, 120) or "default"
        with self._lock:
            item = self._items.get(key)
            if item is None:
                item = ResearchProgress(session_key=key)
                self._items[key] = item
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)
            return item

    def snapshot(self, session_key: str) -> dict | None:
        key = _clip(session_key, 120) or "default"
        with self._lock:
            item = self._items.get(key)
            return item.ui_card() if item is not None else None

    def clear(self, session_key: str) -> None:
        key = _clip(session_key, 120) or "default"
        with self._lock:
            self._items.pop(key, None)


PROGRESS_STORE = ResearchProgressStore()

# Optional tool schema: model declares state; Runtime only stores it.
RESEARCH_STATE_TOOLS = [{
    "name": "research_state_update",
    "description": (
        "Declare or revise the model's research state for this session: phase, "
        "short summary, open items, findings and hypotheses. Runtime stores the "
        "declaration and returns the combined card; it does not infer state from "
        "other tool names. Use when your plan or conclusions change."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "phase": {
                "type": ["string", "null"],
                "enum": ["explore", "act", "verify", "blocked", "done", "unknown", None],
                "description": "Model-declared phase; null leaves phase unchanged",
            },
            "summary": {
                "type": ["string", "null"],
                "description": "Short factual status in the model's own words",
            },
            "open_items": {
                "type": ["array", "null"],
                "items": {"type": "string"},
                "description": "Replace open items list when provided",
            },
            "findings": {
                "type": ["array", "null"],
                "items": {"type": "string"},
                "description": "Replace findings list when provided",
            },
            "hypotheses": {
                "type": ["array", "null"],
                "items": {"type": "string"},
                "description": "Replace hypotheses list when provided",
            },
            "resolve_open": {
                "type": ["array", "null"],
                "items": {"type": "string"},
                "description": "Remove these items from open_items if present",
            },
        },
        "required": ["phase", "summary", "open_items", "findings", "hypotheses", "resolve_open"],
        "additionalProperties": False,
    },
}]
