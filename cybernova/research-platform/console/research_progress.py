"""Session observation and model-declared research state.

Architecture:
  - The model decides phase, sub-goals, hypotheses and findings.
  - Runtime records verifiable observations (tool outcomes, errors, usage,
    last page origin from tool results) and stores model-declared state when the
    model explicitly updates it.
  - Tool *names* never imply research meaning: browser_snapshot is not
    "investigation", browser_click is not "goal achieved".

Operational context (model prompt), this store, EvidenceJournal proofs and the
technical timeline are separate layers; this module must not merge them.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import re
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

MAX_SESSIONS = 64
MAX_LABEL = 80
# Model-declared phases only — Runtime never assigns these from tool names.
MODEL_PHASES = frozenset({
    "explore", "act", "verify", "blocked", "done", "unknown",
})

_SAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_OBSERVATION_ERRORS = frozenset({
    "browser_target_stale", "browser_stale_element_ref", "browser_action_timeout",
    "browser_access_limited", "tool_not_registered", "tool_not_exposed_in_this_round",
    "tool_denied_by_policy", "tool_backend_unsupported", "tool_unavailable",
})


def _page_location(value: str) -> tuple[str, bytes]:
    """Retain the origin and an internal page fingerprint for the page count."""
    try:
        parsed = urlsplit(value)
        scheme, host, port = parsed.scheme, parsed.hostname or "", parsed.port
    except ValueError:
        return "", b""
    if scheme not in {"http", "https"} or not re.fullmatch(r"[a-z0-9.:-]{1,253}", host):
        return "", b""
    hostname = f"[{host}]" if ":" in host else host
    origin = f"{scheme}://{hostname}"
    if port is not None and port != (443 if scheme == "https" else 80):
        origin += f":{port}"
    page_key = hashlib.sha256((origin + (parsed.path or "/")).encode("utf-8", "replace")).digest()
    return origin, page_key


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clip(value: Any, limit: int | None = None) -> str:
    text = _SAFE.sub("", str(value or "")).strip()
    if limit is None or len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


@dataclass
class ResearchProgress:
    """Per-session store: observed facts + optional model-declared semantics."""

    session_key: str
    # User task text (trusted input), not inferred from tools.
    goal: str = ""
    current_request: str = ""
    goal_generation: int = 0
    last_browser_check: bool | None = None
    last_browser_check_inconclusive: bool = False
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
    # The existing API field now contains only an origin.
    last_page_url: str = ""
    _last_page_key: bytes = field(default=b"", init=False, repr=False)
    pages_observed: int = 0
    tools_ok: int = 0
    tools_failed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    updated_at: str = field(default_factory=_now)

    def set_goal(self, goal: str) -> None:
        """Record the latest request without guessing a task boundary.

        Within a session, a different request remains a continuation while the
        root goal is open. A completed root goal advances on the next distinct
        request; an explicit new chat uses /api/reset and fresh session state.
        """
        request = _clip(goal)
        if request and (not self.goal or (self.phase == "done" and not self.open_items
                                          and request != self.current_request)):
            self.goal = request
            self.goal_generation += 1
            self.phase = "unknown"
            self.model_summary = ""
            self.open_items.clear()
            self.findings.clear()
            self.hypotheses.clear()
        if request:
            # A browser check belongs to the turn in which it ran, including
            # when the user repeats the same request.
            self.last_browser_check = None
            self.last_browser_check_inconclusive = False
            self.current_request = request
        self.touch()

    def completion_status(self) -> str:
        if self.phase != "done":
            return "not_declared_done"
        if self.open_items:
            return "declared_done_with_open_items"
        if self.last_browser_check_inconclusive:
            return "declared_done_with_inconclusive_browser_check"
        if self.last_browser_check is False:
            return "declared_done_with_unmet_browser_check"
        if self.last_browser_check is True:
            return "declared_done_with_observed_browser_check"
        return "declared_done_without_browser_check"

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
            self.model_summary = _clip(summary)
        if open_items is not None:
            self.open_items = [_clip(x) for x in open_items if _clip(x)]
        if findings is not None:
            self.findings = [_clip(x) for x in findings if _clip(x)]
        if hypotheses is not None:
            self.hypotheses = [_clip(x) for x in hypotheses if _clip(x)]
        if resolve_open:
            drop = {_clip(x) for x in resolve_open}
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
        browser_verified: bool | None = None,
        browser_check_inconclusive: bool = False,
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
            code = (error if isinstance(error, str) and error in _OBSERVATION_ERRORS
                    else "tool_execution_failed")
            self.last_error = code
            self.recent_errors.append(code)
            self.recent_errors = self.recent_errors[-6:]
        if tool == "browser_verify":
            self.last_browser_check_inconclusive = ok is True and browser_check_inconclusive
            self.last_browser_check = (
                browser_verified if ok is True and not self.last_browser_check_inconclusive else None
            )
        elif tool.startswith("browser_") and tool not in {
            "browser_snapshot", "browser_find_controls", "browser_find_text",
            "browser_read_page", "browser_read_table", "browser_screenshot",
            "browser_network_session", "browser_console", "browser_tabs",
        }:
            # A check describes the previously observed state, not future actions.
            self.last_browser_check = None
            self.last_browser_check_inconclusive = False
        if isinstance(page_url, str) and page_url:
            origin, page_key = _page_location(page_url)
            if origin:
                if page_key != self._last_page_key:
                    self.pages_observed += 1
                self.last_page_url = origin
                self._last_page_key = page_key
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
        if self.current_request and self.current_request != self.goal:
            parts.append("current_request=" + self.current_request)
        parts.append("model_phase=" + (self.phase or "unknown"))
        if self.model_summary:
            parts.append("model_summary=" + self.model_summary)
        if self.open_items:
            parts.append("open=[" + "; ".join(self.open_items) + "]")
        if self.findings:
            parts.append("findings=[" + "; ".join(self.findings) + "]")
        if self.hypotheses:
            parts.append("hyp=[" + "; ".join(self.hypotheses) + "]")
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
        return _clip(note)

    def ui_card(self) -> dict:
        """Facts for UI/API — not a simulated chain-of-thought."""
        return {
            "goal": self.goal,
            "current_request": self.current_request,
            "goal_generation": self.goal_generation,
            "completion_status": self.completion_status(),
            "model": {
                "phase": self.phase,
                "summary": self.model_summary,
                "open_items": list(self.open_items),
                "findings": list(self.findings),
                "hypotheses": list(self.hypotheses),
            },
            "observed": {
                "last_tool": self.last_tool,
                "last_tool_ok": self.last_tool_ok,
                "last_browser_check": self.last_browser_check,
                "last_browser_check_inconclusive": self.last_browser_check_inconclusive,
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
