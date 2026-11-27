"""Bounded, local-only Cybernova error journal.

Each service writes its own JSONL file (plus three rotations) because Windows
RotatingFileHandler must not be shared by multiple processes. The authenticated
access gateway exports a single merged report. No prompts, cookies, passwords,
tool arguments or response bodies are intentionally recorded.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextvars import ContextVar
from functools import wraps
from contextlib import contextmanager
from inspect import signature
import time
import json
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import threading
import traceback

CHAT_LOG = logging.getLogger("cybernova.chat_turn")
CHAT_LOG.setLevel(logging.INFO)
CHAT_LOG.addHandler(logging.NullHandler())
TIMELINE_LOG = logging.getLogger("cybernova.timeline")
TIMELINE_LOG.setLevel(logging.INFO)
TIMELINE_LOG.addHandler(logging.NullHandler())
RUN_CONTEXT = ContextVar("cybernova_diagnostic_run", default=None)
CHAT_PROGRESS_SINK = ContextVar("cybernova_chat_progress_sink", default=None)
SESSION_CONTEXT = ContextVar("cybernova_diagnostic_session", default=None)
TASK_CONTEXT = ContextVar("cybernova_diagnostic_task", default=None)
AGENT_CONTEXT = ContextVar("cybernova_diagnostic_agent", default=None)
MODE_CONTEXT = ContextVar("cybernova_diagnostic_mode", default=None)
BOOT_ID = os.urandom(8).hex()
_TIMELINE_KINDS = frozenset({"action", "approval", "error", "model", "session"})
_TIMELINE_STRINGS = frozenset({
    "event", "kind", "mode", "module", "stage", "status", "tool", "provider", "model",
    "error_type", "error_code", "method", "session_kind", "backend", "preferred_backend", "fallback_reason", "agent", "source",
    "tool_group", "target_host", "resource_type", "shell", "operation",
    "decision", "action", "component", "result_code", "input_type",
    "call_ref", "finish_reason", "groups", "source_file", "source_function",
    "handler_file", "handler_function", "dispatch_file", "dispatch_function",
    "args_preview", "result_preview", "result_status",
})
_TIMELINE_INTS = frozenset({
    "duration_ms", "http_status", "upstream_http_status", "pid", "exit_code",
    "round", "tool_calls", "input_tokens", "output_tokens",
    "local_count", "remote_count", "filtered_remote_count", "combined_count",
    "discovered_count", "advertised_count", "omitted_count", "raw_tool_calls", "dropped_tool_calls",
    "source_line",
})
_TIMELINE_BOOLS = frozenset({"headless", "timed_out", "result_ok", "is_error", "verified", "pagination_verified"})
_SAFE_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,160}")
_SAFE_SOURCE_PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]{1,160}")

MAX_FILE_BYTES = 512 * 1024
BACKUP_COUNT = 3
MAX_TEXT = 3000
COMPONENTS = frozenset({
    "supervisor", "console", "tool-mcp", "communication-mcp", "access-gateway"
})
_CONFIGURED = set()
_CONFIG_LOCK = threading.RLock()

# Redact the value, not the failure type, tool name or source line number.
_SECRET = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|access[_-]?token|"
    r"refresh[_-]?token|token|api[_-]?key|password|passwd|cookie|secret|"
    r"client[_-]?secret|set-cookie|otp|verification[_-]?code|card[_-]?number|"
    r"pan|cvv|cvc|security[_-]?code)\b\s*[:=]\s*)"
    r"(?:[\"']?)([^\s\"',;\}\]]{2,})"
)
_CARD_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:card[_-]?number|pan|cvv|cvc|security[_-]?code)\b\s*[:=]\s*)"
    r"(?:[\"']?)([^\"',;\}\]]{2,})"
)
_CARD_NUMBER = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9_.~+/-]{8,}={0,2}")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}")
_URL_QUERY = re.compile(r"(https?://[^\s?\"']+)\?[^\s\"']+")
_PERSONAL = re.compile(r"(?i)(\\Users\\)[^\\\s]+")
_NEWLINES = re.compile(r"[\r\n\x00-\x1f]+")


def scrub(value: object, limit: int = MAX_TEXT) -> str:
    raw = str(value)
    raw = _URL_QUERY.sub(r"\1?[QUERY-REDACTED]", raw)
    raw = _CARD_ASSIGNMENT.sub(r"\1[REDACTED]", raw)
    raw = _CARD_NUMBER.sub("[REDACTED-CARD]", raw)
    raw = _BEARER.sub(r"\1 [REDACTED]", raw)
    raw = _SECRET.sub(r"\1[REDACTED]", raw)
    raw = _OPENAI_KEY.sub("[REDACTED-API-KEY]", raw)
    raw = _AWS_KEY.sub("[REDACTED-AWS-KEY]", raw)
    raw = _JWT.sub("[REDACTED-JWT]", raw)
    raw = _EMAIL.sub("[REDACTED-EMAIL]", raw)
    raw = _PERSONAL.sub(r"\1[USER]", raw)
    return _NEWLINES.sub(" ", raw)[:limit]


def journal_dir() -> Path:
    configured = os.environ.get("CYBERNOVA_DIAGNOSTICS_DIR")
    if configured:
        return Path(configured).expanduser()
    db = os.environ.get("CYBERNOVA_COMM_DB")
    if db:
        return Path(db).expanduser().parent / "diagnostics"
    if os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "CyberNova" / "data" / "diagnostics"
    return Path.home() / ".cybernova" / "diagnostics"


def diagnostic_ref(kind: str, value: str | None) -> str | None:
    """Stable one-way reference for a private session/task identifier."""
    if not isinstance(kind, str) or not _SAFE_LABEL.fullmatch(kind):
        return None
    if not isinstance(value, str) or not value:
        return None
    return hashlib.sha256(("cybernova:" + kind + ":" + value).encode("utf-8")).hexdigest()[:16]


def _safe_context_label(value):
    return value if isinstance(value, str) and _SAFE_LABEL.fullmatch(value) else None


def _trace_fields() -> dict:
    result = {}
    run_id = RUN_CONTEXT.get()
    if isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{16,32}", run_id):
        result["run_id"] = run_id
    for key, value in (
        ("session_ref", SESSION_CONTEXT.get()),
        ("task_ref", TASK_CONTEXT.get()),
        ("agent", AGENT_CONTEXT.get()),
        ("mode", MODE_CONTEXT.get()),
    ):
        if isinstance(value, str) and _SAFE_LABEL.fullmatch(value):
            result[key] = value
    return result


def _clean_trace(value):
    if not isinstance(value, dict):
        return None
    result = {}
    run_id = value.get("run_id")
    if isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{16,32}", run_id):
        result["run_id"] = run_id
    for key in ("session_ref", "task_ref"):
        raw = value.get(key)
        if isinstance(raw, str) and re.fullmatch(r"[0-9a-f]{16}", raw):
            result[key] = raw
    for key in ("agent", "mode"):
        raw = value.get(key)
        if isinstance(raw, str) and _SAFE_LABEL.fullmatch(raw):
            result[key] = raw
    return result or None


def set_context(*, session_id=None, task_id=None, agent=None, mode=None) -> None:
    """Bind safe correlation metadata until the enclosing chat turn exits."""
    if session_id is not None:
        SESSION_CONTEXT.set(diagnostic_ref("session", session_id))
    if task_id is not None:
        TASK_CONTEXT.set(diagnostic_ref("task", task_id))
    if agent is not None:
        AGENT_CONTEXT.set(_safe_context_label(agent))
    if mode is not None:
        MODE_CONTEXT.set(_safe_context_label(mode))


@contextmanager
def diagnostic_context(*, run_id=None, session_id=None, task_id=None, agent=None, mode=None):
    """Temporarily bind run/session/task metadata across nested and copied contexts."""
    tokens = []
    values = (
        (RUN_CONTEXT, run_id),
        (SESSION_CONTEXT, diagnostic_ref("session", session_id) if session_id is not None else None),
        (TASK_CONTEXT, diagnostic_ref("task", task_id) if task_id is not None else None),
        (AGENT_CONTEXT, _safe_context_label(agent) if agent is not None else None),
        (MODE_CONTEXT, _safe_context_label(mode) if mode is not None else None),
    )
    for variable, value in values:
        if value is not None:
            tokens.append((variable, variable.set(value)))
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def _source_location() -> dict:
    """Return a repository-relative callsite; never export absolute user paths."""
    frame = inspect.currentframe()
    try:
        frame = frame.f_back
        while frame is not None and frame.f_globals.get("__name__") == __name__:
            frame = frame.f_back
        if frame is None:
            return {}
        raw = str(frame.f_code.co_filename).replace("\\\\", "/").replace("\\", "/")
        marker = "/research-platform/"
        source_file = raw.rsplit(marker, 1)[-1] if marker in raw else raw.rsplit("/", 1)[-1]
        if not _SAFE_SOURCE_PATH.fullmatch(source_file):
            source_file = raw.rsplit("/", 1)[-1]
        function = frame.f_code.co_name
        if not _SAFE_LABEL.fullmatch(function):
            function = "unknown"
        return {"source_file": source_file, "source_function": function,
                "source_line": frame.f_lineno}
    except Exception:
        return {}
    finally:
        del frame


def _event_kind(name, fields):
    requested = fields.get("kind")
    if requested in _TIMELINE_KINDS:
        return requested
    if fields.get("status") in {"failed", "error", "blocked", "timeout", "denied", "expired"}:
        return "error"
    if isinstance(name, str) and name.startswith(("approval_", "owner_input_")):
        return "approval"
    if isinstance(name, str) and name.startswith(("session_", "background_task_")):
        return "session"
    if isinstance(name, str) and name.startswith(("chat_", "model_")):
        return "model"
    return "action"


class JSONLineFormatter(logging.Formatter):
    def __init__(self, component: str):
        super().__init__()
        self.component = component

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "component": self.component,
            "level": record.levelname,
            "logger": scrub(record.name, 100),
            "message": scrub(record.getMessage()),
            "process_id": record.process,
            "kind": "error" if record.levelno >= logging.ERROR else
                    "model" if record.name == CHAT_LOG.name else
                    "action" if record.name == TIMELINE_LOG.name else "runtime",
        }
        trace = _clean_trace(_trace_fields())
        if trace is not None:
            data["trace"] = trace
        if record.name == CHAT_LOG.name and hasattr(record, "chat_turn"):
            data["chat_turn"] = record.chat_turn
        if record.name == TIMELINE_LOG.name and hasattr(record, "timeline"):
            data["timeline"] = record.timeline
        if record.exc_info and record.exc_info[1]:
            exception = record.exc_info[1]
            data["exception_type"] = type(exception).__name__
            # Exception messages can contain arbitrary user or provider payloads.
            frames = traceback.extract_tb(record.exc_info[2])
            data["frames"] = [
                f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}"
                for frame in frames[-16:]
            ]
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def configure(component: str) -> None:
    """Attach one rotating handler per *process*; no stdout changes."""
    if component not in COMPONENTS:
        raise ValueError("unknown_diagnostics_component")
    key = (os.getpid(), component)
    with _CONFIG_LOCK:
        if key in _CONFIGURED:
            return
        folder = journal_dir()
        folder.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            folder / (component + ".jsonl"),
            maxBytes=MAX_FILE_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8",
        )
        handler.setLevel(logging.INFO)
        handler.addFilter(
            lambda r: r.levelno >= logging.ERROR
            or r.name == TIMELINE_LOG.name
            or (component == "console" and r.name == CHAT_LOG.name)
        )
        handler.setFormatter(JSONLineFormatter(component))
        logging.getLogger().addHandler(handler)
        try:
            os.chmod(handler.baseFilename, 0o600)
        except OSError:
            pass
        _CONFIGURED.add(key)


def _clean_timeline(value):
    """Export-allowlisted metadata. Never record prompts, URLs or raw tool arguments."""
    if not isinstance(value, dict):
        return None
    result = {}
    for key in _TIMELINE_STRINGS:
        raw = value.get(key)
        if key in {"args_preview", "result_preview"}:
            if isinstance(raw, str) and raw:
                result[key] = scrub(raw, 1400)
        elif key in {"source_file", "handler_file", "dispatch_file"}:
            if isinstance(raw, str):
                normalized = raw.replace("\\\\", "/").replace("\\", "/")
                if _SAFE_SOURCE_PATH.fullmatch(normalized):
                    result[key] = normalized
        elif isinstance(raw, str) and _SAFE_LABEL.fullmatch(raw):
            result[key] = raw
    # MCP methods have a slash; permit only the known protocol labels.
    method = value.get("method")
    if method in ("initialize", "tools/list", "tools/call", "notifications/initialized", "ping"):
        result["method"] = method
    for key in _TIMELINE_INTS:
        raw = value.get(key)
        if type(raw) is int and -2147483648 <= raw <= 2147483647:
            result[key] = raw
    for key in _TIMELINE_BOOLS:
        raw = value.get(key)
        if type(raw) is bool:
            result[key] = raw
    for key in ("run_id", "boot_id"):
        raw = value.get(key)
        if isinstance(raw, str) and re.fullmatch(r"[0-9a-f]{16,32}", raw):
            result[key] = raw
    for key in ("session_ref", "task_ref"):
        raw = value.get(key)
        if isinstance(raw, str) and re.fullmatch(r"[0-9a-f]{16}", raw):
            result[key] = raw
    detail = value.get("error_detail")
    if isinstance(detail, str) and detail:
        result["error_detail"] = scrub(detail, 420)
    return result if "event" in result else None


def event(name: str, **fields) -> None:
    """Write one allowlisted metadata event with private IDs hashed before storage."""
    try:
        if not isinstance(name, str) or not _SAFE_LABEL.fullmatch(name):
            return
        supplied = dict(fields)
        session_id = supplied.pop("session_id", None)
        task_id = supplied.pop("task_id", None)
        if session_id is not None:
            supplied.setdefault("session_ref", diagnostic_ref("session", session_id))
        if task_id is not None:
            supplied.setdefault("task_ref", diagnostic_ref("task", task_id))
        supplied.setdefault("kind", _event_kind(name, supplied))
        data = {"event": name, "boot_id": BOOT_ID, **_source_location(), **supplied, **_trace_fields()}
        clean = _clean_timeline(data)
        if clean is not None:
            TIMELINE_LOG.info("event %s", clean["event"], extra={"timeline": clean})
            sink = CHAT_PROGRESS_SINK.get()
            if sink is not None:
                sink(clean)
    except Exception:
        pass  # Diagnostics must never affect tool execution.


def tool_outcome(result, failed=False):
    """Distinguish transport completion, task waiting, and verified tool success."""
    if not isinstance(result, dict):
        return "failed" if failed else "unverified"
    state = result.get("status")
    state = state if isinstance(state, str) else ""
    if state in {"owner_input_required", "human_challenge_required", "waiting_owner",
                 "approval_required", "pending", "waiting", "prepared"}:
        return "waiting"
    if state in {"not_executed", "task_intent_required", "blocked", "denied", "skipped"}:
        return "not_executed"
    if failed or result.get("ok") is False or result.get("success") is False or (
        type(result.get("exit_code")) is int and result["exit_code"] != 0
    ) or state in {"failed", "error", "timeout", "expired"}:
        return "failed"
    if state in {"partial", "incomplete", "unverified", "unknown", "not_verified"}:
        return "partial" if state in {"partial", "incomplete"} else "unverified"
    if result.get("verified") is False or result.get("verification_ok") is False:
        return "unverified"
    if result.get("ok") is True or result.get("success") is True or (
        type(result.get("exit_code")) is int and result["exit_code"] == 0
    ):
        return "ok"
    return "unverified"


def _tool_handler_source(name: str, backend: str) -> dict:
    """Best-known implementation location for the selected local or MCP tool."""
    if backend != "local":
        return {"handler_file": "external/mcp", "handler_function": "MCPClient.call"}
    if name.startswith("browser_"):
        if name in {
            "browser_request_protected_input", "browser_fill_owner_input",
            "browser_generate_and_fill_password", "browser_fill_saved_credential",
            "browser_request_and_fill_payment_card", "browser_submit_payment",
        }:
            return {"handler_file": "console/gpt_tool_runtime.py",
                    "handler_function": "GPTToolRuntime.call"}
        return {"handler_file": "console/browser_control.py",
                "handler_function": "browser_control_call"}
    if name.startswith("computer_"):
        return {"handler_file": "console/computer_control.py",
                "handler_function": "computer_control_call"}
    if name.startswith("terminal_") or name == "safe_terminal":
        return {"handler_file": "console/gpt_tool_runtime.py",
                "handler_function": "_run_terminal"}
    if name in {"google_search", "research_source_open"}:
        return {"handler_file": "console/research_web.py",
                "handler_function": "research_web_call"}
    if name.startswith("github_"):
        if re.search(r"(?:create|update|delete|merge|push|write|remove)", name):
            return {"handler_file": "console/github_write_tools.py",
                    "handler_function": "github_write_call"}
        return {"handler_file": "console/github_tools.py", "handler_function": "github_call"}
    if name.startswith("dev_"):
        return {"handler_file": "console/developer_tools.py", "handler_function": "SOURCE"}
    if name.startswith("account_mission_"):
        return {"handler_file": "console/account_missions.py",
                "handler_function": "AccountMissionStore"}
    if name.startswith("account_vault_"):
        return {"handler_file": "console/account_vault.py", "handler_function": "AccountVault"}
    if name == "owner_request_input":
        return {"handler_file": "console/owner_input.py", "handler_function": "owner_input_broker"}
    return {"handler_file": "console/gpt_tool_runtime.py", "handler_function": "GPTToolRuntime.call"}


def _preview_json(value, limit=1200) -> str:
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        raw = str(value)
    return scrub(raw, limit)


def _tool_result_preview(name: str, result) -> dict:
    """Compact result metadata only; never persist response bodies or page text."""
    if not isinstance(result, dict):
        return {"result_type": type(result).__name__}
    preview = {}
    scalar_keys = (
        "ok", "success", "status", "provider", "fallback_reason", "fallback_error",
        "pagination_verified", "result_count", "source_status", "http_status",
        "exit_code", "timed_out", "duration_ms", "page", "start_index",
        "title", "page_type", "text_chars", "visible_text_chars", "headings_count",
        "links_count", "buttons_count", "matched_count", "count", "verified",
        "verification_ok",
    )
    for key in scalar_keys:
        value = result.get(key)
        if type(value) in {bool, int, float}:
            preview[key] = value
        elif isinstance(value, str) and key in {
            "status", "provider", "fallback_reason", "fallback_error", "title", "page_type"
        }:
            preview[key] = scrub(value, 180)
    for key in ("query", "url"):
        value = result.get(key)
        if isinstance(value, str):
            preview[key] = scrub(value, 240)
    attempts = result.get("fallback_attempts")
    if isinstance(attempts, list):
        preview["fallback_attempts"] = [scrub(item, 120) for item in attempts[:3]]
    rows = result.get("results")
    if isinstance(rows, list):
        compact = []
        for item in rows[:3]:
            if not isinstance(item, dict):
                continue
            entry = {}
            for key in ("title", "domain", "url", "source"):
                value = item.get(key)
                if isinstance(value, str):
                    entry[key] = scrub(value, 180)
            if entry:
                compact.append(entry)
        if compact:
            preview["results_preview"] = compact
    stats = result.get("content_stats")
    if isinstance(stats, dict):
        safe_stats = {str(key): value for key, value in list(stats.items())[:20]
                      if type(value) in {bool, int}}
        if safe_stats:
            preview["content_stats"] = safe_stats
    for key in ("stdout", "stderr", "text", "visible_text", "html", "body", "content"):
        value = result.get(key)
        if isinstance(value, str):
            preview[key + "_chars"] = len(value)
    return preview


def observe_tool_call(name, invoke, *, backend, call_ref=None, args_preview=None):
    """Record a correlated dispatch, safe argument preview, handler location and result summary."""
    ref = call_ref or os.urandom(8).hex()
    started = time.monotonic()
    fields = {
        "tool": name, "call_ref": ref, "backend": backend, "stage": "dispatch",
        "dispatch_file": "console/agent.py",
        "dispatch_function": "Agent._call_registered_tool" if backend == "local" else "Agent._call_mcp",
        **_tool_handler_source(name, backend),
    }
    if args_preview is not None:
        fields["args_preview"] = _preview_json(args_preview, 1000)
    event("agent_tool_dispatch_start", **fields, status="started")
    try:
        result, failed = invoke()
    except BaseException as exc:
        code = adapter_error_code(exc)
        event("agent_tool_dispatch_finish", **fields, status="failed",
              error_type=type(exc).__name__, error_code=code,
              is_error=True, duration_ms=round((time.monotonic() - started) * 1000))
        raise
    outcome = tool_outcome(result, failed)
    fields["status"] = outcome
    fields["is_error"] = bool(failed or outcome == "failed")
    if outcome == "failed":
        fields["error_type"] = "ToolResultError"
    if isinstance(result, dict):
        result_status = result.get("status")
        if isinstance(result_status, str) and _SAFE_LABEL.fullmatch(result_status):
            fields["result_status"] = result_status
        result_ok = result.get("ok", result.get("success"))
        if type(result_ok) is bool:
            fields["result_ok"] = result_ok
        if type(result.get("verified")) is bool:
            fields["verified"] = result["verified"]
        for key in ("exit_code", "http_status"):
            if type(result.get(key)) is int:
                fields[key] = result[key]
        preview = _tool_result_preview(name, result)
        if preview:
            fields["result_preview"] = _preview_json(preview, 1400)
    event("agent_tool_dispatch_finish", **fields,
          duration_ms=round((time.monotonic() - started) * 1000))
    return result, failed


@contextmanager
def span(name: str, **fields):
    """Duration/status without leaking exception messages or tool payloads."""
    started = time.monotonic()
    event(name + "_start", **fields)
    try:
        yield
    except BaseException as exc:
        code = adapter_error_code(exc)
        detail = getattr(exc, "safe_detail", None)
        event(name + "_failure", **fields,
              duration_ms=round((time.monotonic() - started) * 1000),
              error_type=type(exc).__name__, error_code=code, error_detail=detail)
        raise
    else:
        event(name + "_complete", **fields, duration_ms=round((time.monotonic() - started) * 1000))


def failure(component: str, operation: str, exc: BaseException, *,
            error_id: str = "") -> None:
    """Write a structured failure without including user/model payloads."""
    safe_type = type(exc).__name__
    identifier = scrub(error_id, 40) if error_id else "-"
    logging.getLogger("cybernova.failure").error(
        "%s failed error_type=%s error_id=%s",
        scrub(operation, 100), safe_type, identifier,
        exc_info=(type(exc), exc, exc.__traceback__),
    )


_ADAPTER_CODE = re.compile(
    r"(?:gpt|llm|models)_http_[1-5][0-9]{2}|"
    r"gpt_(?:stream_(?:incomplete|too_large)|transport_unavailable|"
    r"response_(?:failed|empty)|reply_too_large|tool_calling_unsupported)|"
    r"llm_(?:transport_(?:URLError|TimeoutError|OSError|ValueError)|"
    r"response_too_large|choices_missing|message_missing)"
)


def adapter_error_code(exc):
    value = exc.args[0] if exc.args else None
    return value if isinstance(value, str) and _ADAPTER_CODE.fullmatch(value) else None


def _chat_error(exc):
    # urllib exceptions may be hidden by a stable adapter error, which may
    # itself be wrapped by an HTTP exception. Keep the first known code.
    chain = set()
    root = exc
    while exc is not None and id(exc) not in chain:
        chain.add(id(exc))
        root = exc
        code = adapter_error_code(exc)
        if code is not None:
            return exc, code
        exc = exc.__cause__ or exc.__context__
    return root, None


_CHAT_TOKEN_FIELDS = ("input_tokens", "output_tokens", "cached_tokens", "total_tokens",
                      "requests", "measured_requests")


def _export_chat_turn(fields):
    if not isinstance(fields, dict):
        return None
    run_id = fields.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        return None
    result = {"run_id": run_id}
    for key in ("session_ref", "task_ref"):
        value = fields.get(key)
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{16}", value):
            result[key] = value
    agent = fields.get("agent")
    if isinstance(agent, str) and _SAFE_LABEL.fullmatch(agent):
        result["agent"] = agent
    for key in (*_CHAT_TOKEN_FIELDS, "duration_ms", "tool_errors", "tool_incomplete", "tool_calls", "http_status", "upstream_http_status"):
        value = fields.get(key)
        result[key] = value if type(value) is int and value >= 0 else None
    for key, limit in (("provider", 80), ("model", 160)):
        value = fields.get(key)
        result[key] = scrub(value, limit) if isinstance(value, str) else None
    for key, allowed in (
        ("mode", ("account_gpt", "researcher")),
        ("status", ("failed", "partial", "completed")),
        ("stage", ("chat_turn", "provider_http", "provider_stream", "provider_transport", "provider_response")),
    ):
        value = fields.get(key)
        result[key] = value if value in allowed else None
    for key, pattern in (("error_type", re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,79}")),
                         ("error_code", _ADAPTER_CODE)):
        value = fields.get(key)
        result[key] = value if isinstance(value, str) and pattern.fullmatch(value) else None
    result["usage_complete"] = fields.get("usage_complete") if type(fields.get("usage_complete")) is bool else None
    return result


def observe_chat(mode, backend, latest_usage):
    """One metadata-only terminal event per chat turn, including partial turns."""
    def decorate(func):
        @wraps(func)
        def wrapped(payload):
            start = time.monotonic()
            result = error = None
            run_id = getattr(payload, "run_id", None)
            context_tokens = [
                (RUN_CONTEXT, RUN_CONTEXT.set(run_id if isinstance(run_id, str) else None)),
                (SESSION_CONTEXT, SESSION_CONTEXT.set(None)),
                (TASK_CONTEXT, TASK_CONTEXT.set(None)),
                (AGENT_CONTEXT, AGENT_CONTEXT.set("deepseek" if mode == "researcher" else "chatgpt")),
                (MODE_CONTEXT, MODE_CONTEXT.set(mode)),
            ]
            event("chat_start", mode=mode)
            try:
                result = func(payload)
                return result
            except Exception as exc:
                error = exc
                raise
            finally:
                try:
                    valid_run_id = re.fullmatch(r"[0-9a-f]{32}", payload.run_id) is not None
                    provider, model = backend(payload)
                    result = result if isinstance(result, dict) else {}
                    progress = latest_usage(payload.run_id) or {}
                    usage = result.get("usage") or progress.get("usage") or {}
                    partial = result.get("source") == "chatgpt_plan_responses_partial"
                    result_code = result.get("error_code")
                    handled_provider_failure = (
                        not partial and isinstance(result_code, str)
                        and _ADAPTER_CODE.fullmatch(result_code)
                    )
                    status = ("failed" if error is not None or handled_provider_failure
                              else "partial" if partial else "completed")
                    root, code = (
                        _chat_error(error) if error is not None
                        else (None, result_code if handled_provider_failure else result.get("error_code"))
                    )
                    stage, upstream = "chat_turn", None
                    if isinstance(code, str) and _ADAPTER_CODE.fullmatch(code):
                        if "_http_" in code:
                            stage, upstream = "provider_http", int(code.rsplit("_", 1)[1])
                        elif "_stream_" in code:
                            stage = "provider_stream"
                        elif "_transport_" in code:
                            stage = "provider_transport"
                        else:
                            stage = "provider_response"
                    else:
                        code = None
                    fields = dict(run_id=payload.run_id, mode=mode, provider=scrub(provider, 80),
                                  model=scrub(model, 160), status=status, stage=stage,
                                  duration_ms=round((time.monotonic()-start)*1000),
                                  error_type=(type(root).__name__ if root is not None else
                                              result.get("error_type") if handled_provider_failure else "SIWCError" if partial else None),
                                  error_code=code, upstream_http_status=upstream,
                                  http_status=getattr(error, "status_code", 500) if error else 200)
                    events = result.get("tool_events", result.get("events", []))
                    if isinstance(events, list):
                        fields["tool_errors"] = sum(
                            item.get("is_error") is True or item.get("type") in {
                                "agent_error", "mcp_error", "tool_catalog_error", "tool_selection_error"
                            }
                            for item in events if isinstance(item, dict)
                        ) if result else None
                        fields["tool_incomplete"] = sum(
                            tool_outcome(item.get("result"), item.get("is_error") is True)
                            in {"waiting", "not_executed", "partial", "unverified"}
                            for item in events if isinstance(item, dict) and
                            item.get("type") in {"tool_result", "approved_tool_result",
                                                "scope_change_required", "task_intent_required"}
                        ) if result else None
                    if type(result.get("tool_calls")) is int:
                        fields["tool_calls"] = result["tool_calls"]
                    fields["usage_complete"] = usage.get("complete")
                    for key in _CHAT_TOKEN_FIELDS:
                        value = usage.get(key)
                        fields[key] = value if type(value) is int and value >= 0 else None
                    fields.update(_trace_fields())
                    if valid_run_id:
                        CHAT_LOG.log(logging.INFO if status == "completed" else logging.ERROR,
                                     "chat turn %s", status, extra={"chat_turn": fields})
                    event("chat_finished", mode=mode, status=status,
                          duration_ms=fields["duration_ms"],
                          error_type=fields["error_type"] or "none",
                          error_code=fields["error_code"] or "none")
                except Exception:
                    pass  # A broken journal must not break chat.
                finally:
                    for variable, token in reversed(context_tokens):
                        variable.reset(token)
        wrapped.__signature__ = signature(func, eval_str=True)
        return wrapped
    return decorate


def _matches_export_filters(item, filters):
    if not filters:
        return True
    contexts = [item.get("trace"), item.get("timeline"), item.get("chat_turn")]
    return any(
        isinstance(context, dict)
        and all(context.get(key) == expected for key, expected in filters.items())
        for context in contexts
    )


def export_jsonl(*, run_id=None, session_ref=None, task_ref=None) -> bytes:
    """Merge bounded logs; optional filters isolate one run, session or task."""
    patterns = {
        "run_id": re.compile(r"[0-9a-f]{32}"),
        "session_ref": re.compile(r"[0-9a-f]{16}"),
        "task_ref": re.compile(r"[0-9a-f]{16}"),
    }
    filters = {}
    for key, value in (("run_id", run_id), ("session_ref", session_ref), ("task_ref", task_ref)):
        if value is None:
            continue
        if not isinstance(value, str) or not patterns[key].fullmatch(value):
            raise ValueError("invalid_diagnostics_filter")
        filters[key] = value

    folder = journal_dir()
    entries = []
    if folder.is_dir():
        for component in sorted(COMPONENTS):
            for suffix in (".3", ".2", ".1", ""):
                path = folder / (component + ".jsonl" + suffix)
                try:
                    if not path.is_file():
                        continue
                    with path.open("r", encoding="utf-8", errors="replace") as source:
                        for line in source:
                            if len(line) > 8192:
                                continue
                            try:
                                obj = json.loads(line)
                            except ValueError:
                                continue
                            if not isinstance(obj, dict):
                                continue
                            item = {
                                key: value for key, value in obj.items()
                                if key in {"time", "component", "level", "logger", "message",
                                           "process_id", "exception_type", "frames", "kind",
                                           "trace", "chat_turn", "timeline"}
                            }
                            if item.get("component") != component:
                                continue
                            item["message"] = scrub(item.get("message", ""))
                            if "trace" in item:
                                trace = _clean_trace(item.get("trace"))
                                if trace is None:
                                    item.pop("trace", None)
                                else:
                                    item["trace"] = trace
                            if "chat_turn" in item:
                                chat_turn = _export_chat_turn(item.pop("chat_turn"))
                                if component == "console" and chat_turn is not None:
                                    item["chat_turn"] = chat_turn
                            if "timeline" in item:
                                timeline = _clean_timeline(item.pop("timeline"))
                                if timeline is not None:
                                    item["timeline"] = timeline
                            if isinstance(item.get("frames"), list):
                                item["frames"] = [scrub(v, 150) for v in item["frames"][:16]]
                            if not _matches_export_filters(item, filters):
                                continue
                            entries.append(item)
                except OSError:
                    continue
    entries.sort(key=lambda x: str(x.get("time", "")))
    manifest = {
        "kind": "cybernova-diagnostics",
        "schema_version": 3,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(entries),
        "filters": filters,
        "streams": ["action", "approval", "error", "model", "session"],
        "truncated": False,
        "dropped_event_count": 0,
        "notice": "Metadata-only best-effort sanitized journal; inspect before sharing.",
    }
    lines = [json.dumps(manifest, ensure_ascii=False)]
    lines.extend(json.dumps(item, ensure_ascii=False) for item in entries)
    result = ("\n".join(lines) + "\n").encode("utf-8")
    if len(result) > 6_000_000:
        selected = []
        kept = 0
        for entry in reversed(entries):
            encoded = json.dumps(entry, ensure_ascii=False)
            size = len(encoded.encode("utf-8")) + 1
            if kept + size > 5_000_000:
                break
            selected.append(encoded)
            kept += size
        manifest["event_count"] = len(selected)
        manifest["truncated"] = True
        manifest["dropped_event_count"] = len(entries) - len(selected)
        result = ("\n".join([json.dumps(manifest, ensure_ascii=False), *reversed(selected)]) + "\n").encode("utf-8")
    return result
