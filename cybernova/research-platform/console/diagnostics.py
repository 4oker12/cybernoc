"""Bounded, local-only Cybernova error journal.

Each service writes its own JSONL file (plus two rotations) because Windows
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
BOOT_ID = os.urandom(8).hex()
_TIMELINE_STRINGS = frozenset({
    "event", "mode", "module", "stage", "status", "tool", "provider", "model",
    "error_type", "error_code", "method", "session_kind",
})
_TIMELINE_INTS = frozenset({
    "duration_ms", "http_status", "upstream_http_status", "pid", "exit_code",
    "round", "tool_calls", "input_tokens", "output_tokens",
})
_TIMELINE_BOOLS = frozenset({"headless"})
_SAFE_LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,160}")

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
    r"client[_-]?secret|set-cookie)\b\s*[:=]\s*)"
    r"(?:[\"']?)([^\s\"',;\}\]]{2,})"
)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9_.~+/-]{8,}={0,2}")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}")
_URL_QUERY = re.compile(r"(https?://[^\s?\"']+)\?[^\s\"']+")
_PERSONAL = re.compile(r"(?i)(\\Users\\)[^\\\s]+")
_NEWLINES = re.compile(r"[\r\n\x00-\x1f]+")


def scrub(value: object, limit: int = MAX_TEXT) -> str:
    raw = str(value)
    raw = _URL_QUERY.sub(r"\1?[QUERY-REDACTED]", raw)
    # Remove full bearer/basic credentials *before* generic key=value masking.
    raw = _BEARER.sub(r"\1 [REDACTED]", raw)
    raw = _SECRET.sub(r"\1[REDACTED]", raw)
    raw = _OPENAI_KEY.sub("[REDACTED-API-KEY]", raw)
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
        }
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
        if isinstance(raw, str) and _SAFE_LABEL.fullmatch(raw):
            result[key] = raw
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
    return result if "event" in result else None


def event(name: str, **fields) -> None:
    """Single privacy-controlled timeline event, correlated with the active chat turn."""
    try:
        data = {"event": name, "boot_id": BOOT_ID, **fields}
        run_id = RUN_CONTEXT.get()
        if isinstance(run_id, str):
            data["run_id"] = run_id
        clean = _clean_timeline(data)
        if clean is not None:
            TIMELINE_LOG.info("event %s", clean["event"], extra={"timeline": clean})
    except Exception:
        pass  # Diagnostics must never affect tool execution.


@contextmanager
def span(name: str, **fields):
    """Duration/status without leaking exception messages or tool payloads."""
    started = time.monotonic()
    event(name + "_start", **fields)
    try:
        yield
    except BaseException as exc:
        event(name + "_failure", **fields, duration_ms=round((time.monotonic() - started) * 1000),
              error_type=type(exc).__name__)
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
    for key in (*_CHAT_TOKEN_FIELDS, "duration_ms", "tool_errors", "http_status", "upstream_http_status"):
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
            token = RUN_CONTEXT.set(run_id if isinstance(run_id, str) else None)
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
                    status = "failed" if error is not None else "partial" if partial else "completed"
                    root, code = _chat_error(error) if error is not None else (None, result.get("error_code"))
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
                                              "SIWCError" if partial else None),
                                  error_code=code, upstream_http_status=upstream,
                                  http_status=getattr(error, "status_code", 500) if error else 200)
                    events = result.get("tool_events", result.get("events", []))
                    if isinstance(events, list):
                        fields["tool_errors"] = sum(
                            event.get("is_error") is True for event in events if isinstance(event, dict)
                        ) if result else None
                    fields["usage_complete"] = usage.get("complete")
                    for key in _CHAT_TOKEN_FIELDS:
                        value = usage.get(key)
                        fields[key] = value if type(value) is int and value >= 0 else None
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
                    RUN_CONTEXT.reset(token)
        wrapped.__signature__ = signature(func, eval_str=True)
        return wrapped
    return decorate


def export_jsonl() -> bytes:
    """Merge bounded rotated service logs into a single reviewable text file."""
    folder = journal_dir()
    entries = []
    if folder.is_dir():
        for component in sorted(COMPONENTS):
            for suffix in (".2", ".1", ""):
                path = folder / (component + ".jsonl" + suffix)
                try:
                    if not path.is_file():
                        continue
                    # Max export size remains below the gateway's 7 MB bound.
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
                            # Whitelist fields to prevent untrusted extra data in logs.
                            item = {
                                key: value for key, value in obj.items()
                                if key in {"time", "component", "level", "logger",
                                           "message", "process_id", "exception_type",
                                           "frames", "chat_turn", "timeline"}
                            }
                            if item.get("component") != component:
                                continue
                            item["message"] = scrub(item.get("message", ""))
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
                            entries.append(item)
                except OSError:
                    continue  # Active Windows file rotation may move a file.
    entries.sort(key=lambda x: str(x.get("time", "")))
    manifest = {
        "kind": "cybernova-diagnostics",
        "schema_version": 2,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(entries),
        "truncated": False,
        "dropped_event_count": 0,
        "notice": "Metadata-only best-effort sanitized journal; inspect before sharing.",
    }
    lines = [json.dumps(manifest, ensure_ascii=False)]
    lines.extend(json.dumps(item, ensure_ascii=False) for item in entries)
    result = ("\n".join(lines) + "\n").encode("utf-8")
    # Never allow an oversized journal export to exhaust the gateway response.
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
