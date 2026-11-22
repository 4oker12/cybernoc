"""Bounded, local-only Cybernova error journal.

Each service writes its own JSONL file (plus two rotations) because Windows
RotatingFileHandler must not be shared by multiple processes. The authenticated
access gateway exports a single merged report. No prompts, cookies, passwords,
tool arguments or response bodies are intentionally recorded.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import threading
import traceback

MAX_FILE_BYTES = 256 * 1024
BACKUP_COUNT = 2
MAX_TEXT = 3000
COMPONENTS = frozenset({
    "supervisor", "console", "tool-mcp", "communication-mcp", "access-gateway"
})
_CONFIGURED = set()
_CONFIG_LOCK = threading.RLock()

# Redact the value, not the failure type, tool name or source line number.
_SECRET = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|access[_-]?token|"
    r"refresh[_-]?token|api[_-]?key|password|passwd|cookie|secret|"
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
        if record.exc_info and record.exc_info[1]:
            exception = record.exc_info[1]
            data["exception_type"] = type(exception).__name__
            data["exception"] = scrub(exception, 600)
            frames = traceback.extract_tb(record.exc_info[2])
            data["frames"] = [
                f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}"
                for frame in frames[-16:]
            ]
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def configure(component: str) -> None:
    """Attach one ERROR-only rotating handler per *process*; no stdout changes."""
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
        handler.setLevel(logging.ERROR)
        handler.setFormatter(JSONLineFormatter(component))
        logging.getLogger().addHandler(handler)
        try:
            os.chmod(handler.baseFilename, 0o600)
        except OSError:
            pass
        _CONFIGURED.add(key)


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
                                           "exception", "frames"}
                            }
                            if item.get("component") != component:
                                continue
                            item["message"] = scrub(item.get("message", ""))
                            if "exception" in item:
                                item["exception"] = scrub(item["exception"], 600)
                            if isinstance(item.get("frames"), list):
                                item["frames"] = [scrub(v, 150) for v in item["frames"][:16]]
                            entries.append(item)
                except OSError:
                    continue  # Active Windows file rotation may move a file.
    entries.sort(key=lambda x: str(x.get("time", "")))
    manifest = {
        "kind": "cybernova-diagnostics",
        "schema_version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(entries),
        "notice": "Inspect before sharing. Logs are best-effort sanitized; not a raw trace.",
    }
    lines = [json.dumps(manifest, ensure_ascii=False)]
    lines.extend(json.dumps(item, ensure_ascii=False) for item in entries)
    result = ("\n".join(lines) + "\n").encode("utf-8")
    # Never allow an oversized journal export to exhaust the gateway response.
    if len(result) > 6_000_000:
        lines = [lines[0]]
        kept = 0
        for entry in reversed(entries):
            encoded = json.dumps(entry, ensure_ascii=False)
            if kept + len(encoded.encode("utf-8")) > 5_000_000:
                break
            lines.append(encoded)
            kept += len(encoded.encode("utf-8")) + 1
        result = ("\n".join(lines) + "\n").encode("utf-8")
    return result
