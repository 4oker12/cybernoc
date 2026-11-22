"""Durable, single-user GPT conversations, separate from Qwen research tasks.

Shares the already-backed-up Communications SQLite file but uses isolated
tables. This module makes no network calls and never forwards to MCP/Qwen.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from threading import RLock

try:
    from .communication import _db_path
except ImportError:
    from communication import _db_path

ID_PATTERN = re.compile(r"^gpt_[A-Za-z0-9_-]{16,80}$")
MAX_MESSAGE_CHARS = 12000
MAX_CONTEXT_CHARS = 60000
MAX_CONTEXT_MESSAGES = 36


class GPTChatError(ValueError):
    pass


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _validate_id(thread_id: str) -> str:
    if not isinstance(thread_id, str) or not ID_PATTERN.fullmatch(thread_id):
        raise GPTChatError("invalid_gpt_thread_id")
    return thread_id


def _validate_content(content: str, *, limit: int = MAX_MESSAGE_CHARS) -> str:
    if not isinstance(content, str) or not content.strip() or len(content) > limit:
        raise GPTChatError("invalid_gpt_chat_message")
    return content.strip()


class GPTChatStore:
    def __init__(self, path: str | Path | None = None):
        self.path = (Path(path) if path is not None else _db_path()).expanduser().absolute()
        if self.path.is_symlink():
            raise GPTChatError("db_symlink_forbidden")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = RLock()
        with self._connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS gpt_threads (
                    thread_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    model TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gpt_messages (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    thread_id TEXT NOT NULL REFERENCES gpt_threads(thread_id),
                    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS gpt_messages_by_thread
                    ON gpt_messages(thread_id, seq);
                CREATE INDEX IF NOT EXISTS gpt_threads_recent
                    ON gpt_threads(updated_at DESC);
                CREATE TABLE IF NOT EXISTS gpt_tool_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    thread_id TEXT NOT NULL REFERENCES gpt_threads(thread_id),
                    message_seq INTEGER NOT NULL REFERENCES gpt_messages(seq),
                    name TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    is_error INTEGER NOT NULL CHECK(is_error IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS gpt_tool_events_by_thread
                    ON gpt_tool_events(thread_id, event_id);
            """)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=10000")
            with db:
                yield db
        finally:
            db.close()

    def list_threads(self, limit: int = 30) -> list[dict]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT thread_id,title,model,updated_at FROM gpt_threads "
                "ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_thread(self, thread_id: str) -> dict:
        _validate_id(thread_id)
        with self._connection() as db:
            row = db.execute("SELECT * FROM gpt_threads WHERE thread_id=?",
                             (thread_id,)).fetchone()
            if row is None:
                raise GPTChatError("gpt_thread_not_found")
            messages = db.execute(
                "SELECT seq,role,content,created_at FROM gpt_messages "
                "WHERE thread_id=? ORDER BY seq ASC LIMIT 500",
                (thread_id,)
            ).fetchall()
            tool_rows = db.execute(
                "SELECT event_id,message_seq,name,arguments_json,result_json,is_error,created_at "
                "FROM gpt_tool_events WHERE thread_id=? ORDER BY event_id ASC LIMIT 500",
                (thread_id,)
            ).fetchall()
        events = []
        for item in tool_rows:
            try:
                arguments = json.loads(item["arguments_json"])
            except (ValueError, TypeError):
                arguments = {}
            try:
                result = json.loads(item["result_json"])
            except (ValueError, TypeError):
                result = {}
            events.append({
                "event_id": item["event_id"], "message_seq": item["message_seq"],
                "name": item["name"], "arguments": arguments, "result": result,
                "is_error": bool(item["is_error"]), "created_at": item["created_at"],
            })
        return {
            "thread": dict(row), "messages": [dict(x) for x in messages],
            "tool_events": events,
        }

    def context(self, thread_id: str) -> list[dict]:
        _validate_id(thread_id)
        with self._connection() as db:
            present = db.execute(
                "SELECT 1 FROM gpt_threads WHERE thread_id=?", (thread_id,)
            ).fetchone()
            if not present:
                raise GPTChatError("gpt_thread_not_found")
            rows = db.execute(
                "SELECT role,content FROM ("
                "SELECT seq,role,content FROM gpt_messages "
                "WHERE thread_id=? ORDER BY seq DESC LIMIT ?) "
                "ORDER BY seq ASC",
                (thread_id, MAX_CONTEXT_MESSAGES)
            ).fetchall()
        history = []
        used = 0
        for row in reversed(rows):
            content = row["content"]
            if used + len(content) > MAX_CONTEXT_CHARS:
                break
            history.append({"role": row["role"], "content": content})
            used += len(content)
        # Receipts remain in the UI, not in prompts for later turns.
        return list(reversed(history))

    def begin_exchange(self, thread_id: str | None, model: str, user: str) -> tuple[str, int]:
        user = _validate_content(user, limit=10000)
        if not isinstance(model, str) or not 1 <= len(model) <= 160:
            raise GPTChatError("invalid_gpt_model")
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if thread_id is None:
                thread_id = "gpt_" + secrets.token_urlsafe(18)
                db.execute(
                    "INSERT INTO gpt_threads(thread_id,title,model,created_at,updated_at) "
                    "VALUES(?,?,?,?,?)",
                    (thread_id, user[:100], model, now, now)
                )
            else:
                _validate_id(thread_id)
                updated = db.execute(
                    "UPDATE gpt_threads SET model=?,updated_at=? WHERE thread_id=?",
                    (model, now, thread_id)
                )
                if updated.rowcount != 1:
                    raise GPTChatError("gpt_thread_not_found")
            cursor = db.execute(
                "INSERT INTO gpt_messages(thread_id,role,content,created_at) "
                "VALUES(?,?,?,?)",
                (thread_id, "user", user, now)
            )
            return thread_id, int(cursor.lastrowid)

    def finish_exchange(self, thread_id: str, assistant: str) -> int:
        _validate_id(thread_id)
        assistant = _validate_content(assistant)
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            present = db.execute(
                "SELECT 1 FROM gpt_threads WHERE thread_id=?", (thread_id,)
            ).fetchone()
            if not present:
                raise GPTChatError("gpt_thread_not_found")
            cursor = db.execute(
                "INSERT INTO gpt_messages(thread_id,role,content,created_at) "
                "VALUES(?,?,?,?)",
                (thread_id, "assistant", assistant, now)
            )
            db.execute(
                "UPDATE gpt_threads SET updated_at=? WHERE thread_id=?",
                (now, thread_id)
            )
            return int(cursor.lastrowid)

    def save_exchange(self, thread_id: str | None, model: str,
                      user: str, assistant: str) -> str:
        user = _validate_content(user, limit=10000)
        assistant = _validate_content(assistant)
        if not isinstance(model, str) or not 1 <= len(model) <= 160:
            raise GPTChatError("invalid_gpt_model")
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if thread_id is None:
                thread_id = "gpt_" + secrets.token_urlsafe(18)
                db.execute(
                    "INSERT INTO gpt_threads(thread_id,title,model,created_at,updated_at) "
                    "VALUES(?,?,?,?,?)",
                    (thread_id, user[:100], model, now, now)
                )
            else:
                _validate_id(thread_id)
                updated = db.execute(
                    "UPDATE gpt_threads SET model=?,updated_at=? WHERE thread_id=?",
                    (model, now, thread_id)
                )
                if updated.rowcount != 1:
                    raise GPTChatError("gpt_thread_not_found")
            db.executemany(
                "INSERT INTO gpt_messages(thread_id,role,content,created_at) "
                "VALUES(?,?,?,?)",
                [(thread_id, "user", user, now),
                 (thread_id, "assistant", assistant, now)]
            )
        return thread_id

    def save_tool_events(self, thread_id: str, events: list[dict], *,
                         message_seq: int | None = None) -> None:
        _validate_id(thread_id)
        if not isinstance(events, list) or len(events) > 24:
            raise GPTChatError("invalid_gpt_tool_events")
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if message_seq is None:
                row = db.execute(
                    "SELECT seq FROM gpt_messages WHERE thread_id=? AND role='assistant' "
                    "ORDER BY seq DESC LIMIT 1", (thread_id,)
                ).fetchone()
                if row is None:
                    raise GPTChatError("gpt_assistant_message_not_found")
                message_seq = int(row["seq"])
            else:
                row = db.execute(
                    "SELECT seq FROM gpt_messages WHERE thread_id=? AND seq=?",
                    (thread_id, message_seq)
                ).fetchone()
                if row is None:
                    raise GPTChatError("gpt_message_not_found")
            for event in events:
                if not isinstance(event, dict):
                    continue
                name = event.get("name")
                if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", name):
                    continue
                arguments = event.get("arguments")
                result = event.get("result")
                if not isinstance(arguments, dict):
                    arguments = {}
                if not isinstance(result, dict):
                    result = {"value": str(result)[:1000]}
                if name in {"browser_fill", "browser_select"} and "value" in arguments:
                    arguments = {**arguments, "value": "[REDACTED FORM INPUT]"}
                if "url" in arguments and isinstance(arguments["url"], str):
                    arguments = {**arguments, "url": re.sub(r"([?#]).*$", "", arguments["url"])[:1200]}
                args_json = json.dumps(arguments, ensure_ascii=False, default=str)
                result_json = json.dumps(result, ensure_ascii=False, default=str)
                if len(args_json) > 3000:
                    args_json = json.dumps({"truncated": True, "preview": args_json[:2400]}, ensure_ascii=False)
                if len(result_json) > 12000:
                    result_json = json.dumps({"truncated": True, "preview": result_json[:10800]}, ensure_ascii=False)
                db.execute(
                    "INSERT INTO gpt_tool_events(thread_id,message_seq,name,arguments_json,"
                    "result_json,is_error,created_at) VALUES(?,?,?,?,?,?,?)",
                    (thread_id, message_seq, name, args_json, result_json,
                     int(bool(event.get("is_error"))), now),
                )
