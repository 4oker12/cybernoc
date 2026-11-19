"""Persistent Cybernova communication queue shared by Web UI and MCP.

SQLite is the single source of truth. The database contains short text messages,
event cursors, task status and references to evidence; not scanner raw output.
No network, Ollama, or MCP dependency in this module.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from threading import RLock

ACTORS = frozenset({"human", "chatgpt", "qwen", "controller"})
KINDS = frozenset({"instruction", "feedback", "progress", "result", "request_review", "decision", "system"})
STATES = frozenset({"idle", "queued", "running", "needs_review", "completed", "blocked"})
REF = re.compile(r"^[A-Za-z0-9_./:-]{1,140}$")
ID = re.compile(r"^[a-zA-Z0-9_-]{12,100}$")
MAX_BODY = 12000
MAX_TITLE = 160


class CommunicationError(ValueError):
    pass


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _check_text(value: str, length: int = MAX_BODY) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > length:
        raise CommunicationError("invalid_text_length")
    if "\x00" in value:
        raise CommunicationError("nul_not_allowed")
    return value.strip()


def _refs(values: object) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > 24:
        raise CommunicationError("invalid_evidence_refs")
    if not all(isinstance(x, str) and REF.fullmatch(x) for x in values):
        raise CommunicationError("invalid_evidence_ref")
    return list(dict.fromkeys(values))


def _db_path() -> Path:
    return Path(os.environ.get(
        "CYBERNOVA_COMM_DB",
        str(Path.home() / ".local" / "share" / "cybernova" / "communications.sqlite3"),
    )).expanduser()


class CommunicationStore:
    """Append-only messages, durable tasks, atomic feedback queue and cursors."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else _db_path()
        self.path = self.path.expanduser().absolute()
        self._lock = RLock()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise CommunicationError("database_path_symlink_forbidden")
        self._setup()

    def _connection(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _setup(self) -> None:
        with self._lock:
            with self._connection() as db:
                db.executescript("""
                    PRAGMA journal_mode=WAL;
                    CREATE TABLE IF NOT EXISTS tasks (
                      task_id TEXT PRIMARY KEY,
                      title TEXT NOT NULL,
                      status TEXT NOT NULL DEFAULT 'idle',
                      origin TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      updated_at TEXT NOT NULL,
                      revision INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE IF NOT EXISTS messages (
                      seq INTEGER PRIMARY KEY AUTOINCREMENT,
                      message_id TEXT UNIQUE NOT NULL,
                      task_id TEXT NOT NULL REFERENCES tasks(task_id),
                      actor TEXT NOT NULL,
                      kind TEXT NOT NULL,
                      body TEXT NOT NULL,
                      evidence_refs TEXT NOT NULL DEFAULT '[]',
                      created_at TEXT NOT NULL,
                      event_key TEXT,
                      UNIQUE(task_id,actor,event_key)
                    );
                    CREATE INDEX IF NOT EXISTS messages_by_task
                    ON messages(task_id,seq);
                    CREATE INDEX IF NOT EXISTS tasks_by_update
                    ON tasks(updated_at,task_id);
                """)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _task(row) -> dict:
        return {key: row[key] for key in
                ("task_id", "title", "status", "origin", "created_at", "updated_at", "revision")}

    @staticmethod
    def _message(row) -> dict:
        return {
            "seq": row["seq"], "message_id": row["message_id"],
            "task_id": row["task_id"], "actor": row["actor"],
            "kind": row["kind"], "body": row["body"],
            "evidence_refs": json.loads(row["evidence_refs"]),
            "created_at": row["created_at"],
        }

    def create_task(self, title: str, origin: str = "human") -> dict:
        title = _check_text(title, MAX_TITLE)
        if origin not in ("human", "chatgpt"):
            raise CommunicationError("invalid_task_origin")
        now = _utc()
        task_id = "cn_" + secrets.token_urlsafe(18)
        with self._lock, self._connection() as db:
            db.execute(
                "INSERT INTO tasks(task_id,title,status,origin,created_at,updated_at)"
                " VALUES(?,?,'idle',?,?,?)", (task_id, title, origin, now, now),
            )
        return self.get_task(task_id)

    def get_task(self, task_id: str) -> dict:
        if not isinstance(task_id, str) or not ID.fullmatch(task_id):
            raise CommunicationError("invalid_task_id")
        with self._connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            raise CommunicationError("task_not_found")
        return self._task(row)

    def list_tasks(self, *, status: str | None = None, limit: int = 20) -> list[dict]:
        if status is not None and status not in STATES:
            raise CommunicationError("invalid_status")
        if type(limit) is not int or not 1 <= limit <= 50:
            raise CommunicationError("invalid_limit")
        with self._connection() as db:
            if status:
                rows = db.execute(
                    "SELECT * FROM tasks WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM tasks ORDER BY updated_at DESC LIMIT ?", (limit,),
                ).fetchall()
        return [self._task(row) for row in rows]

    def append(
        self, task_id: str, actor: str, kind: str, body: str, *,
        evidence_refs: list[str] | None = None, event_key: str | None = None,
        status: str | None = None,
    ) -> dict:
        self.get_task(task_id)
        if actor not in ACTORS or kind not in KINDS:
            raise CommunicationError("invalid_actor_or_kind")
        if status is not None and status not in STATES:
            raise CommunicationError("invalid_status")
        if event_key is not None and (not isinstance(event_key, str)
                                      or not ID.fullmatch(event_key)):
            raise CommunicationError("invalid_event_key")
        body = _check_text(body)
        evidence_refs = _refs(evidence_refs)
        now = _utc()
        message_id = "msg_" + secrets.token_urlsafe(18)
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if event_key:
                row = db.execute(
                    "SELECT * FROM messages WHERE task_id=? AND actor=? AND event_key=?",
                    (task_id, actor, event_key),
                ).fetchone()
                if row is not None:
                    db.commit()
                    return self._message(row)
            db.execute(
                "INSERT INTO messages(message_id,task_id,actor,kind,body,"
                "evidence_refs,created_at,event_key) VALUES(?,?,?,?,?,?,?,?)",
                (message_id, task_id, actor, kind, body,
                 json.dumps(evidence_refs), now, event_key),
            )
            if status is not None:
                db.execute(
                    "UPDATE tasks SET status=?,updated_at=?,revision=revision+1 "
                    "WHERE task_id=?", (status, now, task_id),
                )
            else:
                db.execute(
                    "UPDATE tasks SET updated_at=?,revision=revision+1 WHERE task_id=?",
                    (now, task_id),
                )
            row = db.execute(
                "SELECT * FROM messages WHERE message_id=?", (message_id,),
            ).fetchone()
            db.commit()
        return self._message(row)

    def read_dialog(self, task_id: str, *, after: int = 0, limit: int = 30) -> dict:
        task = self.get_task(task_id)
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise CommunicationError("invalid_pagination")
        with self._connection() as db:
            rows = db.execute(
                "SELECT * FROM messages WHERE task_id=? AND seq>? "
                "ORDER BY seq ASC LIMIT ?", (task_id, after, limit),
            ).fetchall()
        return {"task": task, "messages": [self._message(r) for r in rows],
                "next_after": rows[-1]["seq"] if rows else after}

    def events(self, *, after: int = 0, limit: int = 30,
               review_only: bool = False) -> dict:
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise CommunicationError("invalid_pagination")
        with self._connection() as db:
            if review_only:
                rows = db.execute(
                    "SELECT m.* FROM messages m JOIN tasks t ON t.task_id=m.task_id "
                    "WHERE m.seq>? AND m.kind='request_review' "
                    "AND t.status='needs_review' ORDER BY m.seq ASC LIMIT ?",
                    (after, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM messages WHERE seq>? ORDER BY seq ASC LIMIT ?",
                    (after, limit),
                ).fetchall()
        return {"messages": [self._message(r) for r in rows],
                "next_after": rows[-1]["seq"] if rows else after}

    def send_feedback(self, task_id: str, text: str, *,
                      event_key: str | None = None) -> dict:
        """ChatGPT posts a message and queues one Qwen continuation."""
        return self.append(task_id, "chatgpt", "feedback", text,
                           event_key=event_key, status="queued")

    def mark_review(self, task_id: str, question: str,
                    evidence_refs: list[str] | None = None) -> dict:
        return self.append(task_id, "qwen", "request_review", question,
                           evidence_refs=evidence_refs, status="needs_review")

    def claim_queued(self) -> dict | None:
        """Atomically lease one queued task; multiple workers cannot claim it."""
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM tasks WHERE status='queued' ORDER BY updated_at ASC LIMIT 1",
            ).fetchone()
            if row is None:
                db.commit()
                return None
            changed = db.execute(
                "UPDATE tasks SET status='running',updated_at=?,revision=revision+1 "
                "WHERE task_id=? AND status='queued'",
                (_utc(), row["task_id"]),
            ).rowcount
            db.commit()
            if changed != 1:
                return None
        return self.get_task(row["task_id"])

    def recover_interrupted(self) -> int:
        """Mark orphaned in-flight tasks blocked after a process restart.

        Never automatically replay a partially executed security operation.
        The user can explicitly queue a fresh safe continuation.
        Call only during single-instance startup, before accepting new jobs.
        """
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT task_id FROM tasks WHERE status='running'"
            ).fetchall()
            for row in rows:
                task_id = row["task_id"]
                db.execute(
                    "UPDATE tasks SET status='blocked', updated_at=?, "
                    "revision=revision+1 WHERE task_id=? AND status='running'",
                    (now, task_id),
                )
                db.execute(
                    "INSERT INTO messages (message_id, task_id, actor, kind, "
                    "body, evidence_refs, created_at, event_key) "
                    "VALUES(?,?,'controller','system',?,'[]',?,NULL)",
                    (
                        "msg_" + secrets.token_urlsafe(18), task_id,
                        "Research was interrupted before completion. "
                        "State is blocked; review evidence and explicitly resume.",
                        now,
                    ),
                )
            db.commit()
            return len(rows)

    def set_state(self, task_id: str, status: str) -> dict:
        if status not in STATES:
            raise CommunicationError("invalid_status")
        self.get_task(task_id)
        with self._lock, self._connection() as db:
            db.execute(
                "UPDATE tasks SET status=?,updated_at=?,revision=revision+1 "
                "WHERE task_id=?", (status, _utc(), task_id),
            )
        return self.get_task(task_id)
