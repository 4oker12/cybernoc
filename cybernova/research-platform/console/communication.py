"""Persistent Cybernova communication queue shared by Web UI and MCP.

SQLite is the single source of truth. The database contains short text messages,
event cursors, task status and references to evidence; not scanner raw output.
No network, Ollama, or MCP dependency in this module.
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

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                yield db
        finally:
            db.close()

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
                    CREATE TABLE IF NOT EXISTS provider_continuation_state (
                      task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
                      message_seq INTEGER NOT NULL REFERENCES messages(seq) ON DELETE CASCADE,
                      provider TEXT NOT NULL,
                      model TEXT NOT NULL,
                      endpoint TEXT NOT NULL DEFAULT '',
                      reasoning_content TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      PRIMARY KEY(task_id,message_seq)
                    );
                    CREATE INDEX IF NOT EXISTS provider_state_by_task
                    ON provider_continuation_state(task_id,message_seq);
                    CREATE TABLE IF NOT EXISTS scheduled_text_tasks (
                      task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
                      due_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS scheduled_text_due ON scheduled_text_tasks(due_at);
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
        status: str | None = None, provider_state: dict | None = None,
        require_available: bool = False,
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
        continuation = None
        if provider_state is not None:
            if actor != "qwen" or kind != "result" or not isinstance(provider_state, dict):
                raise CommunicationError("invalid_provider_continuation")
            provider = provider_state.get("provider")
            model = provider_state.get("model")
            endpoint = provider_state.get("endpoint", "")
            reasoning = provider_state.get("reasoning_content")
            if (not isinstance(provider, str) or not provider or len(provider) > 80
                    or not isinstance(model, str) or not model or len(model) > 160
                    or not isinstance(endpoint, str) or len(endpoint) > 500
                    or not isinstance(reasoning, str) or len(reasoning) > 1800000
                    or any("\x00" in value for value in (provider, model, endpoint, reasoning))):
                raise CommunicationError("invalid_provider_continuation")
            continuation = (provider, model, endpoint, reasoning)
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
                    if continuation is not None:
                        db.execute(
                            "INSERT INTO provider_continuation_state"
                            "(task_id,message_seq,provider,model,endpoint,reasoning_content,created_at) "
                            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(task_id,message_seq) DO UPDATE SET "
                            "provider=excluded.provider,model=excluded.model,endpoint=excluded.endpoint,"
                            "reasoning_content=excluded.reasoning_content,created_at=excluded.created_at",
                            (task_id, row["seq"], *continuation, now),
                        )
                    db.commit()
                    return self._message(row)
            if require_available:
                current = db.execute("SELECT status FROM tasks WHERE task_id=?", (task_id,)).fetchone()
                if current is None or current["status"] in {"running", "queued"}:
                    raise CommunicationError("task_busy")
            if status == "queued":
                scheduled = db.execute("SELECT t.status FROM tasks t JOIN scheduled_text_tasks s USING(task_id) WHERE t.task_id=?", (task_id,)).fetchone()
                if scheduled is not None and scheduled["status"] in {"running", "queued"}:
                    raise CommunicationError("scheduled_task_busy")
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
            if continuation is not None:
                db.execute(
                    "INSERT INTO provider_continuation_state"
                    "(task_id,message_seq,provider,model,endpoint,reasoning_content,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (task_id, row["seq"], *continuation, now),
                )
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

    def load_provider_continuation(
        self, task_id: str, message_seq: int, provider: str, model: str, endpoint: str,
    ) -> str | None:
        """Load private provider state only for the exact provider/model endpoint."""
        self.get_task(task_id)
        if (type(message_seq) is not int or message_seq < 1
                or not isinstance(provider, str) or not isinstance(model, str)
                or not isinstance(endpoint, str)):
            raise CommunicationError("invalid_provider_continuation_lookup")
        with self._connection() as db:
            row = db.execute(
                "SELECT reasoning_content FROM provider_continuation_state "
                "WHERE task_id=? AND message_seq=? AND provider=? AND model=? AND endpoint=?",
                (task_id, message_seq, provider, model, endpoint),
            ).fetchone()
        return row["reasoning_content"] if row is not None else None

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

    def recent_dialog(self, task_id: str, limit: int = 100) -> dict:
        task = self.get_task(task_id)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise CommunicationError("invalid_pagination")
        with self._connection() as db:
            rows = db.execute("SELECT * FROM messages WHERE task_id=? ORDER BY seq DESC LIMIT ?",
                              (task_id, limit)).fetchall()
        return {"task": task, "messages": [self._message(r) for r in reversed(rows)],
                "next_after": rows[0]["seq"] if rows else 0}

    def schedule_text(self, prompt: str, due_at: str) -> dict:
        prompt = _check_text(prompt, 9000)
        try:
            due = datetime.fromisoformat(due_at.replace("Z", "+00:00"))
            if due.tzinfo is None:
                raise ValueError("timezone required")
            due = due.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        except (ValueError, TypeError, AttributeError):
            raise CommunicationError("invalid_schedule_time") from None
        now = _utc()
        task_id = "cn_" + secrets.token_urlsafe(18)
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            pending = db.execute("SELECT count(*) FROM scheduled_text_tasks s JOIN tasks t USING(task_id) WHERE t.status IN ('queued','running')").fetchone()[0]
            if pending >= 32:
                raise CommunicationError("schedule_queue_full")
            db.execute("INSERT INTO tasks(task_id,title,status,origin,created_at,updated_at) VALUES(?,?,'queued','human',?,?)",
                       (task_id, prompt[:MAX_TITLE], now, now))
            db.execute("INSERT INTO scheduled_text_tasks(task_id,due_at) VALUES(?,?)", (task_id, due))
            db.execute("INSERT INTO messages(message_id,task_id,actor,kind,body,created_at) VALUES(?,?,'human','instruction',?,?)",
                       ("msg_" + secrets.token_urlsafe(18), task_id, prompt, now))
            db.commit()
        return self.get_task(task_id)

    def scheduled_due(self, task_id: str) -> str | None:
        with self._connection() as db:
            row = db.execute("SELECT due_at FROM scheduled_text_tasks WHERE task_id=?", (task_id,)).fetchone()
        return row["due_at"] if row else None

    def cancel_scheduled(self, task_id: str) -> dict:
        self.get_task(task_id)
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE tasks SET status='blocked',updated_at=?,revision=revision+1 WHERE task_id=? AND status='queued' AND EXISTS (SELECT 1 FROM scheduled_text_tasks WHERE task_id=?)",
                                 (_utc(), task_id, task_id)).rowcount
            if changed != 1:
                raise CommunicationError("schedule_not_pending")
            db.execute("INSERT INTO messages(message_id,task_id,actor,kind,body,created_at) VALUES(?,?,'controller','system',?,?)",
                       ("msg_" + secrets.token_urlsafe(18), task_id, "Запланированный запуск отменён пользователем.", _utc()))
            db.commit()
        return self.get_task(task_id)

    def claim_queued(self, *, text_only: bool = False) -> dict | None:
        """Atomically lease one queued task; multiple workers cannot claim it."""
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                ("SELECT t.* FROM tasks t JOIN scheduled_text_tasks s USING(task_id) "
                 "WHERE t.status='queued' AND s.due_at<=? ORDER BY s.due_at,t.created_at LIMIT 1")
                if text_only else
                ("SELECT t.* FROM tasks t WHERE t.status='queued' AND NOT EXISTS "
                 "(SELECT 1 FROM scheduled_text_tasks s WHERE s.task_id=t.task_id) "
                 "ORDER BY t.updated_at ASC LIMIT 1"),
                (_utc(),) if text_only else (),
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
