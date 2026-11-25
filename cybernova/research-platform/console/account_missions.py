"""Durable account-operator mission checkpoints.

Only non-secret operational metadata is persisted. Never store passwords, OTPs,
cookies, payment data, raw page dumps, or complete verification URLs here.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import secrets
import sqlite3
from threading import RLock
from functools import lru_cache
from urllib.parse import urlsplit

try:
    from .communication import _db_path
except ImportError:
    from communication import _db_path

MISSION_STATUSES = frozenset({
    "planned", "running", "waiting_owner", "waiting_external",
    "blocked", "completed", "failed", "cancelled",
})
STEP_STATUSES = frozenset({
    "started", "completed", "waiting_owner", "waiting_external",
    "blocked", "failed", "needs_reconciliation", "skipped",
})
MISSION_ID = re.compile(r"^am_[A-Za-z0-9_-]{16,80}$")
STEP_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|passcode|secret|token|api[_-]?key|"
    r"access[_-]?key|authorization|cookie|otp|verification[_ ]code)"
    r"\s*[:=]\s*[^,\s;]+"
)
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
LONG_PATH_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{36,}(?![A-Za-z0-9_-])")


class AccountMissionError(ValueError):
    pass


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _text(value: str, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise AccountMissionError("invalid_" + field)
    if "\x00" in value:
        raise AccountMissionError("nul_not_allowed")
    return value.strip()


def _safe_text(value: str, field: str, limit: int) -> str:
    value = _text(value, field, limit)
    value = SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + "=[REDACTED]", value)
    value = BEARER.sub("Bearer [REDACTED]", value)
    value = AWS_KEY.sub("[REDACTED AWS KEY]", value)
    return value[:limit]


def _safe_url(value: str | None) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > 2048:
        raise AccountMissionError("invalid_page_url")
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError
        host = parsed.hostname.lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
            raise ValueError
        port = parsed.port
        if port not in (None, 443):
            raise ValueError
        path = LONG_PATH_TOKEN.sub("[REDACTED]", parsed.path[:700])
        # Query strings and fragments are intentionally never persisted:
        # verification links frequently carry bearer-like one-time tokens.
        return "https://" + host + path
    except (ValueError, TypeError):
        raise AccountMissionError("invalid_page_url") from None


class AccountMissionStore:
    """SQLite-backed checkpoints for long-running account setup workflows."""

    def __init__(self, path: str | Path | None = None):
        self.path = (Path(path) if path is not None else _db_path()).expanduser().absolute()
        if self.path.is_symlink():
            raise AccountMissionError("database_path_symlink_forbidden")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = RLock()
        self._setup()

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

    def _setup(self):
        with self._lock, self._connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS account_missions (
                    mission_id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    goal TEXT NOT NULL,
                    success_criteria TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'planned',
                    current_step_key TEXT NOT NULL DEFAULT '',
                    next_action TEXT NOT NULL DEFAULT '',
                    last_safe_url TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS account_mission_steps (
                    mission_id TEXT NOT NULL REFERENCES account_missions(mission_id) ON DELETE CASCADE,
                    step_key TEXT NOT NULL,
                    step_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    next_action TEXT NOT NULL DEFAULT '',
                    safe_url TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(mission_id, step_key)
                );
                CREATE INDEX IF NOT EXISTS account_missions_recent
                    ON account_missions(updated_at DESC);
                CREATE INDEX IF NOT EXISTS account_missions_status
                    ON account_missions(status, updated_at DESC);
                CREATE INDEX IF NOT EXISTS account_mission_steps_order
                    ON account_mission_steps(mission_id, created_at, step_key);
            """)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _mission(row) -> dict:
        return {key: row[key] for key in (
            "mission_id", "service", "goal", "success_criteria", "status",
            "current_step_key", "next_action", "last_safe_url",
            "created_at", "updated_at", "revision",
        )}

    @staticmethod
    def _step(row) -> dict:
        return {key: row[key] for key in (
            "step_key", "step_name", "status", "summary", "next_action",
            "safe_url", "created_at", "updated_at", "revision",
        )}

    def create(self, service: str, goal: str, success_criteria: str = "") -> dict:
        service = _safe_text(service, "service", 120)
        goal = _safe_text(goal, "goal", 2000)
        if not isinstance(success_criteria, str) or len(success_criteria) > 1200:
            raise AccountMissionError("invalid_success_criteria")
        success_criteria = _safe_text(success_criteria or "Complete the requested setup and verify the resulting account state.",
                                      "success_criteria", 1200)
        now = _utc()
        mission_id = "am_" + secrets.token_urlsafe(18)
        with self._lock, self._connection() as db:
            db.execute(
                "INSERT INTO account_missions(mission_id,service,goal,success_criteria,status,"
                "created_at,updated_at) VALUES(?,?,?,?,'planned',?,?)",
                (mission_id, service, goal, success_criteria, now, now),
            )
        return self.get(mission_id)

    def get(self, mission_id: str) -> dict:
        if not isinstance(mission_id, str) or not MISSION_ID.fullmatch(mission_id):
            raise AccountMissionError("invalid_mission_id")
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM account_missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if row is None:
                raise AccountMissionError("mission_not_found")
            steps = db.execute(
                "SELECT * FROM account_mission_steps WHERE mission_id=? "
                "ORDER BY created_at ASC, step_key ASC", (mission_id,)
            ).fetchall()
        result = self._mission(row)
        result["steps"] = [self._step(item) for item in steps]
        result["resume_requires_reconciliation"] = any(
            item["status"] in {"started", "needs_reconciliation"}
            for item in result["steps"]
        )
        return result

    def list(self, status: str | None = None, limit: int = 20) -> list[dict]:
        if status is not None and status not in MISSION_STATUSES:
            raise AccountMissionError("invalid_mission_status")
        if type(limit) is not int or not 1 <= limit <= 50:
            raise AccountMissionError("invalid_limit")
        with self._connection() as db:
            if status:
                rows = db.execute(
                    "SELECT * FROM account_missions WHERE status=? "
                    "ORDER BY updated_at DESC LIMIT ?", (status, limit)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM account_missions ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [self._mission(row) for row in rows]

    def checkpoint(
        self, mission_id: str, step_key: str, step_name: str, step_status: str,
        summary: str, next_action: str = "", page_url: str = "",
        mission_status: str | None = None,
    ) -> dict:
        if not isinstance(mission_id, str) or not MISSION_ID.fullmatch(mission_id):
            raise AccountMissionError("invalid_mission_id")
        if not isinstance(step_key, str) or not STEP_KEY.fullmatch(step_key):
            raise AccountMissionError("invalid_step_key")
        if step_status not in STEP_STATUSES:
            raise AccountMissionError("invalid_step_status")
        if mission_status is not None and mission_status not in MISSION_STATUSES:
            raise AccountMissionError("invalid_mission_status")
        step_name = _safe_text(step_name, "step_name", 160)
        summary = _safe_text(summary, "summary", 1200)
        next_action = _safe_text(next_action, "next_action", 600) if next_action else ""
        safe_url = _safe_url(page_url)
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            mission = db.execute(
                "SELECT status FROM account_missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if mission is None:
                db.rollback()
                raise AccountMissionError("mission_not_found")
            existing = db.execute(
                "SELECT status,created_at FROM account_mission_steps "
                "WHERE mission_id=? AND step_key=?", (mission_id, step_key)
            ).fetchone()
            # A duplicate/replayed "started" event must never downgrade a step
            # already verified as complete.
            if existing and existing["status"] in {"completed", "skipped"} and step_status == "started":
                db.commit()
                return self.get(mission_id)
            created = existing["created_at"] if existing else now
            db.execute(
                "INSERT INTO account_mission_steps(mission_id,step_key,step_name,status,summary,"
                "next_action,safe_url,created_at,updated_at,revision) VALUES(?,?,?,?,?,?,?,?,?,0) "
                "ON CONFLICT(mission_id,step_key) DO UPDATE SET "
                "step_name=excluded.step_name,status=excluded.status,summary=excluded.summary,"
                "next_action=excluded.next_action,safe_url=excluded.safe_url,"
                "updated_at=excluded.updated_at,revision=account_mission_steps.revision+1",
                (mission_id, step_key, step_name, step_status, summary,
                 next_action, safe_url, created, now),
            )
            inferred = {
                "started": "running", "completed": "running",
                "waiting_owner": "waiting_owner", "waiting_external": "waiting_external",
                "blocked": "blocked", "failed": "failed",
                "needs_reconciliation": "blocked", "skipped": "running",
            }[step_status]
            new_status = mission_status or inferred
            db.execute(
                "UPDATE account_missions SET status=?,current_step_key=?,next_action=?,"
                "last_safe_url=?,updated_at=?,revision=revision+1 WHERE mission_id=?",
                (new_status, step_key, next_action, safe_url, now, mission_id),
            )
            db.commit()
        return self.get(mission_id)

    def resume(self, mission_id: str) -> dict:
        if not isinstance(mission_id, str) or not MISSION_ID.fullmatch(mission_id):
            raise AccountMissionError("invalid_mission_id")
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM account_missions WHERE mission_id=?", (mission_id,)
            ).fetchone()
            if row is None:
                db.rollback()
                raise AccountMissionError("mission_not_found")
            if row["status"] not in {"blocked", "waiting_owner", "waiting_external"}:
                db.rollback()
                raise AccountMissionError("mission_not_resumable:" + row["status"])
            db.execute(
                "UPDATE account_missions SET status='running',updated_at=?,revision=revision+1 "
                "WHERE mission_id=?", (_utc(), mission_id)
            )
            db.commit()
        return self.get(mission_id)

    def recover_interrupted(self) -> int:
        """Block running missions and mark in-flight steps for reconciliation.

        Recovery never replays a browser action, registration submit, payment,
        or verification. The next model turn must inspect the current site state.
        """
        now = _utc()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT mission_id FROM account_missions WHERE status='running'"
            ).fetchall()
            for row in rows:
                mission_id = row["mission_id"]
                db.execute(
                    "UPDATE account_mission_steps SET status='needs_reconciliation',"
                    "summary='Process restarted during this step; inspect external state before retrying.',"
                    "next_action='Reopen the saved site/profile and verify whether the prior action completed.',"
                    "updated_at=?,revision=revision+1 WHERE mission_id=? AND status='started'",
                    (now, mission_id),
                )
                db.execute(
                    "UPDATE account_missions SET status='blocked',"
                    "next_action='Process restarted. Reconcile the last in-flight step before continuing.',"
                    "updated_at=?,revision=revision+1 WHERE mission_id=?",
                    (now, mission_id),
                )
            db.commit()
            return len(rows)


@lru_cache(maxsize=1)
def account_mission_store() -> AccountMissionStore:
    """Return the process-wide store bound to the configured communications DB."""
    return AccountMissionStore()
