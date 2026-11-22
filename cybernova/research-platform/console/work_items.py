"""Bounded, durable work-item scheduling for Cybernova collaboration tasks.

No background worker is started here. Each model call requires a browser/UI
step request; SQLite atomically claims items and enforces dependency gates.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import secrets
import sqlite3

try:
    from .collaboration import CollaborationError, CollaborationStore
    from .communication import CommunicationError
except ImportError:
    from collaboration import CollaborationError, CollaborationStore
    from communication import CommunicationError


MAX_ITEMS = 6
MAX_CONCURRENT_ITEMS = 2
MAX_ATTEMPTS = 3
MAX_ITEM_TEXT = 2000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class WorkItemError(ValueError):
    pass


class WorkItemStore:
    """A task-owned DAG and state machine in the existing private SQLite DB."""

    def __init__(self, collaboration: CollaborationStore):
        self.collab = collaboration
        self.comm = collaboration.comm
        with self.comm._lock, self.comm._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS collaboration_work_items (
                    item_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES collaboration_runs(task_id),
                    position INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    instructions TEXT NOT NULL,
                    dependencies_json TEXT NOT NULL DEFAULT '[]',
                    state TEXT NOT NULL DEFAULT 'queued',
                    attempt INTEGER NOT NULL DEFAULT 0,
                    result TEXT NOT NULL DEFAULT '',
                    review TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    blocked_phase TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(task_id,position)
                );
                CREATE INDEX IF NOT EXISTS collaboration_items_by_task
                ON collaboration_work_items(task_id,position);
            """)

    @staticmethod
    def _validate_text(text: object, limit: int) -> str:
        if not isinstance(text, str) or not 1 <= len(text.strip()) <= limit or "\x00" in text:
            raise WorkItemError("invalid_work_item_text")
        return text.strip()

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["depends_on"] = json.loads(result.pop("dependencies_json"))
        return result

    @staticmethod
    def _validate_plan(plan: object) -> list[dict]:
        if not isinstance(plan, list) or not 2 <= len(plan) <= MAX_ITEMS:
            raise WorkItemError("work_plan_size_invalid")
        normalized = []
        for index, item in enumerate(plan):
            if not isinstance(item, dict) or set(item) != {"title", "instructions", "depends_on"}:
                raise WorkItemError("work_plan_schema_invalid")
            title = WorkItemStore._validate_text(item["title"], 120)
            instructions = WorkItemStore._validate_text(item["instructions"], MAX_ITEM_TEXT)
            deps = item["depends_on"]
            if not isinstance(deps, list) or len(deps) > index or any(
                type(value) is not int or value < 0 or value >= index for value in deps
            ) or len(set(deps)) != len(deps):
                raise WorkItemError("work_plan_dependency_invalid")
            normalized.append({"title": title, "instructions": instructions,
                               "depends_on": deps})
        return normalized

    def create_plan(self, task_id: str, plan: object) -> list[dict]:
        items = self._validate_plan(plan)
        self.collab.read(task_id, recover=False)
        now = _now()
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            parent = db.execute(
                "SELECT state,mode FROM collaboration_runs WHERE task_id=?", (task_id,)
            ).fetchone()
            if parent is None or parent["mode"] != "parallel" or parent["state"] != "active":
                raise WorkItemError("work_plan_parent_not_active")
            count = db.execute(
                "SELECT COUNT(*) FROM collaboration_work_items WHERE task_id=?",
                (task_id,),
            ).fetchone()[0]
            if count:
                raise WorkItemError("work_plan_already_created")
            identities = ["wi_" + secrets.token_urlsafe(15) for _ in items]
            for i, item in enumerate(items):
                db.execute(
                    "INSERT INTO collaboration_work_items "
                    "(item_id,task_id,position,title,instructions,dependencies_json,"
                    "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (identities[i], task_id, i, item["title"], item["instructions"],
                     json.dumps([identities[d] for d in item["depends_on"]]),
                     now, now),
                )
            db.commit()
        for i, item in enumerate(items):
            self.comm.append(task_id, "chatgpt", "instruction",
                             "Подзадача " + str(i + 1) + ": " + item["title"] +
                             ". Критерии: " + item["instructions"][:1000])
        return self.list_items(task_id)

    def list_items(self, task_id: str) -> list[dict]:
        self.collab.read(task_id, recover=False)
        with self.comm._connection() as db:
            rows = db.execute(
                "SELECT * FROM collaboration_work_items WHERE task_id=? ORDER BY position",
                (task_id,),
            ).fetchall()
        result = [self._row(row) for row in rows]
        accepted = {item["item_id"] for item in result if item["state"] == "accepted"}
        for item in result:
            item["ready"] = item["state"] in {"queued", "rework"} and all(
                dependency in accepted for dependency in item["depends_on"]
            )
        return result

    def claim(self, task_id: str, item_id: str) -> tuple[dict, str]:
        self.collab.read(task_id, recover=False)
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            parent = db.execute(
                "SELECT state,mode FROM collaboration_runs WHERE task_id=?", (task_id,)
            ).fetchone()
            if not parent or parent["state"] != "active" or parent["mode"] != "parallel":
                raise WorkItemError("work_parent_not_active")
            row = db.execute(
                "SELECT * FROM collaboration_work_items WHERE task_id=? AND item_id=?",
                (task_id, item_id),
            ).fetchone()
            if row is None:
                raise WorkItemError("work_item_not_found")
            item = self._row(row)
            if item["state"] not in {"queued", "rework", "needs_review"}:
                raise WorkItemError("work_item_not_claimable")
            inflight = db.execute(
                "SELECT COUNT(*) FROM collaboration_work_items "
                "WHERE task_id=? AND state IN ('running','reviewing')",
                (task_id,),
            ).fetchone()[0]
            if inflight >= MAX_CONCURRENT_ITEMS:
                raise WorkItemError("work_item_capacity_reached")
            phase = "review" if item["state"] == "needs_review" else "research"
            if phase == "research":
                approved = {
                    r["item_id"] for r in db.execute(
                        "SELECT item_id FROM collaboration_work_items "
                        "WHERE task_id=? AND state='accepted'", (task_id,),
                    )
                }
                if not all(dep in approved for dep in item["depends_on"]):
                    raise WorkItemError("work_item_dependencies_pending")
                if item["attempt"] >= MAX_ATTEMPTS:
                    raise WorkItemError("work_item_retry_limit")
                db.execute(
                    "UPDATE collaboration_work_items SET state='running',"
                    "attempt=attempt+1,updated_at=? WHERE item_id=?",
                    (_now(), item_id),
                )
            else:
                db.execute(
                    "UPDATE collaboration_work_items SET state='reviewing',updated_at=? "
                    "WHERE item_id=?", (_now(), item_id),
                )
            db.commit()
        return self.get_item(task_id, item_id), phase

    def get_item(self, task_id: str, item_id: str) -> dict:
        rows = self.list_items(task_id)
        for item in rows:
            if item["item_id"] == item_id:
                return item
        raise WorkItemError("work_item_not_found")

    def dependency_results(self, task_id: str, item: dict) -> list[dict]:
        by_id = {row["item_id"]: row for row in self.list_items(task_id)}
        return [{"title": by_id[dep]["title"], "result": by_id[dep]["result"][:5000]}
                for dep in item["depends_on"]]

    def complete_research(self, task_id: str, item_id: str, answer: str,
                          *, blocked: bool = False) -> dict:
        answer = self._validate_text(answer, 12000)
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            item = db.execute(
                "SELECT state,title FROM collaboration_work_items "
                "WHERE task_id=? AND item_id=?", (task_id, item_id),
            ).fetchone()
            if item is None or item["state"] != "running":
                raise WorkItemError("work_item_not_running")
            parent = db.execute(
                "SELECT state FROM collaboration_runs WHERE task_id=?", (task_id,)
            ).fetchone()
            state = ("cancelled" if parent is None or parent["state"] == "completed"
                     else "blocked" if blocked else "needs_review")
            db.execute(
                "UPDATE collaboration_work_items SET state=?,result=?,updated_at=? "
                "WHERE item_id=?", (state, answer, _now(), item_id),
            )
            db.commit()
        self.comm.append(task_id, "qwen", "result",
                         "Подзадача «" + item["title"] + "»: " + answer[:10500])
        return self.get_item(task_id, item_id)

    def complete_review(self, task_id: str, item_id: str, decision: str,
                        feedback: str) -> dict:
        if decision not in {"accept", "rework"}:
            raise WorkItemError("work_review_decision_invalid")
        feedback = self._validate_text(feedback, 6000)
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            item = db.execute(
                "SELECT state,title,attempt FROM collaboration_work_items "
                "WHERE task_id=? AND item_id=?", (task_id, item_id),
            ).fetchone()
            if item is None or item["state"] != "reviewing":
                raise WorkItemError("work_item_not_reviewing")
            parent = db.execute(
                "SELECT state FROM collaboration_runs WHERE task_id=?", (task_id,)
            ).fetchone()
            state = ("cancelled" if parent is None or parent["state"] == "completed"
                     else "accepted" if decision == "accept" else
                     "blocked" if item["attempt"] >= MAX_ATTEMPTS else "rework")
            db.execute(
                "UPDATE collaboration_work_items SET state=?,review=?,updated_at=? "
                "WHERE item_id=?", (state, feedback, _now(), item_id),
            )
            db.commit()
        self.comm.append(task_id, "chatgpt", "feedback",
                         "Ревью «" + item["title"] + "»: " + (
                             "принято" if state == "accepted" else "доработка"
                             if state == "rework" else state) + ". " + feedback[:5500])
        return self.get_item(task_id, item_id)

    def fail(self, task_id: str, item_id: str, code: str) -> dict:
        safe = str(code)[:140]
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state FROM collaboration_work_items WHERE task_id=? AND item_id=?",
                (task_id, item_id),
            ).fetchone()
            if row is None:
                raise WorkItemError("work_item_not_found")
            if row["state"] in {"running", "reviewing"}:
                db.execute(
                    "UPDATE collaboration_work_items SET state='blocked',last_error=?,"
                    "blocked_phase=?,updated_at=? WHERE item_id=?",
                    (safe, "review" if row["state"] == "reviewing" else "research",
                     _now(), item_id),
                )
            db.commit()
        self.comm.append(task_id, "controller", "system",
                         "Подзадача остановлена: " + safe)
        return self.get_item(task_id, item_id)

    def retry(self, task_id: str, item_id: str) -> dict:
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            parent = db.execute(
                "SELECT state FROM collaboration_runs WHERE task_id=?", (task_id,)
            ).fetchone()
            if parent is None or parent["state"] not in {"active", "paused"}:
                raise WorkItemError("work_parent_not_resumable")
            item = db.execute(
                "SELECT state,attempt,blocked_phase FROM collaboration_work_items "
                "WHERE task_id=? AND item_id=?", (task_id, item_id),
            ).fetchone()
            if item is None or item["state"] != "blocked" or item["attempt"] >= MAX_ATTEMPTS:
                raise WorkItemError("work_item_retry_not_allowed")
            db.execute(
                "UPDATE collaboration_work_items SET state=?,last_error='',"
                "blocked_phase='',updated_at=? WHERE item_id=?",
                ("needs_review" if item["blocked_phase"] == "review" else "rework",
                 _now(), item_id),
            )
            db.commit()
        self.comm.append(task_id, "human", "decision",
                         "Разрешён новый ограниченный запуск подзадачи.")
        return self.get_item(task_id, item_id)

    def cancel_pending(self, task_id: str) -> int:
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            result = db.execute(
                "UPDATE collaboration_work_items SET state='cancelled',updated_at=? "
                "WHERE task_id=? AND state IN ('queued','rework','needs_review','blocked')",
                (_now(), task_id),
            )
            db.commit()
        return result.rowcount

    def recover_interrupted(self) -> int:
        """Fail closed after a restart; never replay uncertain tool actions."""
        with self.comm._lock, self.comm._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            result = db.execute(
                "UPDATE collaboration_work_items SET state='blocked',"
                "last_error='interrupted_before_commit',"
                "blocked_phase=CASE WHEN state='reviewing' THEN 'review' "
                "ELSE 'research' END,updated_at=? "
                "WHERE state IN ('running','reviewing')",
                (_now(),),
            )
            db.commit()
        return result.rowcount
