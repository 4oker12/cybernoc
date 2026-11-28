"""Persistent job receipts; never replay a potentially executed action."""
from __future__ import annotations

import hashlib
import json
import time

ACTIVE = ("running", "stopping")


class ChatJobError(ValueError):
    pass


class ChatJobStore:
    def __init__(self, store):
        self.store = store
        with store._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS console_chat_jobs (
                    receipt TEXT PRIMARY KEY, run_id TEXT UNIQUE NOT NULL,
                    fingerprint TEXT NOT NULL, session_id TEXT, task_id TEXT,
                    status TEXT NOT NULL, created_at REAL NOT NULL,
                    updated_at REAL NOT NULL, started_at REAL,
                    progress TEXT, result_meta TEXT, detail TEXT
                );
                CREATE TABLE IF NOT EXISTS console_chat_job_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt TEXT NOT NULL,
                    recorded_at REAL NOT NULL,
                    event_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS console_chat_job_events_receipt
                    ON console_chat_job_events(receipt,seq);
                CREATE INDEX IF NOT EXISTS console_chat_jobs_session
                    ON console_chat_jobs(session_id,status);
                CREATE INDEX IF NOT EXISTS console_chat_jobs_task
                    ON console_chat_jobs(task_id,status);
            """)

    def start(self, payload):
        # Persist only a request fingerprint; dialogue already has its own store.
        fingerprint = hashlib.sha256(json.dumps([
            payload.session_id, payload.message, payload.tool_groups, payload.tools_enabled
        ], ensure_ascii=False).encode()).hexdigest()
        now = time.time()
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM console_chat_jobs WHERE receipt=? OR run_id=?",
                             (payload.receipt, payload.run_id)).fetchone()
            if row:
                if (row["receipt"], row["run_id"], row["fingerprint"]) != (
                        payload.receipt, payload.run_id, fingerprint):
                    raise ChatJobError("chat_receipt_conflict")
                return row["status"], False
            if payload.session_id and db.execute(
                "SELECT 1 FROM console_chat_jobs WHERE session_id=? AND status IN (?,?)",
                (payload.session_id, *ACTIVE)).fetchone():
                raise ChatJobError("chat_session_busy")
            if db.execute("SELECT count(*) FROM console_chat_jobs WHERE status IN (?,?)",
                          ACTIVE).fetchone()[0] >= 4:
                raise ChatJobError("chat_queue_full")
            db.execute("INSERT INTO console_chat_jobs "
                       "(receipt,run_id,fingerprint,session_id,status,created_at,updated_at) "
                       "VALUES(?,?,?,?,'running',?,?)",
                       (payload.receipt,payload.run_id,fingerprint,payload.session_id,now,now))
        return "running", True

    def claim(self, receipt):
        now = time.time()
        with self.store._connection() as db:
            return db.execute("UPDATE console_chat_jobs SET started_at=?,updated_at=? "
                              "WHERE receipt=? AND started_at IS NULL AND status IN (?,?)",
                              (now,now,receipt,*ACTIVE)).rowcount == 1

    def bind(self, receipt, session_id, task_id):
        with self.store._connection() as db:
            db.execute("UPDATE console_chat_jobs SET session_id=?,task_id=?,updated_at=? "
                       "WHERE receipt=? AND status IN (?,?)",
                       (session_id,task_id,time.time(),receipt,*ACTIVE))

    def active_task(self, task_id):
        with self.store._connection() as db:
            return bool(db.execute("SELECT 1 FROM console_chat_jobs WHERE task_id=? AND status IN (?,?)",
                                   (task_id,*ACTIVE)).fetchone())

    def progress(self, receipt, event):
        # The diagnostics sink already sanitizes metadata. Never save raw
        # commands, arguments, screenshots, credentials or model reasoning.
        safe = {k:event[k] for k in ("event","tool","status","round","tool_calls") if k in event}
        timeline = dict(safe)
        for key in ("call_ref", "source", "error_code", "result_code", "duration_ms",
                    "effect", "change_strategy", "attempts_on_state", "is_error", "finish_reason"):
            if key in event:
                timeline[key] = event[key]
        now = time.time()
        with self.store._connection() as db:
            changed = db.execute(
                "UPDATE console_chat_jobs SET progress=?,updated_at=? WHERE receipt=? AND status IN (?,?)",
                (json.dumps(safe),now,receipt,*ACTIVE)).rowcount
            if changed:
                db.execute(
                    "INSERT INTO console_chat_job_events(receipt,recorded_at,event_json) VALUES(?,?,?)",
                    (receipt,now,json.dumps(timeline,ensure_ascii=False)))

    def request_stop(self, receipt):
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM console_chat_jobs WHERE receipt=?", (receipt,)).fetchone()
            if not row:
                raise ChatJobError("chat_result_not_found")
            if row["status"] == "running":
                db.execute("UPDATE console_chat_jobs SET status='stopping',updated_at=? WHERE receipt=?",
                           (time.time(),receipt))
                return "stopping"
            return row["status"]

    def should_stop(self, receipt):
        with self.store._connection() as db:
            row = db.execute("SELECT status FROM console_chat_jobs WHERE receipt=?", (receipt,)).fetchone()
        return row is None or row["status"] != "running"

    def finish(self, receipt, status, outcome=None, detail=None):
        outcome = outcome if isinstance(outcome,dict) else {}
        meta = {k:outcome[k] for k in ("session_id","task_id","event_seq","turn","run_id",
                                     "tool_calls","selected_by","model","stop_reason","error_code")
                if k in outcome and isinstance(outcome[k],(str,int,bool,type(None)))}
        with self.store._connection() as db:
            db.execute("UPDATE console_chat_jobs SET status=?,result_meta=?,detail=?,updated_at=? "
                       "WHERE receipt=? AND status IN (?,?)",
                       (status,json.dumps(meta,ensure_ascii=False),detail,time.time(),receipt,*ACTIVE))

    def read(self, receipt):
        with self.store._connection() as db:
            row = db.execute("SELECT * FROM console_chat_jobs WHERE receipt=?", (receipt,)).fetchone()
            events = db.execute(
                "SELECT seq,recorded_at,event_json FROM console_chat_job_events WHERE receipt=? ORDER BY seq",
                (receipt,)).fetchall()
        if not row:
            return None
        result = {k:row[k] for k in ("status","run_id","session_id","task_id","created_at","updated_at")}
        result["elapsed_seconds"] = max(0,int((time.time() if row["status"] in ACTIVE else row["updated_at"])-row["created_at"]))
        result["timeline"] = [
            {**json.loads(item["event_json"]), "seq": item["seq"], "at": item["recorded_at"]}
            for item in events
        ]
        result["timeline_now"] = time.time() if row["status"] in ACTIVE else row["updated_at"]
        if row["progress"]:
            result["progress"] = json.loads(row["progress"])
        if row["detail"]:
            result["detail"] = row["detail"]
        if row["result_meta"]:
            meta = json.loads(row["result_meta"])
            if meta.get("task_id") and type(meta.get("event_seq")) is int and meta["event_seq"] > 0:
                dialog = self.store.read_dialog(meta["task_id"],after=meta["event_seq"]-1,limit=1)
                messages = dialog["messages"]
                if messages and messages[0]["seq"] == meta["event_seq"]:
                    meta.update(answer=messages[0]["body"],recovered=True)
                    result["result"] = meta
        return result

    def recover_interrupted(self):
        with self.store._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT task_id FROM console_chat_jobs WHERE status IN (?,?)", ACTIVE).fetchall()
            db.execute("UPDATE console_chat_jobs SET status='interrupted',detail=?,updated_at=? WHERE status IN (?,?)",
                       ("backend_restarted_reconcile_before_continue",time.time(),*ACTIVE))
            for row in rows:
                if row["task_id"]:
                    db.execute("UPDATE tasks SET status='blocked',revision=revision+1 WHERE task_id=? AND status='running'",
                               (row["task_id"],))
        return len(rows)
