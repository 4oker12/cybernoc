"""Local Cybernova SQLite evidence-free case store.

Only sanitized observations and SHA-256 artifact references are persisted here.
Raw tokens, cookies, request/response bodies and PII are not accepted.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
import uuid

STATUSES = {"observation", "hypothesis", "verified", "rejected"}
HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
IDENT = re.compile(r"^[a-zA-Z0-9_.-]{1,96}$")

def utc_now():
    return datetime.now(timezone.utc).isoformat()

class CaseStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.init_db()

    def connect(self):
        con = sqlite3.connect(self.path, timeout=5)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def init_db(self):
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    state TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    evidence_sha256 TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    reviewed_by TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    item_id TEXT,
                    details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS findings_updated_idx
                    ON findings(updated_at DESC);
            """)

    def log(self, action: str, status: str, item_id: str = "", details: str = ""):
        if not (IDENT.fullmatch(action) and IDENT.fullmatch(status)):
            raise ValueError("Invalid audit event")
        # Never pass raw tool arguments or responses here.
        with self.connect() as db:
            db.execute("INSERT INTO events(timestamp,action,status,item_id,details) VALUES(?,?,?,?,?)",
                (utc_now(), action, status, item_id[:96], details[:180]))

    def add_finding(self, title: str, asset: str, summary: str,
                    state: str, confidence: str):
        if state not in ("observation", "hypothesis"):
            raise ValueError("New findings must begin as observation or hypothesis")
        if confidence not in ("low", "medium", "high"):
            raise ValueError("Invalid confidence")
        if not 5 <= len(title.strip()) <= 180 or not 5 <= len(summary.strip()) <= 1200:
            raise ValueError("Title or summary length invalid")
        if not 3 <= len(asset) <= 300:
            raise ValueError("Asset label length invalid")
        fid = "F-" + uuid.uuid4().hex[:12].upper()
        now = utc_now()
        with self.connect() as db:
            db.execute("""INSERT INTO findings(id,title,asset,summary,state,confidence,
                        created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)""",
                       (fid,title.strip(),asset.strip(),summary.strip(),state,confidence,now,now))
        self.log("finding_create", "recorded", fid)
        return fid

    def review_finding(self, fid: str, state: str, reviewer: str,
                       digest: str | None = None):
        if state not in {"verified", "rejected"}:
            raise ValueError("Review state must be verified or rejected")
        if not isinstance(fid, str) or not re.fullmatch(r"F-[A-Z0-9]{12}", fid):
            raise ValueError("Invalid finding ID")
        if not isinstance(reviewer, str) or not re.fullmatch(r"[A-Za-z0-9 _.@-]{3,90}", reviewer):
            raise ValueError("Reviewer required")
        if state == "verified" and (not digest or not HEX64.fullmatch(digest)):
            raise ValueError("Verified finding requires SHA-256 evidence hash")
        if digest is not None and not HEX64.fullmatch(digest):
            raise ValueError("Malformed evidence SHA-256")
        with self.connect() as db:
            prior=db.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
            if not prior:
                raise KeyError("Finding not found")
            if prior["state"] in ("verified","rejected"):
                raise ValueError("Finding already reviewed; create a new retest record")
            db.execute("""UPDATE findings SET state=?, reviewed_by=?,
                     evidence_sha256=?, updated_at=? WHERE id=?""",
                     (state,reviewer,digest,utc_now(),fid))
        self.log("finding_verify", "reviewed", fid)
        return fid

    def list_findings(self, limit=100):
        with self.connect() as db:
            rows=db.execute("""SELECT id,title,asset,summary,state,confidence,
                     evidence_sha256,created_at,updated_at,reviewed_by
                     FROM findings ORDER BY updated_at DESC LIMIT ?""",
                     (max(1,min(int(limit),100)),)).fetchall()
            return [dict(r) for r in rows]

    def list_events(self, limit=100):
        with self.connect() as db:
            rows=db.execute("""SELECT timestamp,action,status,item_id,details
                               FROM events ORDER BY id DESC LIMIT ?""",
                               (max(1,min(int(limit),100)),)).fetchall()
            return [dict(r) for r in rows]
