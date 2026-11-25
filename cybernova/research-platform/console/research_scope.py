"""User-selected research targets and evidence policy; never hardcode a website.

The model cannot create or expand the profile. Only the authenticated Web UI
calls the scope API. A copy is stored per task in the private SQLite database,
so queued/reopened tasks retain the operator's exact authorized scope.
"""
from __future__ import annotations
from contextlib import contextmanager

import ipaddress
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

try:
    from .communication import _db_path
except ImportError:
    from communication import _db_path

ALLOWED_DETAIL = frozenset({"metadata", "evidence"})
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,250}[a-z0-9])?$")
MAX_TARGETS = 20


def normalize_targets(values: list[str]) -> list[str]:
    if not isinstance(values, list) or len(values) > MAX_TARGETS:
        raise ValueError("targets_invalid")
    result = []
    for raw in values:
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 255:
            raise ValueError("invalid_target")
        host = raw.strip().lower()
        if "://" in host or "/" in host or "@" in host or "*" in host or ":" in host:
            raise ValueError("enter_host_not_url")
        if host.endswith("."):
            host = host[:-1]
        if not HOST_RE.fullmatch(host) or ".." in host:
            raise ValueError("invalid_hostname")
        try:
            ipaddress.ip_address(host)
            # IP targets can be used for explicitly approved scanner plans,
            # but the public browser still requires DNS names and public IP.
        except ValueError:
            if "." not in host or any(part.startswith("-") or part.endswith("-")
                                      for part in host.split(".")):
                raise ValueError("invalid_hostname")
        if host not in result:
            result.append(host)
    return result


def scope_profile(hosts: list[str], detail: str = "evidence") -> dict:
    if detail not in ALLOWED_DETAIL:
        raise ValueError("invalid_capture_detail")
    return {
        "hosts": normalize_targets(hosts),
        "capture_detail": detail,
        "active_actions": "propose_and_confirm",
        "owner_selected": True,
    }


def passive_hosts(profile: dict | None) -> set[str]:
    return set((profile or {}).get("hosts") or [])


class ResearchScopeStore:
    def __init__(self, db_path: str | Path | None = None):
        self.path = Path(db_path) if db_path else _db_path()
        self.path = self.path.expanduser().absolute()
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS research_scopes ("
                "task_id TEXT PRIMARY KEY, profile_json TEXT NOT NULL)"
            )

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        try:
            db.execute("PRAGMA busy_timeout=10000")
            with db:
                yield db
        finally:
            db.close()

    def save(self, task_id: str, profile: dict) -> None:
        validated = scope_profile(profile.get("hosts", []),
                                  profile.get("capture_detail", "evidence"))
        with self._connect() as db:
            db.execute(
                "INSERT INTO research_scopes(task_id,profile_json) VALUES(?,?) "
                "ON CONFLICT(task_id) DO UPDATE SET profile_json=excluded.profile_json",
                (task_id, json.dumps(validated, ensure_ascii=False, sort_keys=True)),
            )

    def load(self, task_id: str) -> dict:
        with self._connect() as db:
            row = db.execute(
                "SELECT profile_json FROM research_scopes WHERE task_id=?",
                (task_id,),
            ).fetchone()
        if row is None:
            return scope_profile([])
        data: Any = json.loads(row[0])
        if not isinstance(data, dict):
            return scope_profile([])
        return scope_profile(data.get("hosts", []), data.get("capture_detail", "evidence"))
