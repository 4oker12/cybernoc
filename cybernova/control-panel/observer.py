"""Durable, metadata-only Cybernova Observer; no commands or external requests.

The first collection establishes a baseline without re-broadcasting historical jobs.
Subsequent polls emit monotonically sequenced transitions that consumers can
read with a cursor. No subscriber or ChatGPT wake is executed here.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3
import threading
import time

from ring import Paths, sessions, agent_jobs

TERMINAL_SESSION = {'completed', 'failed', 'stalled'}
TERMINAL_JOB = {'succeeded', 'failed', 'cancelled', 'needs_human'}


class Observer:
    def __init__(self, data_dir: Path):
        if data_dir.is_symlink():
            raise ValueError('Observer directory may not be a symlink')
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not data_dir.is_dir():
            raise ValueError('Invalid Observer directory')
        if os.name == 'posix':
            os.chmod(data_dir, 0o700)
        self.dbfile = data_dir / 'observer.sqlite3'
        if self.dbfile.is_symlink():
            raise ValueError('Observer database may not be a symlink')
        self._mutex = threading.Lock()
        with self._db() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS observed (
                kind TEXT NOT NULL, ref_id TEXT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY(kind, ref_id));
              CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                time TEXT NOT NULL, kind TEXT NOT NULL,
                ref_id TEXT NOT NULL, state TEXT NOT NULL);
              CREATE INDEX IF NOT EXISTS events_seq ON events(seq);
            ''')
        if os.name == 'posix':
            os.chmod(self.dbfile, 0o600)

    def _db(self):
        db = sqlite3.connect(str(self.dbfile), timeout=5)
        db.execute('PRAGMA busy_timeout=5000')
        return db

    def collect(self, paths: Paths):
        """Collect at most one event per observed terminal transition, idempotently."""
        current = [('session', item['id'], item['state']) for item in sessions(paths)]
        current += [('agent', item['id'], item['state']) for item in agent_jobs(paths)]
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with self._mutex, self._db() as db:
            initialized = db.execute('SELECT 1 FROM meta WHERE key=?', ('initialized',)).fetchone() is not None
            if not initialized:
                db.execute('INSERT INTO meta(key,value) VALUES (?,?)', ('initialized', now))
            count = 0
            for kind, ref_id, state in current:
                prev = db.execute('SELECT state FROM observed WHERE kind=? AND ref_id=?',
                                  (kind,ref_id)).fetchone()
                if prev is not None and prev[0] == state:
                    continue
                db.execute('INSERT INTO observed(kind,ref_id,state) VALUES (?,?,?) '
                           'ON CONFLICT(kind,ref_id) DO UPDATE SET state=excluded.state',
                           (kind,ref_id,state))
                terminal = state in (TERMINAL_SESSION if kind=='session' else TERMINAL_JOB)
                if initialized and terminal:
                    key = f'{kind}:{ref_id}:{state}'
                    before = db.total_changes
                    db.execute('INSERT OR IGNORE INTO events(event_key,time,kind,ref_id,state) '
                               'VALUES (?,?,?,?,?)', (key,now,kind,ref_id,state))
                    if db.total_changes > before:
                        count += 1
            db.commit()
        return {'ok': True, 'new_events': count}

    def read(self, after: int = 0, limit: int = 50):
        if type(after) is not int or after < 0 or after > 2**63 - 1:
            raise ValueError('Invalid cursor')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Invalid limit')
        with self._mutex, self._db() as db:
            rows=db.execute('SELECT seq,time,kind,ref_id,state FROM events '
                            'WHERE seq>? ORDER BY seq ASC LIMIT ?', (after,limit)).fetchall()
            latest=db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]
        events=[{'seq':s,'time':t,'kind':k,'id':i,'state':st} for s,t,k,i,st in rows]
        return {'ok': True, 'events': events, 'latest_seq': latest,
                'next_cursor':events[-1]['seq'] if events else after}


def run_observer(observer: Observer, paths: Paths, stop: threading.Event, interval: int=3):
    while not stop.is_set():
        try:
            observer.collect(paths)
        except (OSError, sqlite3.Error, ValueError):
            # The panel remains viewable if its read-only observer cannot poll.
            pass
        stop.wait(interval)