"""Portable encrypted-backup acceptance tests (no live Vast/database)."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from console.backup import create_key, load_key, backup, verify, restore, BackupError


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.key=self.root/"private_key"
        create_key(self.key)
        self.source=self.root/"sample.sqlite3"
        with sqlite3.connect(self.source) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE tasks(name TEXT PRIMARY KEY)")
            db.execute("INSERT INTO tasks VALUES(?)", ("research-123",))
        self.archive=self.root/"backup.cnbk"

    def test_online_snapshot_restore_and_integrity(self):
        result=backup(self.source,self.archive,key_path=self.key)
        self.assertTrue(self.archive.is_file())
        self.assertTrue(Path(result["manifest"]).is_file())
        self.assertNotIn(b"research-123",self.archive.read_bytes())
        plaintext=verify(self.archive,key_path=self.key)
        self.assertIn(b"SQLite format 3",plaintext[:40])
        destination=self.root/"restored.sqlite3"
        response=restore(self.archive,destination,key_path=self.key)
        self.assertEqual(response["restored_to"],str(destination))
        with sqlite3.connect(destination) as db:
            rows=db.execute("SELECT name FROM tasks").fetchall()
        self.assertEqual(rows,[("research-123",)])

    def test_ciphertext_corruption_detected(self):
        backup(self.source,self.archive,key_path=self.key)
        data=bytearray(self.archive.read_bytes())
        data[40]^=0x7F
        self.archive.write_bytes(data)
        with self.assertRaises(BackupError):
            verify(self.archive,key_path=self.key)

    def test_manifest_tampering_detected(self):
        backup(self.source,self.archive,key_path=self.key)
        manifest=Path(str(self.archive)+".manifest.json")
        obj=json.loads(manifest.read_text())
        obj["ciphertext_sha256"]="0"*64
        manifest.write_text(json.dumps(obj))
        with self.assertRaises(BackupError):
            verify(self.archive,key_path=self.key)

    def test_wrong_key_cannot_authenticate(self):
        backup(self.source,self.archive,key_path=self.key)
        wrong=self.root/"wrong_key"
        create_key(wrong)
        with self.assertRaises(BackupError):
            verify(self.archive,key_path=wrong)

    def test_restore_refuses_existing_db(self):
        backup(self.source,self.archive,key_path=self.key)
        with self.assertRaises(BackupError):
            restore(self.archive,self.source,key_path=self.key)

    def test_key_creation_is_one_time(self):
        self.assertEqual(len(load_key(self.key)),32)
        with self.assertRaises(BackupError):
            create_key(self.key)

    def test_backup_path_collision_is_rejected(self):
        backup(self.source,self.archive,key_path=self.key)
        with self.assertRaises(BackupError):
            backup(self.source,self.archive,key_path=self.key)


if __name__=="__main__":
    unittest.main()
