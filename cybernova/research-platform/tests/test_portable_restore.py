"""No-network cross-machine restore staging acceptance tests."""
from __future__ import annotations
from contextlib import closing

from io import BytesIO
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from console.backup import create_key, backup, BackupError
from console.portable_restore import stage


def make_zip(archive: Path) -> bytes:
    buf=BytesIO()
    with zipfile.ZipFile(buf,"w") as zipobj:
        zipobj.writestr("snapshot.cnbk",archive.read_bytes())
        zipobj.writestr("snapshot.cnbk.manifest.json",
                        Path(str(archive)+".manifest.json").read_bytes())
    return buf.getvalue()


class CrossMachineRestoreTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.key=self.root/"offline.key"
        create_key(self.key)
        self.db=self.root/"original.sqlite3"
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("CREATE TABLE evidence (name TEXT)")
            conn.execute("INSERT INTO evidence VALUES ('test-finding')")
        self.archive=self.root/"snapshot.cnbk"
        backup(self.db,self.archive,key_path=self.key)

    def test_remote_restore_stages_new_db_without_touching_source(self):
        received=self.root/"received.cnbk"
        target=self.root/"communications-restored.sqlite3"
        with patch.dict(os.environ,{"CYBERNOVA_BACKUP_KEY_FILE":str(self.key)}):
            report=stage(make_zip(self.archive),destination=target,incoming=received)
        self.assertFalse(report["activated"])
        self.assertTrue(target.is_file())
        with closing(sqlite3.connect(target)) as db, db:
            self.assertEqual(db.execute("SELECT name FROM evidence").fetchone()[0],
                             "test-finding")
        self.assertTrue(self.db.is_file())
        self.assertFalse(received.exists())

    def test_rejects_zip_path_traversal_and_extraneous_entries(self):
        payload=BytesIO()
        with zipfile.ZipFile(payload,"w") as zipobj:
            zipobj.writestr("../../etc/passwd","bad")
        with patch.dict(os.environ,{"CYBERNOVA_BACKUP_KEY_FILE":str(self.key)}):
            with self.assertRaises(BackupError):
                stage(payload.getvalue(),destination=self.root/"target",
                      incoming=self.root/"incoming")

    def test_rejects_untrusted_corrupt_archive(self):
        data=bytearray(make_zip(self.archive))
        data[len(data)//2]^=0x18
        with patch.dict(os.environ,{"CYBERNOVA_BACKUP_KEY_FILE":str(self.key)}):
            with self.assertRaises((BackupError,zipfile.BadZipFile)):
                stage(bytes(data),destination=self.root/"target",
                      incoming=self.root/"incoming")

    def test_existing_staged_database_not_overwritten(self):
        target=self.root/"restored.sqlite3"
        target.write_text("existing")
        with patch.dict(os.environ,{"CYBERNOVA_BACKUP_KEY_FILE":str(self.key)}):
            with self.assertRaises(BackupError):
                stage(make_zip(self.archive),destination=target,
                      incoming=self.root/"incoming")
        self.assertEqual(target.read_text(),"existing")


if __name__=="__main__":
    unittest.main()
