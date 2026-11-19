"""Offline regression: live upgrade preserves communications before restart."""
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from console import upgrade_communication as up


class LiveUpgradeTests(unittest.TestCase):
    def test_sqlite_online_backup_has_data_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)/"private"
            private.mkdir(mode=0o700)
            path=private/"communications.sqlite3"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE task(test TEXT NOT NULL)")
                db.execute("INSERT INTO task VALUES ('preserved')")
            with patch.object(up,"PRIVATE",private), patch.object(up,"DB",path):
                up.backup_db()
            backups=list((private/"upgrade-backups").glob("*.sqlite3"))
            self.assertEqual(len(backups),1)
            with sqlite3.connect(backups[0]) as copy:
                self.assertEqual(copy.execute("SELECT test FROM task").fetchone()[0],
                                 "preserved")
                self.assertEqual(copy.execute("PRAGMA integrity_check").fetchone()[0],"ok")
            if os.name!="nt":
                self.assertEqual(backups[0].stat().st_mode & 0o077,0)
                self.assertEqual((private/"upgrade-backups").stat().st_mode & 0o077,0)

    def test_live_runtime_config_contains_persistent_siwc(self):
        source=(ROOT/"console/upgrade_communication.py").read_text()
        self.assertIn("CYBERNOVA_SIWC_DIR=",source)
        self.assertIn("CYBERNOVA_SIWC_CALLBACK_PORT=18795",source)
        self.assertIn("backup_db()",source)
        self.assertIn("requirements.txt",source)


if __name__=="__main__":
    unittest.main()
