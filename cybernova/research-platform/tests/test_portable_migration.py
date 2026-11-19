"""No-Docker unit tests for safe portable migration orchestration."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve()
MANAGER = HERE.parents[1] / "portable" / "manage.py"
spec = importlib.util.spec_from_file_location("cybernova_portable_manager", MANAGER)
manager = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(manager)


class PortableMigrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        env = self.root / ".env"
        env.write_text("CYBERNOVA_LLM_PROVIDER=ollama\n", encoding="utf-8")
        p1 = patch.object(manager, "ROOT", self.root)
        p2 = patch.object(manager, "ENV_FILE", env)
        p1.start()
        p2.start()
        self.addCleanup(p2.stop)
        self.addCleanup(p1.stop)
        self.key = self.root / "backup.key"
        self.key.write_bytes(b"\x13" * 32)
        self.archive = self.root / "sample.cnbk"
        self.archive.write_bytes(b"CNBK1\x00encrypted-placeholder")
        self.manifest = self.root / "sample.cnbk.manifest.json"
        self.manifest.write_text('{"format":"CNBK1"}', encoding="utf-8")

    def test_import_key_is_binary_stdin_not_argv_or_env(self):
        with patch.object(manager, "_compose", return_value="") as compose, \
             patch.object(manager.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0)) as run:
            result = manager.import_backup_key(self.key)
        self.assertTrue(result["backup_key_imported"])
        compose.assert_called_once_with("build", "cybernova")
        args, kwargs = run.call_args
        self.assertEqual(kwargs["input"], b"\x13" * 32)
        self.assertNotIn("131313", " ".join(args[0]))
        self.assertIn("import-backup-key", args[0])

    def test_import_refuses_bad_length_or_symlink(self):
        self.key.write_bytes(b"short")
        with self.assertRaises(manager.InstallError):
            manager.import_backup_key(self.key)
        self.key.unlink()
        self.key.symlink_to(self.archive)
        with self.assertRaises(manager.InstallError):
            manager.import_backup_key(self.key)

    def test_restore_uses_read_only_mount_and_new_target(self):
        with patch.object(manager, "_compose", return_value="") as compose, \
             patch.object(manager.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0)) as run:
            result = manager.restore_from_host(self.archive)
        self.assertTrue(result["database_restored"])
        self.assertFalse(result["overwrite"])
        self.assertEqual(compose.call_args_list[0].args,
                         ("ps", "--status", "running", "-q", "cybernova"))
        command = run.call_args.args[0]
        self.assertIn("--volume", command)
        self.assertTrue(command[command.index("--volume") + 1].endswith(":/restore:ro"))
        self.assertIn("/restore/sample.cnbk", command)
        self.assertIn("/data/communications.sqlite3", command)

    def test_restore_refuses_when_running(self):
        with patch.object(manager, "_compose", return_value="running-id"), \
             patch.object(manager.subprocess, "run") as run:
            with self.assertRaisesRegex(manager.InstallError, "stop_cybernova"):
                manager.restore_from_host(self.archive)
            run.assert_not_called()

    def test_restore_needs_both_archive_and_manifest(self):
        self.manifest.unlink()
        with patch.object(manager, "_compose") as compose:
            with self.assertRaises(manager.InstallError):
                manager.restore_from_host(self.archive)
            compose.assert_not_called()

    def test_import_and_restore_need_initialized_env(self):
        manager.ENV_FILE.unlink()
        with self.assertRaisesRegex(manager.InstallError, "run_init_first"):
            manager.import_backup_key(self.key)
        with self.assertRaisesRegex(manager.InstallError, "run_init_first"):
            manager.restore_from_host(self.archive)


if __name__ == "__main__":
    unittest.main()
