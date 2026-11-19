"""No-Docker native installer tests; no real model/network used."""
from __future__ import annotations
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"portable"))
import native


class NativeInstallerTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.data=Path(t.name)/"cybernova-private"

    def test_native_local_initialization_is_private_and_scope_closed(self):
        result=native.init(self.data,"ollama","cybernova-security:30b")
        self.assertEqual(result["scope"],"empty_default_deny")
        self.assertEqual(self.data.joinpath("scope.json").read_text().strip(),
                         '{\n  "allowed_hosts": []\n}')
        cfg=native._load(self.data)
        self.assertEqual(cfg["CYBERNOVA_COMM_DB"],str(self.data/"communications.sqlite3"))
        self.assertEqual(cfg["CYBERNOVA_ACCESS_HOST"],"127.0.0.1")
        self.assertFalse("model_api_key" in cfg["CYBERNOVA_LLM_API_KEY_FILE"])
        self.assertEqual(result["model"],"cybernova-security:30b")
        with self.assertRaises(native.NativeError):
            native.init(self.data,"ollama","another:7b")

    def test_external_provider_requires_https_and_preserves_key_outside_config(self):
        with self.assertRaises(native.NativeError):
            native.init(self.data,"openai_compatible","test-model",
                        "http://external.example/v1")
        native.init(self.data,"openai_compatible","gpt-test","https://api.example/v1")
        with patch("getpass.getpass",return_value="test_secret_not_real_1234"):
            native.set_key(self.data)
        self.assertEqual((self.data/"model_api_key").read_text(),
                         "test_secret_not_real_1234\n")
        self.assertNotIn("test_secret_not_real_1234",
                         (self.data/"runtime.env").read_text())
        self.assertEqual(native._load(self.data)["CYBERNOVA_LLM_PROVIDER"],
                         "openai_compatible")

    def test_backups_are_never_activated_implicitly(self):
        native.init(self.data,"ollama","test:latest")
        # The unit test must not probe a real Cybernova UI on the test host.
        # A live Vast deployment may legitimately be listening on localhost.
        with patch.object(native,"build_opener",side_effect=OSError("isolated_test")):
            info=native.doctor(self.data)
        self.assertFalse(info["web_ui_up"])
        self.assertFalse((self.data/"communications-restored.sqlite3").exists())

    def test_key_export_does_not_overwrite_destination(self):
        native.init(self.data,"ollama","test:latest")
        key=self.data/"backup.key"
        key.write_bytes(bytes(range(32)))
        dest=self.data.parent/"offline-backup.key"
        result=native.export_backup_key(self.data,dest)
        self.assertTrue(Path(result["backup_key_exported"]).exists())
        self.assertEqual(dest.read_bytes(),bytes(range(32)))
        with self.assertRaises(native.NativeError):
            native.export_backup_key(self.data,dest)


if __name__=="__main__":
    unittest.main()
