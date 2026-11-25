"""Portable repository artifact guard: deny private data, keep legitimate source."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"portable"))
from repo_guard import prohibited, review_tracked


class RepoGuardTests(unittest.TestCase):
    def test_sensitive_runtime_filenames_denied(self):
        paths=[
            "cybernova/portable/config/.env",
            "cybernova/run/communications.sqlite3",
            "cybernova/backups/nov.cnbk",
            "cybernova/pcaps/test.pcap",
            "weights/qwen30b.gguf",
            "models/secret/victim.txt",
            "secrets/password.txt",
            "configs/client-key.pem",
            "credentials.json",
            "data/file.p12",
            "anything/id_ed25519",
        ]
        self.assertEqual(review_tracked(paths), paths)

    def test_public_source_and_example_config_allowed(self):
        paths=[
            "cybernova/research-platform/portable/.env.example",
            "cybernova/research-platform/portable/compose.yaml",
            "cybernova/research-platform/console/model_providers.py",
            ".github/workflows/cybernova-research-platform.yml",
            "docs/model-architecture.md",
        ]
        self.assertEqual(review_tracked(paths), [])

    def test_reject_path_escape(self):
        self.assertTrue(prohibited("../secret"))
        self.assertTrue(prohibited("/var/log/cybernova"))
        self.assertTrue(prohibited("app/../../passwd"))


if __name__=="__main__":
    unittest.main()
