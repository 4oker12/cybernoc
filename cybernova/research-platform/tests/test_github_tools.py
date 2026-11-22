"""Offline tests for the read-only GitHub tool group."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.github_tools import GITHUB_NAMES, GITHUB_TOOLS, github_call
from console.communication import CommunicationStore
from console.communication_tools import CommunicationToolClient


class FakeUpstream:
    def initialize(self):
        return []

    def call(self, name, args):
        return {"ok": True}, False


class GitHubToolsTests(unittest.TestCase):
    def test_catalog_is_closed_and_contains_expected_read_only_areas(self):
        names = {item["name"] for item in GITHUB_TOOLS}
        self.assertEqual(names, set(GITHUB_NAMES))
        for tool in GITHUB_TOOLS:
            schema = tool["inputSchema"]
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["properties"]), set(schema["required"]))
        self.assertTrue({
            "github_status", "github_search_repositories", "github_repo_info",
            "github_list_branches", "github_list_commits", "github_list_issues",
            "github_list_pull_requests", "github_list_workflows",
            "github_list_workflow_runs", "github_compare_refs", "github_read_file",
        }.issubset(names))
        self.assertFalse(any("create" in name or "delete" in name or "merge" in name
                             or "dispatch" in name for name in names))

    def test_status_never_returns_the_token(self):
        secret = "ghp_" + "x" * 36
        with patch("console.github_tools._auth_token", return_value=(secret, "gh_cli")), \
             patch("console.github_tools._api_get", return_value={"login": "cybernova-user", "type": "User"}):
            result, failed = github_call("github_status", {})
        self.assertFalse(failed)
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["account"], "cybernova-user")
        self.assertNotIn(secret, str(result))

    def test_anonymous_mode_is_public_read_only(self):
        with patch("console.github_tools._auth_token", return_value=("", "anonymous")), \
             patch("console.github_tools._api_get", return_value={
                 "resources": {"core": {"remaining": 42, "limit": 60}}
             }) as api:
            result, failed = github_call("github_status", {})
        self.assertFalse(failed)
        self.assertFalse(result["authenticated"])
        self.assertEqual(result["mode"], "public_read_only")
        api.assert_called_once_with("rate_limit")

    def test_json_and_source_assignments_are_redacted(self):
        from console.github_tools import _redact_text
        secrets = ["ghp_" + "x" * 36, "plain-password-value", "hardcoded-api-key"]
        source = (
            '{\n  "github_token": "' + secrets[0] + '",\n'
            '  "password": "' + secrets[1] + '"\n}\n'
            'API_KEY = "' + secrets[2] + '"\n'
        )
        redacted = _redact_text(source)
        for secret in secrets:
            self.assertNotIn(secret, redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_sensitive_file_paths_are_blocked_before_network(self):
        with patch("console.github_tools._api_get") as api:
            result, failed = github_call("github_read_file", {
                "repo": "owner/repo", "path": ".env", "ref": "", "max_chars": 10000,
            })
        self.assertTrue(failed)
        self.assertEqual(result["error"], "github_sensitive_file_blocked")
        api.assert_not_called()

    def test_invalid_repository_and_unknown_tool_are_rejected(self):
        result, failed = github_call("github_repo_info", {"repo": "https://github.com/owner/repo"})
        self.assertTrue(failed)
        self.assertEqual(result["error"], "github_repository_invalid_use_owner_slash_repo")
        result, failed = github_call("github_unknown", {})
        self.assertTrue(failed)
        self.assertEqual(result["error"], "github_tool_unknown")

    def test_communication_mcp_exposes_and_routes_github_tools(self):
        with tempfile.TemporaryDirectory() as dirname:
            store = CommunicationStore(Path(dirname) / "communications.sqlite3")
            task = store.create_task("GitHub integration test")
            client = CommunicationToolClient(FakeUpstream(), store, task["task_id"])
            names = {item["name"] for item in client.initialize()}
            self.assertTrue(GITHUB_NAMES.issubset(names))
            with patch("console.communication_tools.github_call",
                       return_value=({"ok": True, "repository": {"full_name": "owner/repo"}}, False)) as call:
                result, failed = client.call("github_repo_info", {"repo": "owner/repo"})
            self.assertFalse(failed)
            self.assertTrue(result["ok"])
            call.assert_called_once_with("github_repo_info", {"repo": "owner/repo"})


if __name__ == "__main__":
    unittest.main()
