"""Offline tests for autonomous repository-scoped GitHub write tools."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.github_write_tools import (
    GITHUB_WRITE_NAMES, GITHUB_WRITE_TOOLS, github_write_call,
)


class GitHubWriteToolsTests(unittest.TestCase):
    def test_catalog_has_closed_strict_schemas_and_full_repo_workflow(self):
        names = {item["name"] for item in GITHUB_WRITE_TOOLS}
        self.assertEqual(names, set(GITHUB_WRITE_NAMES))
        self.assertTrue({
            "github_api_request", "github_create_branch",
            "github_commit_files", "github_merge_pull_request",
            "github_workflow_job_logs",
        }.issubset(names))
        for item in GITHUB_WRITE_TOOLS:
            schema = item["inputSchema"]
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["properties"]), set(schema["required"]))

    def test_write_tools_require_one_configured_github_credential(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("", "anonymous")), \
             patch("console.github_write_tools._api_request") as api:
            result, failed = github_write_call("github_create_branch", {
                "repo": "owner/repo", "branch": "feature/test", "from_ref": "",
            })
        self.assertTrue(failed)
        self.assertIn("github_auth_required", result["error"])
        api.assert_not_called()

    def test_generic_api_is_repo_scoped_and_redacts_response(self):
        secret = "ghp_" + "x" * 36
        with patch("console.github_write_tools._auth_token",
                   return_value=(secret, "gh_cli")), \
             patch("console.github_write_tools._api_request",
                   return_value=({"message": "Bearer " + "a" * 24, "number": 12}, 200)) as api:
            result, failed = github_write_call("github_api_request", {
                "repo": "owner/repo", "method": "GET", "path": "issues",
                "query_json": "{\"state\":\"open\"}", "body_json": "",
            })
        self.assertFalse(failed)
        self.assertEqual(result["http_status"], 200)
        self.assertNotIn("Bearer " + "a" * 24, str(result))
        api.assert_called_once()
        self.assertEqual(api.call_args.args[:3], ("GET", "owner/repo", "issues"))

    def test_generic_api_rejects_path_traversal_before_network(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request") as api:
            result, failed = github_write_call("github_api_request", {
                "repo": "owner/repo", "method": "GET", "path": "../issues",
                "query_json": "", "body_json": "",
            })
        self.assertTrue(failed)
        self.assertEqual(result["error"], "github_api_path_invalid")
        api.assert_not_called()

    def test_delete_requires_matching_user_task_intent_not_a_confirmation_phrase(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request") as api:
            result, failed = github_write_call("github_api_request", {
                "repo": "owner/repo", "method": "DELETE",
                "path": "git/refs/heads/old-branch",
                "query_json": "", "body_json": "",
            }, user_messages=[{"role": "user", "content": "Проверь список старых веток"}])
        self.assertTrue(failed)
        self.assertIn("github_explicit_task_intent_required", result["error"])
        api.assert_not_called()

    def test_create_branch_uses_default_branch_and_creates_ref(self):
        calls = []
        def fake(method, repo, path, token, query=None, body=None):
            calls.append((method, path, body))
            if (method, path) == ("GET", ""):
                return {"default_branch": "main"}, 200
            if (method, path) == ("GET", "git/ref/heads/main"):
                return {"object": {"sha": "a" * 40}}, 200
            if (method, path) == ("POST", "git/refs"):
                return {"ref": "refs/heads/feature/test"}, 201
            raise AssertionError((method, path))
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request", side_effect=fake):
            result, failed = github_write_call("github_create_branch", {
                "repo": "owner/repo", "branch": "feature/test", "from_ref": "",
            })
        self.assertFalse(failed)
        self.assertEqual(result["branch"], "feature/test")
        self.assertEqual(calls[-1][2], {
            "ref": "refs/heads/feature/test", "sha": "a" * 40,
        })

    def test_commit_files_creates_one_atomic_non_default_branch_commit(self):
        calls = []
        def fake(method, repo, path, token, query=None, body=None):
            calls.append((method, path, body))
            if (method, path) == ("GET", ""):
                return {"default_branch": "main"}, 200
            if (method, path) == ("GET", "git/ref/heads/feature/test"):
                return {"object": {"sha": "a" * 40}}, 200
            if (method, path) == ("GET", "git/commits/" + "a" * 40):
                return {"tree": {"sha": "tree-base"}}, 200
            if (method, path) == ("POST", "git/blobs"):
                return {"sha": "blob-1"}, 201
            if (method, path) == ("POST", "git/trees"):
                return {"sha": "tree-1"}, 201
            if (method, path) == ("POST", "git/commits"):
                return {"sha": "b" * 40}, 201
            if (method, path) == ("PATCH", "git/refs/heads/feature/test"):
                return {"ref": "refs/heads/feature/test"}, 200
            raise AssertionError((method, path))
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request", side_effect=fake):
            result, failed = github_write_call("github_commit_files", {
                "repo": "owner/repo", "branch": "feature/test",
                "message": "Fix autonomous GitHub tools",
                "files": [{
                    "path": "README.md", "operation": "upsert",
                    "content": "# Cybernova\n",
                }],
            })
        self.assertFalse(failed)
        self.assertEqual(result["commit_sha"], "b" * 40)
        self.assertEqual(result["file_count"], 1)
        self.assertEqual(calls[-1][2], {"sha": "b" * 40, "force": False})
        self.assertEqual([row[0] for row in calls].count("POST"), 3)

    def test_default_branch_commit_is_blocked(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request",
                   return_value=({"default_branch": "main"}, 200)) as api:
            result, failed = github_write_call("github_commit_files", {
                "repo": "owner/repo", "branch": "main",
                "message": "Do not write to main",
                "files": [{
                    "path": "README.md", "operation": "upsert", "content": "x",
                }],
            })
        self.assertTrue(failed)
        self.assertEqual(result["error"], "github_direct_default_branch_commit_blocked")
        api.assert_called_once()

    def test_merge_requires_direct_task_intent_before_any_api_call(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request") as api:
            result, failed = github_write_call("github_merge_pull_request", {
                "repo": "owner/repo", "number": 12, "method": "squash",
                "expected_head_sha": "a" * 40,
            }, user_messages=[{"role": "user", "content": "Проверь PR 12"}])
        self.assertTrue(failed)
        self.assertIn("github_explicit_task_intent_required", result["error"])
        api.assert_not_called()


    def test_repository_settings_can_be_read_without_approval(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request",
                   return_value=({"name": "repo", "private": True}, 200)) as api:
            result, failed = github_write_call("github_api_request", {
                "repo": "owner/repo", "method": "GET", "path": "repository",
                "query_json": "", "body_json": "",
            }, user_messages=[{"role": "user", "content": "Изучи репозиторий"}])
        self.assertFalse(failed)
        self.assertEqual(result["data"]["name"], "repo")
        self.assertEqual(api.call_args.args[:3], ("GET", "owner/repo", ""))

    def test_repository_admin_write_needs_direct_task_intent_not_confirmation(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request") as api:
            result, failed = github_write_call("github_api_request", {
                "repo": "owner/repo", "method": "PATCH", "path": "repository",
                "query_json": "", "body_json": "{\"private\":true}",
            }, user_messages=[{"role": "user", "content": "Проверь настройки репозитория"}])
        self.assertTrue(failed)
        self.assertIn("github_explicit_task_intent_required", result["error"])
        api.assert_not_called()

    def test_repository_admin_write_runs_when_user_directly_requests_change(self):
        with patch("console.github_write_tools._auth_token",
                   return_value=("token", "gh_cli")), \
             patch("console.github_write_tools._api_request",
                   return_value=({"private": True}, 200)) as api:
            result, failed = github_write_call("github_api_request", {
                "repo": "owner/repo", "method": "PATCH", "path": "repository",
                "query_json": "", "body_json": "{\"private\":true}",
            }, user_messages=[{"role": "user", "content": "Измени настройки репозитория: сделай его приватным"}])
        self.assertFalse(failed)
        self.assertTrue(result["ok"])
        self.assertEqual(api.call_args.args[:3], ("PATCH", "owner/repo", ""))


if __name__ == "__main__":
    unittest.main()
