"""Qwen coding agent: real Git worktree/edit/commit and no elevated commands."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console import developer_tools as dev
from console.communication_tools import CommunicationToolClient
from console.tool_policy import REVIEWED_TOOLS


class DeveloperToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        root.chmod(0o755)
        self.repo = root / "source"
        self.ws = root / "workspaces"
        self.repo.mkdir(mode=0o755)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        source = self.repo / "cybernova" / "research-platform"
        source.mkdir(parents=True)
        (source / "tests").mkdir()
        (source / "tests" / "test_demo.py").write_text(
            "import unittest\nclass One(unittest.TestCase):\n def test_true(self): self.assertTrue(True)\n")
        (self.repo / "README.md").write_text("Cybernova research platform\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=CI",
                        "-c", "user.email=ci@example.test", "commit", "-qm", "initial"], check=True)
        self.patch_source = patch.object(dev, "SOURCE", self.repo)
        self.patch_workspaces = patch.object(dev, "WORKSPACES", self.ws)
        self.patch_source.start()
        self.patch_workspaces.start()
        self.addCleanup(self.patch_source.stop)
        self.addCleanup(self.patch_workspaces.stop)
        self.task = "task-123"
    def call(self, name, args=None):
        return dev.dev_call(name, args or {}, self.task)

    def test_tree_read_search_edit_diff_commit_in_private_branch(self):
        state = self.call("dev_workspace")
        self.assertTrue(state["ok"])
        self.assertTrue(state["branch"].startswith("cybernova/qwen/"))
        self.assertTrue(Path(state["workspace"]).is_dir())
        self.assertIn("README.md", self.call("dev_list")["files"])
        self.assertIn("Cybernova", self.call("dev_read", {"path":"README.md"})["content"])
        hits = self.call("dev_search", {"query":"research platform"})["hits"]
        self.assertEqual(hits[0]["file"],"README.md")
        edit=self.call("dev_edit", {
            "path":"README.md","old":"research platform","content":"agent developer"})
        self.assertTrue(edit["ok"])
        self.assertIn("README.md", self.call("dev_diff")["stat"])
        self.assertEqual((self.repo/"README.md").read_text(),"Cybernova research platform\n")
        commit=self.call("dev_commit", {"message":"feat(agent): implement coding tools"})
        self.assertTrue(commit["ok"],commit)
        self.assertEqual(len(commit["commit"]),40)
        self.assertEqual(self.call("dev_workspace")["branch"], state["branch"])

    def test_new_file_creation_and_sensitive_paths_blocked(self):
        created=self.call("dev_edit", {"path":"docs/architecture.md","content":"# Architecture\n"})
        self.assertTrue(created["ok"])
        self.assertIn("docs/architecture.md",self.call("dev_list")["files"])
        for path in ("../private.txt", "/tmp/file", ".git/config", ".env",
                     "secrets.txt", "folder/id_ed25519", "dir/../README.md"):
            with self.assertRaises(dev.DeveloperError,msg=path):
                self.call("dev_read",{"path":path})
        with self.assertRaisesRegex(dev.DeveloperError,"old_text_must_match"):
            self.call("dev_edit",{"path":"README.md","old":"missing","content":"changed"})
        with self.assertRaises(dev.DeveloperError):
            self.call("dev_edit",{"path":"README.md","content":"overwrite without old"})

    def test_tests_and_custom_execution_are_non_root(self):
        result=self.call("dev_test")
        self.assertTrue(result["ok"],result)
        self.assertIn("unittest_non_root",result["runner"])
        cmd=self.call("dev_command",{
            "argv":[sys.executable,"-c","import os;print(os.geteuid())"],
            "timeout":15})
        self.assertTrue(cmd["ok"],cmd)
        if os.geteuid()==0:
            self.assertEqual(cmd["stdout"].strip(),"65534")
        else:
            self.assertEqual(cmd["stdout"].strip(),str(os.geteuid()))

    def test_write_capabilities_are_visible_but_publish_approval_required(self):
        class Store:
            def get_task(self,task_id):return {"task_id":task_id}
        class Upstream:
            def initialize(self):return []
            def call(self,*args):return {},True
        with patch("console.communication_tools.EvidenceJournal"):
            client=CommunicationToolClient(Upstream(),Store(),self.task)
        names={x["name"] for x in client.initialize()}
        self.assertIn("dev_workspace",names)
        self.assertIn("dev_edit",names)
        self.assertIn("dev_command",names)
        self.assertIn("dev_push",names)
        self.assertIn("dev_open_pr",names)
        self.assertIn("dev_edit",REVIEWED_TOOLS)
        self.assertIn("dev_commit",REVIEWED_TOOLS)
        self.assertNotIn("dev_command",REVIEWED_TOOLS)
        self.assertNotIn("dev_push",REVIEWED_TOOLS)
        self.assertNotIn("dev_open_pr",REVIEWED_TOOLS)
        with patch.dict(os.environ,{"CYBERNOVA_DEV_WRITE_KEY":""}):
            with self.assertRaisesRegex(dev.DeveloperError,"git_write_key_not_configured"):
                self.call("dev_push")


if __name__=="__main__":
    unittest.main()
