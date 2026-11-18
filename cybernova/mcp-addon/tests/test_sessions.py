import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import session_ops as ops
import session_registry as bridge


class SessionRunnerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.root = root
        for key, value in (("ROOT", root / "sessions"), ("LAB", root / "lab"),
                           ("LAB_PY", root / "python")):
            p = patch.object(ops, key, value)
            p.start()
            self.addCleanup(p.stop)
        (ops.LAB / "cybernova_lab").mkdir(parents=True)
        (ops.LAB / "cybernova_lab" / "__main__.py").write_text("# local fixture\n")
        ops.LAB_PY.touch()

    def test_only_fixed_preset_and_no_arbitrary_shell(self):
        for preset in ("scan_simnet", "sh -c id", "https://site", "", None):
            with self.assertRaises(ValueError):
                ops.start(preset)
        with patch.object(ops.subprocess, "Popen") as spawn:
            created = ops.start()
        self.assertTrue(created["ok"])
        args = spawn.call_args.args[0]
        self.assertEqual(args[:2], [sys.executable, str(Path(ops.__file__).resolve())])
        self.assertEqual(args[2], "worker")
        self.assertEqual(args[3], created["session_id"])
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        self.assertNotIn("shell", spawn.call_args.kwargs)
        self.assertEqual(ops.status(created["session_id"])["state"], "running")
        self.assertEqual(ops.start()["reason"], "session_already_running")

    def test_invalid_and_symlink_session_ids(self):
        for session_id in ("../etc/passwd", "x" * 32, "a" * 33, "", 42):
            with self.assertRaises(ValueError):
                ops.status(session_id)
        ops._root()
        (ops.ROOT / ("a" * 32)).symlink_to(self.root)
        with self.assertRaises(ValueError):
            ops.status("a" * 32)

    def test_missing_environment_refuses_without_spawning(self):
        ops.LAB_PY.unlink()
        with patch.object(ops.subprocess, "Popen") as spawn, self.assertRaises(RuntimeError):
            ops.start()
        spawn.assert_not_called()

    def test_worker_failure_is_recorded_and_report_is_safe(self):
        session_id = "a" * 32
        folder = ops._root() / session_id
        folder.mkdir(mode=0o700)
        ops._write(folder / "session.json", {"session_id": session_id,
                   "started_at": ops.time.time(), "scope": "LOCAL_LAB_ONLY"})
        with patch.object(ops.subprocess, "run", return_value=MagicMock(returncode=1)):
            self.assertEqual(ops.worker(session_id), 1)
        answer = ops.report(session_id)
        self.assertEqual(answer["state"], "failed")
        self.assertEqual(answer["reason"], "ValueError")
        self.assertNotIn("stdout", answer)

    def test_evidence_integrity_detects_mutation(self):
        work = self.root / "case"
        sub = work / "evidence" / ("b" * 32)
        sub.mkdir(parents=True)
        name = "c" * 32
        data = b"original-bytes"
        manifest = {"stdout_file": name + ".stdout",
                    "stderr_file": name + ".stderr",
                    "stdout_sha256": hashlib.sha256(data).hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "stdout_bytes": len(data), "stderr_bytes": 0}
        (sub / manifest["stdout_file"]).write_bytes(data)
        (sub / manifest["stderr_file"]).write_bytes(b"")
        (sub / (name + ".json")).write_text(json.dumps(manifest))
        self.assertEqual(ops._check_evidence(work), 1)
        (sub / manifest["stdout_file"]).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            ops._check_evidence(work)

    def test_worker_reports_success_only_for_two_real_qwen_actions(self):
        session_id = "d" * 32
        folder = ops._root() / session_id
        folder.mkdir()
        ops._write(folder / "session.json", {"session_id": session_id,
                   "started_at": ops.time.time(), "scope": "LOCAL_LAB_ONLY"})
        def run(_argv, **kwargs):
            work = folder / "work"
            work.mkdir(exist_ok=True)
            ops._write(work / "adapter-report.json", {
                "status": "completed_local_workflow",
                "actions": [{"adapter_id": a, "exit_code": 0} for a in ops.EXPECTED]})
            ops._write(work / "qwen-report.json", {
                "status": "completed_local_workflow", "successful_actions": 2,
                "external_target_requests": 0,
                "actions": [{"adapter_id": a, "exit_code": 0} for a in ops.QWEN_EXPECTED]})
            return MagicMock(returncode=0)
        with patch.object(ops.subprocess, "run", side_effect=run) as execute, \
             patch.object(ops, "_check_evidence", return_value=9):
            self.assertEqual(ops.worker(session_id), 0)
        self.assertFalse(execute.call_args.kwargs.get("shell", False))
        self.assertEqual(ops.report(session_id)["evidence_manifests_verified"], 9)
        self.assertTrue(ops.report(session_id)["passed"])


class SessionMCPTests(unittest.TestCase):
    def test_fixed_commands_and_local_approval_not_bypassed(self):
        for op, arg in (("shell", ""), ("start", "x"), ("status", "../x"),
                        ("report", "https://example.com"), ("status", "x" * 32)):
            self.assertFalse(bridge.execute(op, arg)["ok"])
        response = MagicMock(returncode=0, stdout='{"ok":true,"session_id":"x"}', stderr="")
        with patch.object(bridge.os, "geteuid", return_value=0), \
             patch.object(bridge.subprocess, "run", return_value=response) as call:
            self.assertTrue(bridge.execute("start")["ok"])
        argv = call.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/sbin/runuser", "-u", "cybernova", "--"])
        self.assertEqual(argv[-1], "start")
        self.assertFalse(call.call_args.kwargs["shell"])
        self.assertEqual(call.call_args.kwargs["timeout"], 20)

    def test_registration_exposes_only_named_session_tools(self):
        class Fake:
            def __init__(self): self.names = []
            def tool(self):
                def decorate(fn):
                    self.names.append(fn.__name__)
                    return fn
                return decorate
        fake = Fake()
        bridge.register(fake)
        self.assertEqual(fake.names, [
            "cybernova_session_start", "cybernova_session_status",
            "cybernova_session_report"])


if __name__ == "__main__":
    unittest.main()
