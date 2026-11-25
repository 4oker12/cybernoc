import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch,MagicMock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import deployment_ops as ops
import registry

class SecurityTests(unittest.TestCase):
    def test_sha_validation(self):
        self.assertEqual(ops._require_sha("a"*40),"a"*40)
        for value in ("", "A"*40, "a"*39, "a"*41, "../escape"):
            with self.assertRaises(ValueError):
                ops._require_sha(value)

    def test_command_allowlist(self):
        self.assertFalse(registry.execute("run_shell")["ok"])

    def test_argument_bound(self):
        self.assertFalse(registry.execute("stage","a"*200)["ok"])

    def test_runuser_and_no_shell(self):
        completed=MagicMock(returncode=0,stdout='{"ok": true}',stderr="")
        with patch.object(registry.os,"geteuid",return_value=0):
            with patch.object(registry.subprocess,"run",return_value=completed) as call:
                out=registry.execute("status")
        self.assertTrue(out["ok"])
        argv=call.call_args.args[0]
        self.assertEqual(argv[:4],["/usr/sbin/runuser","-u","cybernova","--"])
        self.assertEqual(argv[-1],"status")
        self.assertFalse(call.call_args.kwargs["shell"])

    def test_invalid_json_fails_closed(self):
        completed=MagicMock(returncode=0,stdout="not json",stderr="")
        with patch.object(registry.subprocess,"run",return_value=completed):
            self.assertFalse(registry.execute("preview")["ok"])

    def test_nonzero_exit_is_failure(self):
        completed=MagicMock(returncode=1,stdout='{"ok":true}',stderr="")
        with patch.object(registry.subprocess,"run",return_value=completed):
            self.assertFalse(registry.execute("preview")["ok"])

    def test_registration_preserves_original_tools(self):
        class Fake:
            def __init__(self): self.names=[]
            def tool(self):
                def decorator(fn):
                    self.names.append(fn.__name__)
                    return fn
                return decorator
        fake=Fake()
        registry.register(fake)
        self.assertEqual(fake.names,["deployment_status","deployment_preview",
             "deployment_stage","deployment_apply","deployment_rollback",
             "deployment_recent_events"])

    def test_lock_rejects_parallel_process(self):
        with tempfile.TemporaryDirectory() as root:
            base=Path(root)
            (base/".runner.lock").touch()
            with patch.object(ops,"WORK",base):
                with patch.object(ops,"_require_operator"):
                    with ops._exclusive():
                        with self.assertRaisesRegex(RuntimeError,"Auto Updater is running"):
                            with ops._exclusive(): pass

    def test_event_reports_only_bounded_fields(self):
        with tempfile.TemporaryDirectory() as root:
            base=Path(root);(base/"reports").mkdir()
            (base/"reports"/"1.json").write_text(json.dumps({
                "commit":"a"*40,"status":"success","timestamp":123,
                "detail":"Sensitive content should not be returned"}))
            with patch.object(ops,"WORK",base), patch.object(ops,"_require_operator"):
                result=ops.recent_events()
        self.assertEqual(len(result["events"]),1)
        self.assertNotIn("detail",result["events"][0])

if __name__=="__main__":
    unittest.main()
