"""Offline lifecycle and readiness tests for the portable supervisor."""
from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import portable_runtime


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def sleep(self, amount):
        self.value += amount


class FakeProcess:
    _next_pid = 1000

    def __init__(self, *, stubborn=False, exit_after_polls=None):
        FakeProcess._next_pid += 1
        self.pid = FakeProcess._next_pid
        self.returncode = None
        self.stubborn = stubborn
        self.killed = False
        self.exit_after_polls = exit_after_polls
        self.polls = 0
        self.events = []

    def poll(self):
        self.polls += 1
        if self.exit_after_polls is not None and self.polls >= self.exit_after_polls:
            self.returncode = 7
        return self.returncode

    def terminate(self):
        self.events.append("terminate")
        if not self.stubborn:
            self.returncode = 0

    def wait(self, timeout=None):
        self.events.append("wait")
        if self.stubborn and not self.killed:
            raise subprocess.TimeoutExpired("fake-child", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self):
        self.events.append("kill")
        self.killed = True
        self.returncode = -9


class PortableRuntimeTests(unittest.TestCase):
    def test_wait_for_ready_succeeds_after_probe(self):
        process = FakeProcess()
        ready, stage, code = portable_runtime._wait_for_ready(
            "service", process, 1, probe=lambda _: True,
        )
        self.assertTrue(ready)
        self.assertEqual(stage, "ready")
        self.assertIsNone(code)

    def test_wait_for_ready_reports_child_early_exit(self):
        process = FakeProcess(exit_after_polls=1)
        ready, stage, code = portable_runtime._wait_for_ready(
            "service", process, 1, probe=lambda _: True,
        )
        self.assertFalse(ready)
        self.assertEqual(stage, "early_exit")
        self.assertEqual(code, 7)

    def test_wait_for_ready_times_out_without_readiness(self):
        clock = FakeClock()
        process = FakeProcess()
        ready, stage, code = portable_runtime._wait_for_ready(
            "service", process, 0.5, probe=lambda _: False,
            sleep_fn=clock.sleep, clock=clock,
        )
        self.assertFalse(ready)
        self.assertEqual(stage, "readiness_timeout")
        self.assertIsNone(code)
        self.assertGreaterEqual(clock(), 0.5)

    def test_shutdown_is_graceful_and_reverse_order(self):
        first, second = FakeProcess(), FakeProcess()
        order = []
        original_terminate = FakeProcess.terminate

        def record(process):
            order.append(process.pid)
            original_terminate(process)

        first.terminate = lambda: record(first)
        second.terminate = lambda: record(second)
        portable_runtime._shutdown_children(
            [("first", first), ("second", second)], stop_seconds=1,
        )
        self.assertEqual(order, [second.pid, first.pid])
        self.assertNotIn("kill", first.events + second.events)

    def test_shutdown_escalates_only_known_child_after_timeout(self):
        child = FakeProcess(stubborn=True)
        portable_runtime._shutdown_children([("known-child", child)], stop_seconds=0.1)
        self.assertIn("terminate", child.events)
        self.assertIn("kill", child.events)
        self.assertEqual(child.returncode, -9)

    def test_doctor_reports_api_mcp_and_access_separately(self):
        with patch.object(portable_runtime, "_tcp_ready", side_effect=[True, True]), \
             patch.object(portable_runtime, "_http_probe",
                          side_effect=[(200, b'{"mcp_ready":true}'), (401, b"")]):
            report = portable_runtime._doctor_report()
        self.assertTrue(report["tool_gateway"])
        self.assertTrue(report["communication_mcp"])
        self.assertTrue(report["api_reachable"])
        self.assertTrue(report["mcp_ready"])
        self.assertTrue(report["access_gateway"])
        self.assertEqual(report["access_status"], 401)
        self.assertTrue(report["runtime_ready"])

    def test_doctor_does_not_treat_http_200_without_mcp_as_ready(self):
        with patch.object(portable_runtime, "_tcp_ready", side_effect=[True, True]), \
             patch.object(portable_runtime, "_http_probe",
                          side_effect=[(200, b'{"mcp_ready":false}'), (401, b"")]):
            report = portable_runtime._doctor_report()
        self.assertTrue(report["api_reachable"])
        self.assertFalse(report["mcp_ready"])
        self.assertFalse(report["runtime_ready"])

    def test_startup_failure_returns_nonzero_and_stops_spawned_child(self):
        child = FakeProcess()
        clock = FakeClock()
        with patch.object(portable_runtime.signal, "signal"):
            result = portable_runtime.run_supervisor(
                modules=("service",), process_factory=lambda *a, **k: child,
                readiness_probe=lambda _: False, startup_timeout=0.5,
                sleep_fn=clock.sleep, clock=clock,
            )
        self.assertEqual(result, 2)
        self.assertIn("terminate", child.events)

    def test_requested_shutdown_returns_zero_after_all_children_are_ready(self):
        child = FakeProcess()
        handlers = {}

        def register(sig, handler):
            handlers[sig] = handler

        def stop_on_sleep(_):
            handlers[signal.SIGINT]()

        with patch.object(portable_runtime.signal, "signal", side_effect=register):
            result = portable_runtime.run_supervisor(
                modules=("service",), process_factory=lambda *a, **k: child,
                readiness_probe=lambda _: True, sleep_fn=stop_on_sleep,
            )
        self.assertEqual(result, 0)
        self.assertIn("terminate", child.events)

    def test_main_rejects_symlink_credentials_without_following_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "target.txt"
            target.write_text("do-not-touch", encoding="utf-8")
            link = root / "web_access.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable on this runner")
            with patch.dict(os.environ, {
                "CYBERNOVA_COMM_DB": str(root / "data" / "communications.sqlite3"),
                "CYBERNOVA_ACCESS_SECRET_FILE": str(link),
            }), patch.object(portable_runtime, "configure_diagnostics"):
                with self.assertRaisesRegex(RuntimeError, "access_credentials_symlink_forbidden"):
                    portable_runtime.main()
            self.assertEqual(target.read_text(encoding="utf-8"), "do-not-touch")


if __name__ == "__main__":
    unittest.main()
