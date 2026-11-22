"""No-external-network tests for Cybernova's private diagnostic journal."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import http.client
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import diagnostics
from console.tunnel_access import GatewayHandler, allowed_path


class DiagnosticsTests(unittest.TestCase):
    @contextmanager
    def temp_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {"CYBERNOVA_DIAGNOSTICS_DIR": temp}):
                yield Path(temp)

    @contextmanager
    def journal(self, component="console"):
        with self.temp_folder() as folder:
            root = logging.getLogger()
            before = set(root.handlers)
            old_configured = set(diagnostics._CONFIGURED)
            try:
                diagnostics.configure(component)
                diagnostics.configure(component)
                self.assertEqual(
                    len([h for h in root.handlers if h not in before]), 1
                )
                yield folder
            finally:
                for handler in tuple(root.handlers):
                    if handler not in before:
                        root.removeHandler(handler)
                        handler.close()
                diagnostics._CONFIGURED.clear()
                diagnostics._CONFIGURED.update(old_configured)

    def test_scrub_tokens_urls_user_paths_and_credentials(self):
        line = (
            "Authorization: Bearer abcdefghijklmnop "
            "token=super-secret-value api_key=importantkey "
            "https://example.org/path?session=myvalue "
            "C:\\Users\\PrivateUser\\Documents\\data.txt"
        )
        result = diagnostics.scrub(line)
        for secret in ("abcdefghijklmnop", "super-secret-value",
                       "importantkey", "session=myvalue", "PrivateUser"):
            self.assertNotIn(secret, result)
        self.assertIn("Authorization", result)
        self.assertIn("https://example.org/path", result)

    def test_model_failure_writes_redacted_structured_event(self):
        with self.journal() as folder:
            try:
                raise ValueError("api_key=veryprivate and token=topsecret123")
            except ValueError as exc:
                diagnostics.failure("console", "chatgpt_inference", exc,
                                    error_id="run-safe-id")
            report = diagnostics.export_jsonl().decode("utf-8")
            events = [json.loads(line) for line in report.splitlines()]
            self.assertEqual(events[0]["kind"], "cybernova-diagnostics")
            self.assertEqual(events[0]["event_count"], 1)
            item = events[1]
            self.assertEqual(item["component"], "console")
            self.assertEqual(item["exception_type"], "ValueError")
            self.assertEqual(item["level"], "ERROR")
            self.assertEqual(item["logger"], "cybernova.failure")
            self.assertTrue(item["frames"])
            self.assertNotIn("exception", item)
            self.assertIn("run-safe-id", item["message"])
            self.assertNotIn("veryprivate", report)
            self.assertNotIn("topsecret123", report)
            self.assertTrue((folder / "console.jsonl").is_file())
            self.assertFalse((folder / "supervisor.jsonl").exists())

    def test_chat_turns_record_usage_and_adapter_status_without_payloads(self):
        from types import SimpleNamespace
        run = SimpleNamespace(run_id="a" * 32, message="private prompt")
        observe = diagnostics.observe_chat("researcher", lambda p: ("DeepSeek", "test-model"),
                                           lambda run_id: {})

        @observe
        def ok(payload):
            return {"answer": "private answer", "usage": {"input_tokens": 19, "cached_tokens": 0}}

        @observe
        def fail(payload):
            try:
                try:
                    raise OSError("private upstream body")
                except OSError:
                    raise ValueError("llm_http_429") from None
            except ValueError as exc:
                raise RuntimeError("private wrapper") from exc

        with self.journal():
            ok(run)
            with self.assertRaises(RuntimeError):
                fail(run)
            report = diagnostics.export_jsonl().decode()
        self.assertNotIn("private", report)
        success, error = [
            row["chat_turn"] for row in (json.loads(line) for line in report.splitlines()[1:])
            if "chat_turn" in row
        ]
        self.assertEqual(success["run_id"], run.run_id)
        self.assertEqual(success["cached_tokens"], 0)
        self.assertIsNone(success["output_tokens"])
        self.assertEqual(error["upstream_http_status"], 429)
        self.assertEqual(error["stage"], "provider_http")

    def test_account_gpt_partial_event_omits_response_text_and_uses_progress(self):
        from types import SimpleNamespace
        run = SimpleNamespace(run_id="b" * 32)

        @diagnostics.observe_chat("account_gpt", lambda p: ("OpenAI Responses", "test-model"),
                                  lambda run_id: {"usage": {"input_tokens": 21}})
        def partial(payload):
            return {"answer": "arbitrary response fragment",
                    "source": "chatgpt_plan_responses_partial",
                    "error_code": "gpt_stream_incomplete"}

        with self.journal():
            partial(run)
            report = diagnostics.export_jsonl().decode()
        self.assertNotIn("arbitrary response fragment", report)
        item = next(
            row["chat_turn"] for row in (json.loads(line) for line in report.splitlines()[1:])
            if "chat_turn" in row
        )
        self.assertEqual(item["run_id"], run.run_id)
        self.assertEqual(item["provider"], "OpenAI Responses")
        self.assertEqual(item["status"], "partial")
        self.assertEqual(item["stage"], "provider_stream")
        self.assertEqual(item["input_tokens"], 21)
        self.assertIsNone(item["cached_tokens"])


    def test_timeline_records_correlated_safe_metadata_and_excludes_payloads(self):
        with self.journal():
            token = diagnostics.RUN_CONTEXT.set("c" * 32)
            try:
                diagnostics.event("browser_action", tool="browser_navigate", status="ok",
                                  http_status=200, duration_ms=15,
                                  message="PROMPT_SHOULD_NEVER_EXPORT",
                                  url="https://secret.example/?token=private")
            finally:
                diagnostics.RUN_CONTEXT.reset(token)
            report = diagnostics.export_jsonl().decode("utf-8")
        item = json.loads(report.splitlines()[1])["timeline"]
        self.assertEqual(item["run_id"], "c" * 32)
        self.assertEqual(item["event"], "browser_action")
        self.assertEqual(item["duration_ms"], 15)
        self.assertNotIn("url", item)
        self.assertNotIn("message", item)
        self.assertNotIn("PROMPT_SHOULD_NEVER_EXPORT", report)
        self.assertNotIn("secret.example", report)

    def test_timeline_span_logs_success_and_failure_without_exception_body(self):
        with self.journal():
            with diagnostics.span("model_request", provider="DeepSeek"):
                pass
            try:
                with diagnostics.span("model_request", provider="DeepSeek"):
                    raise ValueError("password=private_test_secret")
            except ValueError:
                pass
            report = diagnostics.export_jsonl().decode("utf-8")
        self.assertIn("model_request_start", report)
        self.assertIn("model_request_complete", report)
        self.assertIn("model_request_failure", report)
        self.assertIn("ValueError", report)
        self.assertNotIn("private_test_secret", report)

    def test_export_drops_unlisted_timeline_values_even_for_forged_logs(self):
        with self.temp_folder() as folder:
            (folder / "console.jsonl").write_text(json.dumps({
                "component": "console", "level": "INFO", "message": "event tool",
                "timeline": {
                    "event": "tool_call_completed", "tool": "browser_navigate",
                    "run_id": "d" * 32, "duration_ms": 25,
                    "url": "https://private.invalid/token",
                    "password": "do-not-export", "status": "ok",
                },
            }) + "\n", encoding="utf-8")
            report = diagnostics.export_jsonl().decode()
        self.assertIn("tool_call_completed", report)
        self.assertNotIn("private.invalid", report)
        self.assertNotIn("do-not-export", report)

    def test_export_merges_services_without_leaking_unlisted_files(self):
        with self.temp_folder() as folder:
            (folder / "console.jsonl").write_text(json.dumps({
                "time": "2026-11-22T10:00:00+00:00",
                "component": "console", "level": "ERROR",
                "message": "DeepSeek failed token=secreta",
            }) + "\n", encoding="utf-8")
            (folder / "tool-mcp.jsonl").write_text(json.dumps({
                "time": "2026-11-22T11:00:00+00:00",
                "component": "tool-mcp", "level": "ERROR",
                "message": "MCP tool failed",
            }) + "\n", encoding="utf-8")
            (folder / "unrelated-secret.txt").write_text(
                "SHOULD_NOT_EXPORT", encoding="utf-8"
            )
            rows = [json.loads(x) for x in diagnostics.export_jsonl().splitlines()]
            self.assertEqual(rows[0]["event_count"], 2)
            self.assertEqual(
                [r["component"] for r in rows[1:]], ["console", "tool-mcp"]
            )
            self.assertNotIn("secreta", str(rows))
            self.assertNotIn("SHOULD_NOT_EXPORT", str(rows))

    def test_export_drops_legacy_exception_text_and_nested_payload_fields(self):
        with self.temp_folder() as folder:
            row = {"component": "console", "message": "chat turn failed",
                   "exception": "legacy private data", "chat_turn": {
                       "run_id": "f" * 32, "status": "failed", "input_tokens": 0,
                       "prompt": "private prompt", "error_code": "private upstream body"}}
            (folder / "console.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            report = diagnostics.export_jsonl().decode()
        self.assertNotIn("private", report)
        chat = json.loads(report.splitlines()[1])["chat_turn"]
        self.assertEqual(chat["input_tokens"], 0)
        self.assertIsNone(chat["error_code"])

    def test_error_logs_rotate_below_a_bounded_total(self):
        with self.journal() as folder:
            logger = logging.getLogger("cybernova.diagnostics.test")
            for idx in range(300):
                logger.error("failure_%d %s", idx, "X" * 2700)
            records = sorted(folder.glob("console.jsonl*"))
            self.assertLessEqual(len(records), diagnostics.BACKUP_COUNT + 1)
            self.assertGreater(len(records), 1)
            self.assertLess(sum(path.stat().st_size for path in records), 1_000_000)
            result = diagnostics.export_jsonl()
            self.assertLess(len(result), 6_000_000)

    def test_export_requires_basic_auth_and_sets_download_headers(self):
        with self.journal("access-gateway"):
            server = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
            server.credentials = ("cybernova", "x" * 32)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/api/diagnostics/export")
                denied = conn.getresponse()
                self.assertEqual(denied.status, 401)
                denied.read()
                conn.close()

                auth = base64.b64encode(b"cybernova:" + b"x" * 32).decode("ascii")
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/api/diagnostics/export",
                             headers={"Authorization": "Basic " + auth})
                allowed = conn.getresponse()
                self.assertEqual(allowed.status, 200)
                self.assertIn("application/x-ndjson", allowed.getheader("Content-Type"))
                self.assertIn("attachment", allowed.getheader("Content-Disposition"))
                report = allowed.read()
                self.assertEqual(json.loads(report.splitlines()[0])["kind"],
                                 "cybernova-diagnostics")
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
        self.assertTrue(allowed_path("/api/diagnostics/export", "GET"))
        self.assertFalse(allowed_path("/api/diagnostics/export", "POST"))


if __name__ == "__main__":
    unittest.main()
