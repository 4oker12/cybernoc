"""Contract between the web client, Console, and a running research turn."""
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from uuid import uuid4
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException

from console import diagnostics, server, tunnel_access


class ChatJobContractTests(unittest.TestCase):
    def test_status_result_and_deduplication(self):
        run = server.ChatJobRequest(message="test", session_id="a" * 32,
                                    receipt=uuid4().hex)
        key = server.ChatJobReceipt(receipt=run.receipt)
        background = BackgroundTasks()

        def execute(payload):
            self.assertEqual(payload.run_id, run.run_id)
            diagnostics.event("tool_call_start", tool="terminal_status", message="private")
            self.assertEqual(server.chat_job_result(key)["progress"], {
                "event": "tool_call_start", "tool": "terminal_status",
            })
            self.assertEqual(server.chat_job_result(key)["state"], "executing_tool")
            return {"answer": "completed"}

        try:
            self.assertTrue(tunnel_access.allowed_path("/api/chat/start", "POST"))
            self.assertTrue(tunnel_access.allowed_path("/api/chat/result", "POST"))
            self.assertEqual(server.start_chat_job(run, background), {"status": "queued"})
            self.assertEqual(server.start_chat_job(run, background), {"status": "queued"})
            self.assertEqual(len(background.tasks), 1)
            with self.assertRaises(HTTPException) as conflict:
                server.start_chat_job(server.ChatJobRequest(
                    message="other", session_id=run.session_id, run_id=run.run_id,
                    receipt=run.receipt), background)
            self.assertEqual(conflict.exception.status_code, 409)
            self.assertEqual(len(background.tasks), 1)
            self.assertEqual(server.chat_job_result(key)["state"], "queued")
            with self.assertRaises(HTTPException) as rejected:
                wrong_key = server.ChatJobReceipt(receipt=uuid4().hex)
                server.chat_job_result(wrong_key)
            self.assertEqual(rejected.exception.status_code, 404)
            with patch.object(server, "chat", side_effect=execute) as chat:
                server._complete_chat_job(run)
            chat.assert_called_once()
            result = server.chat_job_result(key)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["state"], "completed")
            self.assertEqual(result["result"], {"answer": "completed"})
            self.assertNotIn("request_key", result)
            self.assertNotIn("session_id", result)
            self.assertIsNone(diagnostics.CHAT_PROGRESS_SINK.get())
        finally:
            with server.chat_jobs_lock:
                server.chat_jobs.pop(run.receipt, None)

    def test_result_includes_only_the_receipts_owner_input_and_usage(self):
        run = server.ChatJobRequest(message="test", session_id="b" * 32,
                                    receipt=uuid4().hex)
        key = server.ChatJobReceipt(receipt=run.receipt)
        try:
            server.start_chat_job(run, BackgroundTasks())
            pending = {"request_id": "oin_" + "x" * 24, "input_type": "otp"}
            usage = {"status": "running", "usage": {"available": False}}
            with patch.object(server.owner_input_broker, "pending", return_value=pending) as read, \
                 patch.object(server, "_read_usage_progress", return_value=usage):
                result = server.chat_job_result(key)
            read.assert_called_once_with("deepseek:" + run.session_id)
            self.assertEqual(result["state"], "waiting_for_owner_input")
            self.assertEqual(result["owner_input"], pending)
            self.assertEqual(result["usage_progress"], usage)
        finally:
            with server.chat_jobs_lock:
                server.chat_jobs.pop(run.receipt, None)


if __name__ == "__main__":
    unittest.main()
