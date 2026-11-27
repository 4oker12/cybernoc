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
        run = server.ChatJobRequest(message="test", receipt=uuid4().hex)
        key = server.ChatJobReceipt(receipt=run.receipt)
        background = BackgroundTasks()

        def execute(payload):
            self.assertEqual(payload.run_id, run.run_id)
            diagnostics.event("tool_call_start", tool="terminal_status", message="private")
            self.assertEqual(server.chat_job_result(key)["progress"], {
                "event": "tool_call_start", "tool": "terminal_status",
            })
            return {"answer": "completed"}

        try:
            self.assertTrue(tunnel_access.allowed_path("/api/chat/start", "POST"))
            self.assertTrue(tunnel_access.allowed_path("/api/chat/result", "POST"))
            self.assertEqual(server.start_chat_job(run, background), {"status": "running"})
            self.assertEqual(server.start_chat_job(run, background), {"status": "running"})
            self.assertEqual(len(background.tasks), 1)
            with self.assertRaises(HTTPException) as conflict:
                server.start_chat_job(server.ChatJobRequest(message="other", receipt=run.receipt), background)
            self.assertEqual(conflict.exception.status_code, 409)
            self.assertEqual(len(background.tasks), 1)
            self.assertEqual(server.chat_job_result(key)["status"], "running")
            with self.assertRaises(HTTPException) as rejected:
                wrong_key = server.ChatJobReceipt(receipt=uuid4().hex)
                server.chat_job_result(wrong_key)
            self.assertEqual(rejected.exception.status_code, 404)
            with patch.object(server, "chat", side_effect=execute) as chat:
                server._complete_chat_job(run)
            chat.assert_called_once()
            result = server.chat_job_result(key)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["result"], {"answer": "completed"})
            self.assertIsNone(diagnostics.CHAT_PROGRESS_SINK.get())
        finally:
            with server.chat_jobs_lock:
                server.chat_jobs.pop(run.receipt, None)


if __name__ == "__main__":
    unittest.main()
