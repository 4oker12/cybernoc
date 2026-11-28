"""Contract between the web client, Console, and a running research turn."""
import unittest
import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from uuid import uuid4
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException

from console import diagnostics, server, tunnel_access
from console.communication import CommunicationStore
from console.chat_jobs import ChatJobStore


class ChatJobContractTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = CommunicationStore(Path(tmp.name) / "comm.sqlite3")
        self.jobs = ChatJobStore(self.store)
        patcher = patch.object(server,"chat_job_store",return_value=self.jobs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_restart_preserves_receipt_and_never_replays(self):
        task = self.store.create_task("Long test")["task_id"]
        self.store.set_state(task,"running")
        run = server.ChatJobRequest(message="test",receipt=uuid4().hex,session_id=uuid4().hex)
        self.assertEqual(self.jobs.start(run),("running",True))
        self.assertTrue(self.jobs.claim(run.receipt))
        self.jobs.bind(run.receipt,run.session_id,task)
        self.jobs.progress(run.receipt,{"event":"tool_call_start","tool":"terminal_status","private":"never"})
        restored = ChatJobStore(self.store)
        self.assertEqual(restored.recover_interrupted(),1)
        result = restored.read(run.receipt)
        self.assertEqual(result["status"],"interrupted")
        self.assertEqual(result["progress"],{"event":"tool_call_start","tool":"terminal_status"})
        self.assertEqual(self.store.get_task(task)["status"],"blocked")
        self.assertFalse(restored.claim(run.receipt))
        self.assertEqual(restored.start(run),("interrupted",False))

    def test_timeline_preserves_order_and_never_stores_raw_payload(self):
        run = server.ChatJobRequest(message="test", receipt=uuid4().hex)
        self.jobs.start(run)
        self.jobs.progress(run.receipt, {"event":"model_request_start"})
        self.jobs.progress(run.receipt, {"event":"model_request_complete","duration_ms":34000})
        self.jobs.progress(run.receipt, {"event":"agent_tool_requested","tool":"browser_verify",
                                        "call_ref":"a1","arguments":"private"})
        self.jobs.progress(run.receipt, {"event":"agent_tool_observed","tool":"browser_verify",
                                        "call_ref":"a1","change_strategy":True,
                                        "effect":"unverified_partial_observation","reasoning":"private"})
        self.jobs.finish(run.receipt,"completed")
        saved = ChatJobStore(self.store).read(run.receipt)["timeline"]
        self.assertEqual([x["event"] for x in saved], ["model_request_start","model_request_complete",
                         "agent_tool_requested","agent_tool_observed"])
        self.assertEqual(saved[1]["duration_ms"],34000)
        self.assertTrue(saved[-1]["change_strategy"])
        self.assertNotIn("arguments",saved[2])
        self.assertNotIn("reasoning",saved[3])
        self.assertEqual(saved[2]["call_ref"],saved[3]["call_ref"])

    def test_completed_answer_survives_cache_loss(self):
        task = self.store.create_task("Long test")["task_id"]
        run = server.ChatJobRequest(message="test",receipt=uuid4().hex,session_id=uuid4().hex)
        self.jobs.start(run)
        self.jobs.claim(run.receipt)
        self.jobs.bind(run.receipt,run.session_id,task)
        msg = self.store.append(task,"qwen","result","Durable final answer",status="completed")
        self.jobs.finish(run.receipt,"completed",{"task_id":task,"session_id":run.session_id,
            "event_seq":msg["seq"],"events":[{"private":"never"}]})
        result = ChatJobStore(self.store).read(run.receipt)
        self.assertEqual(result["result"]["answer"],"Durable final answer")
        self.assertTrue(result["result"]["recovered"])
        self.assertNotIn("events",result["result"])

    def test_stop_and_same_session_guard(self):
        run = server.ChatJobRequest(message="test",receipt=uuid4().hex,session_id=uuid4().hex)
        self.jobs.start(run)
        self.assertFalse(self.jobs.should_stop(run.receipt))
        with self.assertRaisesRegex(ValueError,"chat_session_busy"):
            self.jobs.start(server.ChatJobRequest(message="other",receipt=uuid4().hex,session_id=run.session_id))
        self.assertTrue(tunnel_access.allowed_path("/api/chat/stop","POST"))
        self.assertEqual(server.stop_chat_job(server.ChatJobReceipt(receipt=run.receipt)),{"status":"stopping"})
        self.assertTrue(self.jobs.should_stop(run.receipt))

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
