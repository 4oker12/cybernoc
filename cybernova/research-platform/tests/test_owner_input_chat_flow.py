"""A running receipt can request protected input and resume the same turn."""
import threading
import time
import unittest
from uuid import uuid4
from unittest.mock import patch

from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from console import server


class OwnerInputChatFlowTests(unittest.TestCase):
    def setUp(self):
        self.sid = uuid4().hex
        self.run = server.ChatJobRequest(
            session_id=self.sid, message="controlled test form", receipt=uuid4().hex,
        )
        server._session(self.sid)
        self.client = TestClient(server.app, base_url="http://127.0.0.1:18794")

    def tearDown(self):
        with server.chat_jobs_lock:
            server.chat_jobs.pop(self.run.receipt, None)
        with server.sessions_lock:
            server.sessions.pop(self.sid, None)

    def _exercise(self, cancel=False):
        consumed = []

        def fake_chat(payload):
            self.assertEqual(payload.session_id, self.sid)
            answer = server.owner_input_broker.request_and_wait(
                "deepseek:" + self.sid, "Controlled form", "otp", "Code",
                timeout=4, expected_origin="https://example.test",
            )
            if answer["ok"]:
                consumed.append(server.owner_input_broker.consume(
                    "deepseek:" + self.sid, answer["request_id"],
                ))
            return {"session_id": self.sid,
                    "answer": "continued" if answer["ok"] else "input cancelled"}

        background = BackgroundTasks()
        self.assertEqual(server.start_chat_job(self.run, background)["status"], "queued")
        with patch.object(server, "chat", side_effect=fake_chat):
            worker = threading.Thread(target=server._complete_chat_job, args=(self.run,))
            worker.start()
            try:
                pending = None
                until = time.monotonic() + 3
                while time.monotonic() < until:
                    response = self.client.post("/api/chat/result",
                                                json={"receipt": self.run.receipt})
                    self.assertEqual(response.status_code, 200)
                    pending = response.json()["owner_input"]
                    if pending:
                        self.assertEqual(response.json()["state"], "waiting_for_owner_input")
                        break
                    time.sleep(0.02)
                self.assertIsNotNone(pending)
                self.assertNotIn("value", pending)
                endpoint = "/api/owner-input/cancel" if cancel else "/api/owner-input/submit"
                body = {"session_id": self.sid, "request_id": pending["request_id"]}
                if not cancel:
                    body["value"] = "123456"  # Test value, never a real OTP.
                response = self.client.post(endpoint, json=body)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertNotIn("123456", response.text)
            finally:
                worker.join(5)
        self.assertFalse(worker.is_alive())
        result = self.client.post("/api/chat/result", json={"receipt": self.run.receipt})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["state"], "completed")
        self.assertEqual(result.json()["result"]["session_id"], self.sid)
        self.assertNotIn("123456", result.text)
        if cancel:
            self.assertEqual(consumed, [])
            self.assertEqual(result.json()["result"]["answer"], "input cancelled")
        else:
            self.assertEqual(consumed, [("otp", "123456", "https://example.test")])
            self.assertEqual(result.json()["result"]["answer"], "continued")

    def test_submit_continues_same_receipt(self):
        self._exercise()

    def test_cancel_unblocks_same_receipt(self):
        self._exercise(cancel=True)


if __name__ == "__main__":
    unittest.main()
