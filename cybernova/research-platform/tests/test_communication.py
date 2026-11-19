"""No-network tests of the shared ChatGPT/Qwen communication gateway."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.communication import CommunicationError, CommunicationStore
from console.communication_tools import CommunicationToolClient, COMMUNICATION_TOOLS
from console.communication_worker import CommunicationWorker
from console.tool_policy import model_tools, REVIEWED_TOOLS


class NoUpstream:
    def initialize(self):
        return []
    def call(self, name, args):
        raise AssertionError("Unexpected upstream MCP call: " + name)


class FakeAgent:
    def __init__(self, answer, *, review=False, store=None, task_id=None, fail=False):
        self.answer = answer
        self.review = review
        self.store = store
        self.task_id = task_id
        self.fail = fail
        self.calls = []
    def run(self, history, prompt, **kwargs):
        self.calls.append((history, prompt))
        if self.fail:
            raise RuntimeError("model error")
        if self.review:
            self.store.mark_review(self.task_id, "Проверь гипотезу", ["har:abc123"])
        return {
            "answer": self.answer, "events": [], "tool_calls": 1,
            "approval_requests": [], "selected_by": "test",
        }


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "comm.sqlite3"
        self.db = CommunicationStore(self.path)
        self.task = self.db.create_task("Аудит учебного API")

    def test_new_task_is_idle_not_claimable(self):
        self.assertEqual(self.task["status"], "idle")
        self.assertIsNone(self.db.claim_queued())

    def test_persistence_and_shared_cursor(self):
        self.db.append(self.task["task_id"], "human", "instruction", "Изучи приложение",
                       status="running")
        first = self.db.append(self.task["task_id"], "qwen", "result",
                               "Нашёл гипотезу", status="completed")
        reopened = CommunicationStore(self.path)
        dialog = reopened.read_dialog(self.task["task_id"])
        self.assertEqual(len(dialog["messages"]), 2)
        self.assertEqual(dialog["messages"][1]["seq"], first["seq"])
        self.assertEqual(dialog["task"]["status"], "completed")
        self.assertEqual(reopened.read_dialog(
            self.task["task_id"], after=first["seq"]
        )["messages"], [])
        self.assertEqual(len(reopened.events(after=0)["messages"]), 2)

    def test_idempotency_key_does_not_queue_second_time(self):
        self.db.append(self.task["task_id"], "qwen", "result", "Ответ",
                       status="needs_review")
        first = self.db.send_feedback(self.task["task_id"], "Перепроверь",
                                      event_key="review_event_123456")
        self.db.set_state(self.task["task_id"], "completed")
        second = self.db.send_feedback(self.task["task_id"], "Совершенно другое",
                                       event_key="review_event_123456")
        self.assertEqual(first["seq"], second["seq"])
        self.assertEqual(self.db.get_task(self.task["task_id"])["status"],
                         "completed")
        self.assertEqual(len(self.db.read_dialog(self.task["task_id"])["messages"]), 2)

    def test_qwen_review_request_chatgpt_feedback_cycle(self):
        tid = self.task["task_id"]
        self.db.append(tid, "human", "instruction", "Изучи объект",
                       status="running")
        self.db.append(tid, "qwen", "result", "Возможная ошибка",
                       status="completed")
        self.db.mark_review(tid, "ChatGPT, проверь вывод", ["har:abc123"])
        reviews = self.db.events(review_only=True)
        self.assertEqual(len(reviews["messages"]), 1)
        self.assertEqual(reviews["messages"][0]["actor"], "qwen")
        self.assertEqual(self.db.get_task(tid)["status"], "needs_review")
        feedback = self.db.send_feedback(tid, "Проверь негативный контроль")
        self.assertEqual(feedback["actor"], "chatgpt")
        self.assertEqual(self.db.get_task(tid)["status"], "queued")
        fake = FakeAgent("Негативный контроль пройден")
        worker = CommunicationWorker(self.db, agent_factory=lambda _: fake)
        finished = worker.run_once()
        self.assertEqual(finished["status"], "completed")
        self.assertEqual(self.db.get_task(tid)["status"], "completed")
        self.assertIn("негативный контроль",
                      fake.calls[0][1].lower())
        self.assertIn("Возможная ошибка",
                      str(fake.calls[0][0]))
        self.assertEqual(self.db.read_dialog(tid)["messages"][-1]["actor"], "qwen")

    def test_worker_can_request_second_independent_review(self):
        tid = self.task["task_id"]
        self.db.append(tid, "chatgpt", "instruction", "Проверь гипотезу",
                       status="queued")
        fake = FakeAgent("Нужен эксперт", review=True,
                         store=self.db, task_id=tid)
        result = CommunicationWorker(self.db, agent_factory=lambda _: fake).run_once()
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(self.db.get_task(tid)["status"], "needs_review")
        reviews = self.db.events(review_only=True)
        self.assertEqual(len(reviews["messages"]), 1)

    def test_worker_error_stays_blocked_not_retried_forever(self):
        tid = self.task["task_id"]
        self.db.append(tid, "chatgpt", "instruction", "Проверь",
                       status="queued")
        result = CommunicationWorker(
            self.db, agent_factory=lambda _: FakeAgent("", fail=True)
        ).run_once()
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(self.db.claim_queued())
        last = self.db.read_dialog(tid)["messages"][-1]
        self.assertEqual(last["kind"], "system")
        self.assertNotIn("model error", last["body"])

    def test_atomic_claim_only_one_worker(self):
        tid = self.task["task_id"]
        self.db.append(tid, "chatgpt", "instruction", "Выполнить",
                       status="queued")
        found = []
        def claim():
            found.append(self.db.claim_queued())
        threads = [threading.Thread(target=claim) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len([x for x in found if x is not None]), 1)

    def test_invalid_messages_and_refs_are_rejected(self):
        tid = self.task["task_id"]
        invalid = [
            ("unknown", "progress", "OK"),
            ("qwen", "malicious", "OK"),
            ("qwen", "progress", ""),
            ("qwen", "progress", "x" * 12001),
        ]
        for actor, kind, body in invalid:
            with self.assertRaises(CommunicationError):
                self.db.append(tid, actor, kind, body)
        with self.assertRaises(CommunicationError):
            self.db.mark_review(tid, "Просмотр", ["../../private?x=secret"])
        with self.assertRaises(CommunicationError):
            self.db.get_task("anything' OR 1=1")

    def test_task_bound_tools_cannot_impersonate_chatgpt(self):
        tid = self.task["task_id"]
        client = CommunicationToolClient(NoUpstream(), self.db, tid)
        names = [x["name"] for x in client.initialize()]
        self.assertEqual(names, [x["name"] for x in COMMUNICATION_TOOLS])
        self.assertTrue(set(names) <= REVIEWED_TOOLS)
        self.assertEqual(
            [x["function"]["name"] for x in model_tools(client.initialize())], names
        )
        update, failed = client.call("comm_post_progress",
                                     {"summary": "Разбираю журнал"})
        self.assertFalse(failed)
        review, failed = client.call("comm_request_review",
                                      {"question": "Проверь аргументацию",
                                       "evidence_refs": ["pcap:123"]})
        self.assertFalse(failed)
        self.assertEqual(review["status"], "needs_review")
        self.assertEqual(self.db.get_task(tid)["status"], "needs_review")
        dialog, failed = client.call("comm_read_dialog", {})
        self.assertFalse(failed)
        self.assertEqual(len(dialog["messages"]), 2)
        self.assertTrue(all(item["actor"] == "qwen" for item in dialog["messages"]))
        other = self.db.create_task("Другая задача")
        with self.assertRaises(AssertionError):
            client.call("comm_read_other_task", {"task_id": other["task_id"]})


if __name__ == "__main__":
    unittest.main()
