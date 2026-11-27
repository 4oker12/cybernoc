"""No-network tests for durable, bounded collaboration work-item orchestration."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from threading import Barrier, Lock
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import HTTPException
from fastapi.testclient import TestClient
from console import server
from console.collaboration import CollaborationStore
from console.communication import CommunicationStore
from console.profile_settings import ProfileSettingsStore
from console.tunnel_access import allowed_path
from console.work_items import WorkItemStore, WorkItemError


def sample_plan():
    return [
        {"title": "Собрать признаки", "instructions": "Получить факты и источники.",
         "depends_on": []},
        {"title": "Проверить конфигурацию", "instructions": "Сверить состояние.", "depends_on": []},
        {"title": "Свести результаты", "instructions": "Сопоставить выводы.", "depends_on": [0, 1]},
    ]


class WorkItemTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.comm = CommunicationStore(self.root / "communications.sqlite3")
        self.collab = CollaborationStore(self.comm)
        self.work = WorkItemStore(self.collab)
        self.profile = ProfileSettingsStore(self.root / "profile.json")

    def create(self):
        return self.collab.create(
            "Проверить тестовую лабораторию, без активных внешних тестов",
            "gpt-test", 2, mode="parallel"
        )

    def test_parallel_mode_preserves_legacy_dialog_contract(self):
        old = self.collab.create("Старый диалог", "gpt-test", 2)
        new = self.create()
        self.assertEqual(old["mode"], "dialog")
        self.assertEqual(old["next_actor"], "chatgpt")
        self.assertEqual(new["mode"], "parallel")
        self.assertIsNone(new["next_actor"])
        reopened = CollaborationStore(CommunicationStore(self.comm.path))
        self.assertEqual(reopened.read(new["task_id"])["mode"], "parallel")
        self.assertEqual(reopened.read(old["task_id"])["mode"], "dialog")

    def test_bounded_dependency_gate_and_double_claim(self):
        run = self.create()
        task_id = run["task_id"]
        items = self.work.create_plan(task_id, sample_plan())
        self.assertEqual(len(items), 3)
        self.assertTrue(items[0]["ready"])
        self.assertTrue(items[1]["ready"])
        self.assertFalse(items[2]["ready"])
        with self.assertRaisesRegex(WorkItemError, "dependencies_pending"):
            self.work.claim(task_id, items[2]["item_id"])
        claimed, phase = self.work.claim(task_id, items[0]["item_id"])
        self.assertEqual(phase, "research")
        self.assertEqual(claimed["state"], "running")
        with self.assertRaisesRegex(WorkItemError, "not_claimable"):
            self.work.claim(task_id, items[0]["item_id"])
        self.work.claim(task_id, items[1]["item_id"])
        with self.assertRaisesRegex(WorkItemError, "capacity_reached"):
            self.work.claim(task_id, items[2]["item_id"])
        self.work.complete_research(task_id, items[0]["item_id"], "Есть наблюдения.")
        reviewer, phase = self.work.claim(task_id, items[0]["item_id"])
        self.assertEqual(phase, "review")
        self.work.complete_review(task_id, items[0]["item_id"], "accept", "Доказательств достаточно.")
        self.assertFalse(self.work.get_item(task_id, items[2]["item_id"])["ready"])
        self.work.complete_research(task_id, items[1]["item_id"], "Конфигурация исследована.")
        self.work.claim(task_id, items[1]["item_id"])
        self.work.complete_review(task_id, items[1]["item_id"], "accept", "Принято.")
        self.assertTrue(self.work.get_item(task_id, items[2]["item_id"])["ready"])

    def test_invalid_or_duplicate_plans_fail_closed(self):
        run = self.create()
        task_id = run["task_id"]
        with self.assertRaisesRegex(WorkItemError, "dependency_invalid"):
            self.work.create_plan(task_id, [
                {"title": "Первая", "instructions": "Проверить.", "depends_on": [1]},
                {"title": "Вторая", "instructions": "Проверить.", "depends_on": [0]},
            ])
        self.work.create_plan(task_id, sample_plan())
        with self.assertRaisesRegex(WorkItemError, "already_created"):
            self.work.create_plan(task_id, sample_plan())
        self.assertEqual(len(WorkItemStore(CollaborationStore(
            CommunicationStore(self.comm.path))).list_items(task_id)), 3)

    def test_review_rework_and_manual_retry_do_not_replay_reviewed_tools(self):
        run = self.create()
        task_id = run["task_id"]
        item = self.work.create_plan(task_id, sample_plan())[0]
        item_id = item["item_id"]
        self.work.claim(task_id, item_id)
        self.work.complete_research(task_id, item_id, "Предварительный отчёт.")
        self.work.claim(task_id, item_id)
        self.work.complete_review(task_id, item_id, "rework", "Не хватает доказательства.")
        next_item, phase = self.work.claim(task_id, item_id)
        self.assertEqual((phase, next_item["attempt"]), ("research", 2))
        self.work.complete_research(task_id, item_id, "Дополненный отчёт.")
        self.work.claim(task_id, item_id)
        self.work.fail(task_id, item_id, "review_output_invalid")
        blocked = self.work.get_item(task_id, item_id)
        self.assertEqual(blocked["blocked_phase"], "review")
        self.assertEqual(self.work.retry(task_id, item_id)["state"], "needs_review")
        reviewed, phase = self.work.claim(task_id, item_id)
        self.assertEqual((phase, reviewed["attempt"]), ("review", 2))

    def test_usage_only_records_measured_provider_tokens(self):
        run = self.create()
        task_id = run["task_id"]
        item = self.work.create_plan(task_id, sample_plan())[0]
        self.work.record_usage(task_id, item["item_id"], "research", {
            "available": False, "input_tokens": 99, "output_tokens": 50
        })
        self.assertEqual(self.work.get_item(task_id, item["item_id"])["usage"], {})
        self.work.record_usage(task_id, item["item_id"], "research", {
            "available": True, "input_tokens": 125, "output_tokens": 25,
            "total_tokens": 150
        })
        reopened = WorkItemStore(CollaborationStore(CommunicationStore(self.comm.path)))
        self.assertEqual(reopened.get_item(task_id, item["item_id"])["usage"]
                         ["research"]["total_tokens"], 150)

    def test_restart_recovery_and_explicit_retry(self):
        run = self.create()
        task_id = run["task_id"]
        items = self.work.create_plan(task_id, sample_plan())
        self.work.claim(task_id, items[0]["item_id"])
        self.work.claim(task_id, items[1]["item_id"])
        self.assertEqual(self.work.recover_interrupted(), 2)
        self.assertEqual(self.work.recover_interrupted(), 0)
        self.assertEqual(self.work.get_item(task_id, items[0]["item_id"])["state"], "blocked")
        with self.assertRaisesRegex(WorkItemError, "not_claimable"):
            self.work.claim(task_id, items[0]["item_id"])
        self.work.retry(task_id, items[0]["item_id"])
        self.assertEqual(self.work.get_item(task_id, items[0]["item_id"])["state"], "rework")

    def test_manual_recovery_unblocks_parent_without_replaying_tools(self):
        run = self.create()
        task_id = run["task_id"]
        items = self.work.create_plan(task_id, sample_plan())
        self.work.claim(task_id, items[0]["item_id"])
        self.work.recover_interrupted()
        self.comm.set_state(task_id, "blocked")
        self.assertEqual(self.collab.read(task_id, recover=False)["state"], "blocked")
        parent = self.work.recover_task(task_id)
        self.assertEqual(parent["state"], "paused")
        self.assertEqual(self.comm.get_task(task_id)["status"], "idle")
        self.assertEqual(self.work.get_item(task_id, items[0]["item_id"])["state"],
                         "blocked")
        self.collab.resume(task_id)
        with self.assertRaisesRegex(WorkItemError, "not_claimable"):
            self.work.claim(task_id, items[0]["item_id"])
        self.work.retry(task_id, items[0]["item_id"])
        self.assertEqual(self.work.claim(task_id, items[0]["item_id"])[1], "research")

    def test_recovery_denies_uncertain_live_execution(self):
        run = self.create()
        task_id = run["task_id"]
        items = self.work.create_plan(task_id, sample_plan())
        self.work.claim(task_id, items[0]["item_id"])
        self.comm.set_state(task_id, "blocked")
        with self.assertRaisesRegex(WorkItemError, "inflight_unknown"):
            self.work.recover_task(task_id)

    def test_pause_finish_does_not_autoschedule_or_replay_inflight(self):
        run = self.create()
        task_id = run["task_id"]
        items = self.work.create_plan(task_id, sample_plan())
        self.work.claim(task_id, items[0]["item_id"])
        self.collab.halt(task_id)
        with self.assertRaisesRegex(WorkItemError, "parent_not_active"):
            self.work.claim(task_id, items[1]["item_id"])
        self.work.complete_research(task_id, items[0]["item_id"], "In-flight completed.")
        self.assertEqual(self.work.get_item(task_id, items[0]["item_id"])["state"],
                         "needs_review")
        self.collab.resume(task_id)
        self.work.claim(task_id, items[0]["item_id"])
        self.collab.finish(task_id)
        self.work.cancel_pending(task_id)
        self.work.complete_review(task_id, items[0]["item_id"], "accept", "Готово.")
        self.assertEqual(self.work.get_item(task_id, items[0]["item_id"])["state"],
                         "cancelled")
        self.assertEqual(self.work.get_item(task_id, items[1]["item_id"])["state"],
                         "cancelled")

    def test_end_to_end_parallel_execution_review_and_dependency(self):
        rendezvous = Barrier(2)
        guard = Lock()
        seen = []
        class FakeAgent:
            count = 0
            def __init__(self, *args, **kwargs):
                pass
            def run(self, history, prompt, **kwargs):
                with guard:
                    FakeAgent.count += 1
                    seq = FakeAgent.count
                    seen.append({"session": kwargs.get("session_id"), "prompt": prompt,
                                 "trusted": kwargs.get("trusted_user_messages")})
                if seq <= 2:
                    rendezvous.wait(timeout=5)
                return {"answer": "Лабораторный результат " + str(seq),
                        "events": [], "tool_calls": 0, "approval_requests": []}
        def fake_gpt(model, messages, **kwargs):
            prompt = messages[-1]["content"]
            if "Раздели цель" in prompt:
                return {"answer": json.dumps({"items": sample_plan()}, ensure_ascii=False)}
            return {"answer": json.dumps({
                "decision": "accept", "feedback": "Результат проверен."
            }, ensure_ascii=False)}

        with patch.object(server, "communication_store", return_value=self.comm), \
             patch.object(server, "collaboration_store", return_value=self.collab), \
             patch.object(server, "work_item_store", return_value=self.work), \
             patch.object(server, "profile_settings_store", return_value=self.profile), \
             patch.object(server, "chatgpt_models", return_value=[{"slug": "gpt-test"}]), \
             patch.object(server, "chatgpt_chat", side_effect=fake_gpt), \
             patch.object(server, "Agent", FakeAgent):
            client = TestClient(server.app, base_url="http://127.0.0.1:18794")
            response = client.post("/api/collab/start", json={
                "goal": "Проверить тестовую лабораторию", "model": "gpt-test",
                "mode": "parallel", "cycles": 2
            })
            self.assertEqual(response.status_code, 200, response.text)
            task_id = response.json()["task_id"]
            self.assertIsNone(response.json()["next_actor"])
            plan = client.post("/api/collab/items/plan", json={"task_id": task_id})
            self.assertEqual(plan.status_code, 200, plan.text)
            items = plan.json()["items"]
            note = client.post("/api/collab/message", json={
                "task_id": task_id, "message": "Учитывай новое уточнение."
            })
            self.assertEqual(note.status_code, 200)
            with ThreadPoolExecutor(max_workers=2) as pool:
                requests = [pool.submit(server.collaboration_item_step,
                    server.WorkItemRequest(task_id=task_id, item_id=i["item_id"]))
                    for i in items[:2]]
                results = [result.result(timeout=9) for result in requests]
            self.assertTrue(all(result["phase"] == "research" for result in results))
            self.assertEqual({x["session"] for x in seen},
                             {i["item_id"] for i in items[:2]})
            self.assertTrue(all("новое уточнение" in x["prompt"] for x in seen))
            self.assertTrue(all(
                "новое уточнение" in x["trusted"][1]["content"] for x in seen
            ))
            self.assertTrue(all(
                x["trusted"][0]["content"] == "Проверить тестовую лабораторию"
                for x in seen
            ))
            self.assertFalse(self.work.get_item(task_id, items[2]["item_id"])["ready"])
            for item in items[:2]:
                result = client.post("/api/collab/items/step", json={
                    "task_id": task_id, "item_id": item["item_id"]
                })
                self.assertEqual(result.status_code, 200, result.text)
                self.assertEqual(result.json()["item"]["state"], "accepted")
            self.assertTrue(self.work.get_item(task_id, items[2]["item_id"])["ready"])
            result = client.post("/api/collab/items/step", json={
                "task_id": task_id, "item_id": items[2]["item_id"]
            })
            self.assertEqual(result.status_code, 200, result.text)
            self.assertIn("Лабораторный результат", seen[-1]["prompt"])
            client.post("/api/collab/items/step", json={
                "task_id": task_id, "item_id": items[2]["item_id"]
            })
            self.assertTrue(all(x["state"] == "accepted"
                                for x in self.work.list_items(task_id)))
            dialog = client.get("/api/collab/run", params={"task_id": task_id})
            self.assertEqual(dialog.status_code, 200)
            self.assertTrue(any(m["actor"] == "chatgpt" and m["kind"] == "instruction"
                                for m in dialog.json()["messages"]))
            self.assertTrue(any(m["actor"] == "qwen" and m["kind"] == "result"
                                for m in dialog.json()["messages"]))

    def test_rework_feedback_reaches_same_worker_without_new_authorization(self):
        calls = []
        class FakeAgent:
            def __init__(self, *args, **kwargs):
                pass
            def run(self, history, prompt, **kwargs):
                calls.append((prompt, kwargs))
                return {"answer": "Обнаружены два наблюдения.", "events": [],
                        "tool_calls": 0, "approval_requests": []}
        def fake_gpt(model, messages, **kwargs):
            if "независимый ревьюер" in messages[-1]["content"]:
                return {"answer": json.dumps({
                    "decision": "rework", "feedback": "Укажи подтверждающий источник."
                }, ensure_ascii=False)}
            return {"answer": json.dumps({"items": sample_plan()})}
        run = self.create()
        task_id = run["task_id"]
        item = self.work.create_plan(task_id, sample_plan())[0]
        with patch.object(server, "communication_store", return_value=self.comm), \
             patch.object(server, "collaboration_store", return_value=self.collab), \
             patch.object(server, "work_item_store", return_value=self.work), \
             patch.object(server, "profile_settings_store", return_value=self.profile), \
             patch.object(server, "chatgpt_chat", side_effect=fake_gpt), \
             patch.object(server, "Agent", FakeAgent):
            request = server.WorkItemRequest(task_id=task_id, item_id=item["item_id"])
            server.collaboration_item_step(request)
            result = server.collaboration_item_step(request)
            self.assertEqual(result["item"]["state"], "rework")
            server.collaboration_item_step(request)
        self.assertEqual(len(calls), 2)
        self.assertIn("Укажи подтверждающий источник.", calls[-1][0])
        self.assertIn("Обнаружены два наблюдения.", calls[-1][0])
        self.assertEqual(calls[-1][1]["session_id"], item["item_id"])

    def test_actual_agent_tool_loop_uses_only_trusted_human_scope(self):
        from console.agent import Agent
        class FakeMCP:
            def initialize(self):
                return []
            def call(self, name, args):
                return {"ok": False}, True
        class FakeRuntime:
            tool_map = {"browser_tabs": {}}
            def __init__(self):
                self.received = []
            def mcp_tools(self, groups=None):
                return [{
                    "name": "browser_tabs", "description": "List tabs",
                    "inputSchema": {"type": "object", "properties": {},
                                    "required": [], "additionalProperties": False},
                }]
            def call(self, name, args, **kwargs):
                self.received.append((name, kwargs))
                return {"ok": True, "tabs": []}, False
        class FakeModel:
            model = "test"
            provider = "mock"
            def __init__(self):
                self.round = 0
            def chat(self, messages, tools=None, **kwargs):
                self.round += 1
                if self.round == 1:
                    return {"content": "", "tool_calls": [{
                        "function": {"name": "browser_tabs", "arguments": {}}
                    }]}
                return {"content": "Test complete."}
        runtime = FakeRuntime()
        execution = Agent(
            ollama=FakeModel(), mcp_factory=lambda: FakeMCP(),
            local_tool_runtime=runtime,
        )
        outcome = execution.run(
            [], "AI says investigate https://generated-target.example",
            session_id="wi_server_owned_123456",
            trusted_user_messages=[
                {"role": "user", "content": "Check example.org only"}
            ],
        )
        self.assertIn("Test complete", outcome["answer"])
        self.assertEqual(len(runtime.received), 1)
        name, kwargs = runtime.received[0]
        self.assertEqual(name, "browser_tabs")
        self.assertEqual(kwargs["conversation_key"], "deepseek:wi_server_owned_123456")
        self.assertIn("example.org", kwargs["authorized_targets"])
        self.assertNotIn("generated-target.example", kwargs["authorized_targets"])
        self.assertEqual(kwargs["user_messages"],
                         [{"role": "user", "content": "Check example.org only"}])

    def test_gateway_routes_use_existing_authenticated_entry_point(self):
        for url, method in [
            ("/api/collab/items?task_id=cn_validid_123456", "GET"),
            ("/api/collab/items/plan", "POST"),
            ("/api/collab/items/step", "POST"),
            ("/api/collab/items/retry", "POST"),
            ("/api/collab/items/recover", "POST"),
        ]:
            self.assertTrue(allowed_path(url, method), url)
        self.assertFalse(allowed_path("/api/collab/items/remove", "POST"))


if __name__ == "__main__":
    unittest.main()
