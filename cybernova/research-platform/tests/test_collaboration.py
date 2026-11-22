"""No-network tests for bounded, persisted two-agent collaboration."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient
from console import server
from console.collaboration import (
    CollaborationStore, CollaborationError, MENTOR_PROFILE,
    mentor_messages, researcher_messages,
)
from console.communication import CommunicationStore
from console.profile_settings import ProfileSettingsStore
from console.tunnel_access import allowed_path


class CollaborationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.comm = CommunicationStore(self.root / "communications.sqlite3")
        self.collab = CollaborationStore(self.comm)
        self.profile = ProfileSettingsStore(self.root / "profile.json")

    def test_moderated_turns_and_persistence(self):
        run = self.collab.create("Найди ошибку в лабораторном API", "gpt-test", 2)
        task_id = run["task_id"]
        self.assertEqual(run["next_actor"], "chatgpt")
        self.assertEqual(run["step"], 0)
        run = self.collab.advance(task_id, "chatgpt", "Задание DeepSeek: проверь API")
        self.assertEqual(run["next_actor"], "qwen")
        history, prompt = researcher_messages(run)
        self.assertIn("Наставник ChatGPT", prompt)
        self.assertIn("лабораторном API", history[0]["content"])
        run = self.collab.advance(task_id, "qwen", "Собраны признаки API")
        self.assertEqual(run["next_actor"], "chatgpt")
        messages = mentor_messages(run)
        self.assertEqual([x["role"] for x in messages], ["user", "assistant", "user"])
        run = self.collab.advance(task_id, "chatgpt", "Повтори проверку с исправлением")
        run = self.collab.advance(task_id, "qwen", "Исправленная версия не воспроизводит проблему")
        self.assertEqual(run["state"], "paused")
        self.assertEqual(run["step"], 4)
        self.assertIsNone(run["next_actor"])
        self.assertEqual(self.comm.get_task(task_id)["status"], "idle")
        resumed = self.collab.resume(task_id)
        self.assertEqual(resumed["state"], "active")
        self.assertEqual(resumed["pause_at"], 8)
        self.assertEqual(self.comm.get_task(task_id)["status"], "running")
        run = self.collab.advance(task_id, "chatgpt", "Продолжим диагностику")
        self.assertEqual(run["state"], "active")
        run = self.collab.finish(task_id)
        self.assertEqual(run["state"], "completed")
        reopened = CollaborationStore(CommunicationStore(self.comm.path))
        self.assertTrue(any(m["body"] == "Продолжим диагностику"
                            for m in reopened.read(task_id)["messages"]))
        with self.assertRaisesRegex(CollaborationError, "not_active"):
            reopened.advance(task_id, "qwen", "Ещё одна попытка")

    def test_human_intervention_is_visible_to_both_agents(self):
        run = self.collab.create("Исследовать тестовую лабораторию", "gpt-test", 2)
        task_id = run["task_id"]
        self.collab.advance(task_id, "chatgpt", "DeepSeek, проверь журнал.")
        run = self.collab.user_message(task_id, "Учитывай также мой дополнительный вывод.")
        self.assertTrue(any(m["actor"] == "human" and
                            m["body"] == "Учитывай также мой дополнительный вывод."
                            for m in run["messages"]))
        history, prompt = researcher_messages(run)
        self.assertIn("дополнительный вывод", prompt)
        self.collab.advance(task_id, "qwen", "Проверка выполнена.")
        mentor_history = mentor_messages(self.collab.read(task_id))
        self.assertTrue(any("дополнительный вывод" in item["content"]
                            for item in mentor_history))

    def test_collaboration_locks_are_per_task(self):
        first = server._collaboration_step_lock("cn_task_one_123456")
        self.assertIs(first, server._collaboration_step_lock("cn_task_one_123456"))
        second = server._collaboration_step_lock("cn_task_two_123456")
        self.assertIsNot(first, second)

    def test_stop_does_not_advance(self):
        run = self.collab.create("Проверь тестовый проект", "gpt-test", 3)
        run = self.collab.halt(run["task_id"])
        self.assertEqual(run["state"], "paused")
        with self.assertRaisesRegex(CollaborationError, "not_active"):
            self.collab.advance(run["task_id"], "chatgpt", "late response")

    def test_interrupted_message_commit_blocks_replay(self):
        run = self.collab.create("Проверка безопасной лаборатории", "gpt-test", 2)
        self.comm.append(run["task_id"], "chatgpt", "feedback",
                         "Ответ записан, но курсор не обновился", status="running")
        recovered = CollaborationStore(CommunicationStore(self.comm.path)).read(run["task_id"])
        self.assertEqual(recovered["state"], "blocked")
        with self.assertRaisesRegex(CollaborationError, "not_active"):
            self.collab.advance(run["task_id"], "chatgpt", "Повтор после сбоя")

    def test_approval_does_not_autorun(self):
        run = self.collab.create("Изучить локальную лабораторию", "gpt-test", 1)
        self.collab.advance(run["task_id"], "chatgpt", "Задание")
        blocked = self.collab.advance(run["task_id"], "qwen", "Требуется разрешение",
                                      blocked=True)
        self.assertEqual(blocked["state"], "blocked")
        self.assertEqual(blocked["next_actor"], None)
        with self.assertRaises(CollaborationError):
            self.collab.advance(run["task_id"], "chatgpt", "Продолжить")

    def test_wrong_actor_and_cycles_rejected(self):
        run = self.collab.create("Анализ кейса", "gpt-test", 1)
        with self.assertRaisesRegex(CollaborationError, "actor_mismatch"):
            self.collab.advance(run["task_id"], "qwen", "Нельзя")
        with self.assertRaisesRegex(CollaborationError, "invalid_collaboration_cycles"):
            self.collab.create("Анализ", "gpt-test", 13)
        self.assertIn("ведущий инженер", MENTOR_PROFILE)

    def test_seven_cycle_batches_pause_and_resume_without_losing_history(self):
        run=self.collab.create("Семь обменов", "gpt-test", 7)
        tid=run["task_id"]
        self.assertEqual(run["pause_at"],14)
        for i in range(14):
            actor="chatgpt" if i%2==0 else "qwen"
            run=self.collab.advance(tid,actor,"Сообщение номер "+str(i+1))
        self.assertEqual(run["state"],"paused")
        self.assertEqual(run["step"],14)
        self.assertEqual(run["max_cycles"],7)
        recent=self.collab.resume(tid)
        self.assertEqual(recent["pause_at"],28)
        self.assertEqual(recent["next_actor"],"chatgpt")
        run=self.collab.advance(tid,"chatgpt","Сообщение после паузы")
        self.assertEqual(run["step"],15)
        self.assertIn("Сообщение после паузы",
                      [m["body"] for m in self.collab.read(tid)["messages"]])
        self.collab.halt(tid)
        self.assertEqual(self.collab.read(tid)["state"],"paused")
        self.assertEqual(self.collab.finish(tid)["state"],"completed")

    def test_old_collaboration_schema_migrates_without_deleting_data(self):
        from sqlite3 import connect
        legacy=Path(self.root)/"legacy.sqlite3"
        previous_comm=CommunicationStore(legacy)
        with connect(legacy) as db:
            db.execute("""
                CREATE TABLE collaboration_runs (
                    task_id TEXT PRIMARY KEY, model TEXT NOT NULL,
                    goal TEXT NOT NULL, max_cycles INTEGER NOT NULL,
                    step INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                )
            """)
        store=CollaborationStore(previous_comm)
        run=store.create("Исходная задача","gpt-test",5)
        self.assertEqual(run["pause_at"],10)
        self.assertEqual(CollaborationStore(CommunicationStore(legacy)).read(
                         run["task_id"])["goal"],"Исходная задача")

    def test_http_real_two_model_turns_with_mocked_inference(self):
        class FakeResearchAgent:
            def __init__(self, *args, **kwargs):
                pass
            def run(self, history, prompt, **kwargs):
                self.prompt = prompt
                return {
                    "answer": "DeepSeek: проверил локальные данные, активных сканов не было.",
                    "events": [], "tool_calls": 0, "approval_requests": [],
                }

        calls = []
        def fake_gpt(model, messages, **kwargs):
            calls.append((messages, kwargs))
            return {"answer": "Наставник: поставь гипотезу и проверь источник.",
                    "model": model, "source": "offline"}
        with patch.object(server, "communication_store", return_value=self.comm), \
             patch.object(server, "collaboration_store", return_value=self.collab), \
             patch.object(server, "profile_settings_store", return_value=self.profile), \
             patch.object(server, "chatgpt_models", return_value=[{"slug":"gpt-test"}]), \
             patch.object(server, "chatgpt_chat", side_effect=fake_gpt), \
             patch.object(server, "Agent", FakeResearchAgent):
            client = TestClient(server.app, base_url="http://127.0.0.1:18794")
            created = client.post("/api/collab/start", json={
                "goal": "Проверить изолированное приложение",
                "model": "gpt-test", "cycles": 1,
            })
            self.assertEqual(created.status_code, 200, created.text)
            task_id = created.json()["task_id"]
            speakers = []
            for _ in range(2):
                response = client.post("/api/collab/step", json={"task_id": task_id})
                self.assertEqual(response.status_code, 200, response.text)
                speakers.append(response.json()["actor"])
            self.assertEqual(speakers, ["chatgpt", "qwen"])
            self.assertEqual(response.json()["run"]["state"], "paused")
            self.assertEqual(client.post("/api/collab/step",
                                         json={"task_id":task_id}).status_code,409)
            resumed=client.post("/api/collab/resume",json={"task_id":task_id})
            self.assertEqual(resumed.status_code,200,resumed.text)
            self.assertEqual(resumed.json()["pause_at"],4)
            for _ in range(2):
                response=client.post("/api/collab/step",json={"task_id":task_id})
                self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(response.json()["run"]["state"],"paused")
            finished=client.post("/api/collab/finish",json={"task_id":task_id})
            self.assertEqual(finished.status_code,200,finished.text)
            self.assertEqual(finished.json()["state"],"completed")
            self.assertEqual(len(calls), 2)
            self.assertIn("DeepSeek", calls[1][0][-1]["content"])
            self.assertIn("ведущий инженер", calls[0][1]["profile_instructions"])
            self.assertGreaterEqual(len(client.get("/api/collab/run",
                params={"task_id":task_id}).json()["messages"]),7)
            self.assertEqual(client.post("/api/collab/step",json={"task_id":task_id}).status_code,409)
            self.assertEqual(client.get("/api/collab/runs").status_code,200)

    def test_gateway_allows_only_exact_collaboration_routes(self):
        for path, method in [
            ("/api/collab/start", "POST"), ("/api/collab/step", "POST"),
            ("/api/collab/stop", "POST"), ("/api/collab/resume", "POST"),
            ("/api/collab/finish", "POST"), ("/api/collab/runs", "GET"),
            ("/api/collab/run?task_id=x", "GET"),
            ("/api/collab/message", "POST"), ("/api/tools/run", "POST"),
        ]:
            self.assertTrue(allowed_path(path,method),path)
        self.assertFalse(allowed_path("/api/tools/execute", "POST"))
        self.assertFalse(allowed_path("/api/collab/delete", "POST"))


if __name__ == "__main__":
    unittest.main()
