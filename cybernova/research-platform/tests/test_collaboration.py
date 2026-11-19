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
        run = self.collab.advance(task_id, "chatgpt", "Итоговый отчёт")
        self.assertEqual(run["state"], "completed")
        self.assertEqual(run["step"], 5)
        self.assertIsNone(run["next_actor"])
        reopened = CollaborationStore(CommunicationStore(self.comm.path))
        self.assertEqual(reopened.read(task_id)["messages"][-1]["body"], "Итоговый отчёт")
        with self.assertRaisesRegex(CollaborationError, "not_active"):
            reopened.advance(task_id, "qwen", "Ещё одна попытка")

    def test_stop_does_not_advance(self):
        run = self.collab.create("Проверь тестовый проект", "gpt-test", 3)
        run = self.collab.halt(run["task_id"])
        self.assertEqual(run["state"], "stopped")
        with self.assertRaisesRegex(CollaborationError, "not_active"):
            self.collab.advance(run["task_id"], "chatgpt", "late response")

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
            self.collab.create("Анализ", "gpt-test", 5)
        self.assertIn("старший инженер", MENTOR_PROFILE)

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
        with patch.object(server, "communication_store", return_value=self.comm), \\
             patch.object(server, "collaboration_store", return_value=self.collab), \\
             patch.object(server, "profile_settings_store", return_value=self.profile), \\
             patch.object(server, "chatgpt_models", return_value=[{"slug":"gpt-test"}]), \\
             patch.object(server, "chatgpt_chat", side_effect=fake_gpt), \\
             patch.object(server, "Agent", FakeResearchAgent), \\
             patch.object(server, "gpt_tool_preflight",
                          return_value={"context": "", "events": []}):
            client = TestClient(server.app, base_url="http://127.0.0.1:18794")
            created = client.post("/api/collab/start", json={
                "goal": "Проверить изолированное приложение",
                "model": "gpt-test", "cycles": 1,
            })
            self.assertEqual(created.status_code, 200, created.text)
            task_id = created.json()["task_id"]
            speakers = []
            for _ in range(3):
                response = client.post("/api/collab/step", json={"task_id": task_id})
                self.assertEqual(response.status_code, 200, response.text)
                speakers.append(response.json()["actor"])
            self.assertEqual(speakers, ["chatgpt", "qwen", "chatgpt"])
            self.assertEqual(response.json()["run"]["state"], "completed")
            self.assertEqual(len(calls), 2)
            self.assertIn("DeepSeek", calls[1][0][-1]["content"])
            self.assertIn("ведущий инженер", calls[0][1]["profile_instructions"])
            self.assertEqual(len(client.get("/api/collab/run",params={"task_id":task_id}).json()["messages"]),4)
            self.assertEqual(client.post("/api/collab/step",json={"task_id":task_id}).status_code,409)
            self.assertEqual(client.get("/api/collab/runs").status_code,200)

    def test_gateway_allows_only_exact_collaboration_routes(self):
        for path, method in [
            ("/api/collab/start", "POST"), ("/api/collab/step", "POST"),
            ("/api/collab/stop", "POST"), ("/api/collab/runs", "GET"),
            ("/api/collab/run?task_id=x", "GET"), ("/api/tools/run", "POST"),
        ]:
            self.assertTrue(allowed_path(path,method),path)
        self.assertFalse(allowed_path("/api/tools/execute", "POST"))
        self.assertFalse(allowed_path("/api/collab/delete", "POST"))


if __name__ == "__main__":
    unittest.main()
