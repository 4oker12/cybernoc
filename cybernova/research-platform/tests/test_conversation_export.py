"""Complete, local-only export and durable scenario UI regression tests."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from console.communication import CommunicationStore
from console.collaboration import CollaborationStore
from console.siwc_chat_store import GPTChatStore
from console.conversation_export import export_data, to_markdown, render_export
from console.tunnel_access import allowed_path
from console import server


class ConversationExportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        database = Path(temp.name) / "chat.sqlite3"
        self.comm = CommunicationStore(database)
        self.collab = CollaborationStore(self.comm)
        self.gpt = GPTChatStore(database)

    def test_collaboration_exports_every_message_beyond_ui_window(self):
        run = self.collab.create("Аудит учебного API", "gpt-test", 3)
        tid = run["task_id"]
        for i in range(135):
            self.comm.append(tid, "controller", "system", "Системная запись " + str(i))
        self.collab.halt(tid)
        self.collab.update_goal(tid, "Изучить новую редакцию")
        result = export_data("collab", tid, self.comm, self.collab, self.gpt)
        self.assertEqual(len(result["messages"]), 138)
        self.assertEqual(result["title"], "Изучить новую редакцию")
        self.assertEqual(result["messages"][0]["content"], "Аудит учебного API")
        self.assertIn("Системная запись 134", result["messages"][-3]["content"])
        self.assertIn("Новая редакция задачи", result["messages"][-1]["content"])
        markdown = to_markdown(result)
        self.assertIn("Системная запись 0", markdown)
        self.assertIn("Системная запись 134", markdown)
        self.assertIn("Изучить новую редакцию", markdown)

    def test_gpt_export_exceeds_500_message_ui_limit(self):
        tid = self.gpt.save_exchange(None, "gpt-test", "Привет", "Здравствуйте")
        with self.gpt._connection() as db:
            for i in range(510):
                db.execute(
                    "INSERT INTO gpt_messages(thread_id,role,content,created_at) "
                    "VALUES(?,?,?,?)",
                    (tid, "assistant", "Сообщение " + str(i), "2026-11-19T00:00:00+00:00"),
                )
        self.assertEqual(len(self.gpt.get_thread(tid)["messages"]), 500)
        result = export_data("gpt", tid, self.comm, self.collab, self.gpt)
        self.assertEqual(len(result["messages"]), 512)
        self.assertEqual(result["messages"][0]["content"], "Привет")
        self.assertEqual(result["messages"][-1]["content"], "Сообщение 509")
        text, media, ext = render_export(result, "json")
        self.assertIn("Сообщение 509", text)
        self.assertIn("json", media)
        self.assertEqual(ext, "json")

    def test_research_export_stays_complete_and_preserves_evidence_refs(self):
        task = self.comm.create_task("Исследование")
        tid = task["task_id"]
        self.comm.append(tid, "human", "instruction", "Проверить заголовки")
        self.comm.append(tid, "qwen", "result", "Есть CSP", evidence_refs=["ev_sample"])
        result = export_data("research", tid, self.comm, self.collab, self.gpt)
        self.assertEqual(len(result["messages"]), 2)
        self.assertIn("Связанные доказательства: ev_sample", to_markdown(result))

    def test_http_export_is_only_an_explicit_get_with_valid_store_ids(self):
        task = self.comm.create_task("Полный журнал")
        self.comm.append(task["task_id"], "human", "instruction", "Исходное сообщение")
        self.assertTrue(allowed_path("/api/conversation/export?mode=research", "GET"))
        self.assertFalse(allowed_path("/api/conversation/export", "POST"))
        with patch.object(server, "communication_store", return_value=self.comm), \
             patch.object(server, "collaboration_store", return_value=self.collab), \
             patch.object(server, "gpt_chat_store", return_value=self.gpt):
            client = TestClient(server.app, base_url="http://127.0.0.1:18794")
            response = client.get("/api/conversation/export", params={
                "mode": "research", "id": task["task_id"], "format": "md",
            })
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn("Исходное сообщение", response.text)
            self.assertIn("attachment", response.headers["content-disposition"])
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(client.get("/api/conversation/export", params={
                "mode":"research", "id":task["task_id"], "format":"exe"
            }).status_code, 422)
            self.assertEqual(client.get("/api/conversation/export", params={
                "mode":"research", "id":"unknown_id", "format":"md"
            }).status_code, 404)


if __name__ == "__main__":
    unittest.main()
