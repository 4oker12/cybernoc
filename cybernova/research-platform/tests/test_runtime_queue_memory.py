import unittest
import tempfile
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console.communication import CommunicationStore, CommunicationError
from console.profile_settings import default_settings, normalize_settings, relevant_memory

class RuntimeQueueMemoryTests(unittest.TestCase):
    def test_schedule_isolated_and_claimed_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=CommunicationStore(Path(tmp)/"state.sqlite")
            future=store.schedule_text("Future task", "2099-01-01T00:00:00+00:00")
            first=store.schedule_text("First task", "2020-01-01T00:00:00+00:00")
            second=store.schedule_text("Second task", "2020-01-01T00:00:00+00:00")
            self.assertIsNone(store.claim_queued())
            with ThreadPoolExecutor(max_workers=3) as pool:
                claims=list(pool.map(lambda _: store.claim_queued(text_only=True), range(3)))
            self.assertEqual({x["task_id"] for x in claims if x}, {first["task_id"], second["task_id"]})
            self.assertEqual(store.cancel_scheduled(future["task_id"])["status"], "blocked")
            self.assertIsNone(store.claim_queued(text_only=True))
            with self.assertRaises(CommunicationError):
                store.append(first["task_id"], "human", "instruction", "duplicate", status="running", require_available=True)

    def test_latest_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=CommunicationStore(Path(tmp)/"state.sqlite")
            task=store.create_task("History")["task_id"]
            for i in range(105):
                store.append(task, "human", "instruction", str(i))
            rows=store.recent_dialog(task, 100)["messages"]
            self.assertEqual((rows[0]["body"],rows[-1]["body"]),("5","104"))

    def test_memory_and_budget(self):
        settings=default_settings()
        settings["researcher"]["memory_notes"]="DNS: проверять резолверы\nPython: проверять версию"
        self.assertIn("DNS",relevant_memory(settings,"Проверь DNS"))
        self.assertNotIn("Python",relevant_memory(settings,"Проверь DNS"))
        settings["privacy"]["share_with_researcher"]=False
        self.assertEqual(relevant_memory(settings,"DNS"),"")
        self.assertEqual(normalize_settings({})["researcher"]["input_budget"],120000)
