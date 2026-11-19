"""MCP tool-surface tests without running a network listener or importing SDK."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class FakeFastMCP:
    def __init__(self, *args, **kwargs):
        self.name = args[0]
        self.kwargs = kwargs
        self.tools = {}
    def tool(self):
        def decorator(func):
            self.tools[func.__name__] = func
            return func
        return decorator


class MCPGatewayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dbpath = str(Path(temp.name) / "gateway.sqlite3")
        root = types.ModuleType("mcp")
        root.__path__ = []
        server = types.ModuleType("mcp.server")
        server.__path__ = []
        fastmcp = types.ModuleType("mcp.server.fastmcp")
        fastmcp.FastMCP = FakeFastMCP
        with patch.dict(sys.modules, {
            "mcp": root, "mcp.server": server,
            "mcp.server.fastmcp": fastmcp,
        }), patch.dict(os.environ, {"CYBERNOVA_COMM_DB": self.dbpath}):
            path = ROOT / "console" / "communication_mcp.py"
            spec = importlib.util.spec_from_file_location(
                "console.communication_mcp_test", path,
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.module = module

    def test_all_eight_mcp_functions_are_actual_callable_tools(self):
        expected = {
            "cybernova_create_task", "cybernova_list_tasks",
            "cybernova_task_status", "cybernova_read_dialog",
            "cybernova_pending_reviews", "cybernova_new_events",
            "cybernova_send_feedback", "cybernova_evidence_index",
        }
        self.assertEqual(set(self.module.mcp.tools), expected)
        self.assertEqual(self.module.mcp.kwargs["host"], "127.0.0.1")
        self.assertEqual(self.module.mcp.kwargs["port"], 18796)

    def test_chatgpt_can_send_feedback_to_qwen_through_same_store(self):
        api = self.module
        task = api.cybernova_create_task("Проверка", "Исследуй стенд")
        tid = task["task_id"]
        self.assertEqual(api.cybernova_task_status(tid)["status"], "queued")
        self.assertEqual(api.cybernova_list_tasks()["tasks"][0]["task_id"], tid)
        queued = api.store.claim_queued()
        self.assertEqual(queued["task_id"], tid)
        api.store.mark_review(tid, "Проверь мою версию", ["har:12345"])
        self.assertEqual(len(api.cybernova_pending_reviews()["messages"]), 1)
        feedback = api.cybernova_send_feedback(tid, "Нужен второй контроль",
                                                "check_123456789")
        self.assertEqual(feedback["status"], "queued")
        self.assertEqual(api.cybernova_evidence_index(tid)["evidence_refs"],
                         ["har:12345"])
        dialog = api.cybernova_read_dialog(tid)
        self.assertEqual(len(dialog["messages"]), 3)
        self.assertEqual(dialog["messages"][-1]["actor"], "chatgpt")
        events = api.cybernova_new_events(after_seq=dialog["messages"][1]["seq"])
        self.assertEqual(len(events["messages"]), 1)

    def test_feedback_idempotent_across_retries(self):
        api = self.module
        tid = api.cybernova_create_task("Тест", "Старт")["task_id"]
        a = api.cybernova_send_feedback(tid, "Проверь", "request_123456")
        b = api.cybernova_send_feedback(tid, "Проверь", "request_123456")
        self.assertEqual(a["event_seq"], b["event_seq"])


if __name__ == "__main__":
    unittest.main()
