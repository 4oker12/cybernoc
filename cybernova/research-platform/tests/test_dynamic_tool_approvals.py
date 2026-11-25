"""Offline regression suite for dynamic MCP discovery and explicit approvals."""
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import Agent, BackendError, APPROVAL_TTL_SECONDS
from console.tool_policy import (
    MAX_ADVERTISED, ToolPolicyError, discovered_tools, model_tools, validate_dynamic_arguments,
    safe_preview, schema_digest, action_description, task_explicitly_prohibits_action,
)

NEW = {
    "name": "dns_research",
    "description": "An example read-only DNS tool; unreviewed by controller",
    "inputSchema": {
        "type": "object",
        "properties": {"domain": {"type": "string"}},
        "required": ["domain"],
        "additionalProperties": False,
    },
}
CHANGED = {**NEW, "inputSchema": {
    "type": "object",
    "properties": {"domain": {"type": "string"}, "mode": {"type": "string"}},
    "required": ["domain"],
}}


HIGH_IMPACT = {
    "name": "owner_shell_execute",
    "description": "Execute a shell command on the owner-controlled host.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "command": {"type": "string"},
            "api_token": {"type": "string"},
        },
        "required": ["command"],
        "additionalProperties": False,
    },
}


class FakeMCP:
    def __init__(self, tools=None):
        self.tools = tools or [NEW]
        self.calls = []

    def initialize(self):
        return self.tools

    def call(self, name, args):
        self.calls.append((name, args))
        return {"ok": True, "domain": args.get("domain"), "source": "fake_mcp"}, False


class FakeQwen:
    model = "test-Qwen"
    def __init__(self, responses):
        self.responses = list(responses)
        self.inputs = []

    def chat(self, messages, tools=None, **kwargs):
        self.inputs.append({"messages": messages, "tools": tools})
        if not self.responses:
            raise AssertionError("Unexpected model response")
        return self.responses.pop(0)


def tool_call(name="dns_research", args=None):
    return {"role": "assistant", "content": "",
            "tool_calls": [{"function": {
                "name": name,
                "arguments": args if args is not None else {"domain": "example.test"},
            }}]}


class DynamicToolPolicyTests(unittest.TestCase):
    def test_model_sees_new_tools_without_name_allowlist(self):
        self.assertEqual(model_tools([NEW])[0]["function"]["name"], "dns_research")
        self.assertIn("Autonomous when relevant", model_tools([NEW])[0]["function"]["description"])

    def test_invalid_names_and_duplicates_ignored(self):
        found = discovered_tools([NEW, NEW, {"name": "x;rm -rf", "inputSchema": {}}])
        self.assertEqual(len(found), 1)

    def test_catalog_overflow_is_explicit_not_silently_truncated(self):
        rows = [{
            "name": f"dynamic_tool_{index:03d}",
            "description": "Read-only test tool",
            "inputSchema": {
                "type": "object", "properties": {}, "required": [],
                "additionalProperties": False,
            },
        } for index in range(MAX_ADVERTISED + 1)]
        with self.assertRaisesRegex(ToolPolicyError, "tool_catalog_limit_exceeded"):
            discovered_tools(rows)

    def test_dynamic_args_enforce_required_and_type(self):
        schema = NEW["inputSchema"]
        self.assertEqual(validate_dynamic_arguments({"domain": "example.test"}, schema),
                         {"domain": "example.test"})
        for invalid in ({}, {"domain": 19}, {"domain": "x", "shell": "id"}):
            with self.assertRaises(ToolPolicyError):
                validate_dynamic_arguments(invalid, schema)

    def test_rejects_nested_and_oversized_arguments(self):
        schema = {"type": "object", "properties": {"value": {"type": "object"}}}
        deep = {"value": {"x": {"y": {"z": {"q": {"w": {"r": {"t": {"u": 1}}}}}}}}}
        with self.assertRaises(ToolPolicyError):
            validate_dynamic_arguments(deep, schema)
        with self.assertRaises(ToolPolicyError):
            validate_dynamic_arguments({"value": {"data": "x" * 5000}}, schema)

    def test_secret_values_redacted_from_approval_card(self):
        args = {"domain": "example.test", "api_token": "NOT-TO-BE-SHOWN",
                "endpoint": "https://example.test/api?token=secret"}
        output = safe_preview(args)
        self.assertEqual(output["api_token"], "[REDACTED SECRET]")
        self.assertEqual(output["endpoint"], "https://example.test/api")
        self.assertNotIn("secret", str(output))

    def test_schema_fingerprint_changes_with_definition(self):
        self.assertNotEqual(schema_digest(NEW), schema_digest(CHANGED))

    def test_new_read_only_tool_runs_without_per_call_approval(self):
        mcp = FakeMCP()
        qwen = FakeQwen([tool_call(), {"role": "assistant", "content": "DNS проверен"}])
        result = Agent(qwen, lambda: mcp).run([], "Проверь DNS")
        self.assertEqual(mcp.calls, [("dns_research", {"domain": "example.test"})])
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(result["events"][0]["type"], "tool_result")
        self.assertEqual(result["approval_requests"], [])

    def test_unrequested_high_impact_tool_creates_visible_one_shot_approval(self):
        mcp = FakeMCP([HIGH_IMPACT])
        qwen = FakeQwen([
            tool_call("owner_shell_execute", {
                "command": "Get-Process", "api_token": "NOT-TO-BE-SHOWN",
            }),
            {"role": "assistant", "content": "Действие ожидает разрешения."},
            {"role": "assistant", "content": "Команда не выполнялась; ожидается решение пользователя."},
            {"role": "assistant", "content": "Одобренная команда выполнена."},
        ])
        worker = Agent(qwen, lambda: mcp)
        result = worker.run(
            [], "Проверь состояние проекта", force_tools=False,
        )
        self.assertEqual(mcp.calls, [])
        self.assertEqual(result["tool_calls"], 0)
        self.assertEqual(len(result["approval_requests"]), 1)
        request = result["approval_requests"][0]
        self.assertEqual(request["tool"], "owner_shell_execute")
        self.assertEqual(request["args"]["api_token"], "NOT-TO-BE-SHOWN")
        self.assertGreaterEqual(len(request["request_id"]), 16)
        self.assertEqual(result["events"][0]["type"], "approval_required")
        self.assertEqual(result["events"][0]["request_id"], request["request_id"])
        self.assertEqual(result["events"][0]["arguments"]["api_token"], "[REDACTED SECRET]")
        self.assertNotIn("NOT-TO-BE-SHOWN", str(result["events"]))
        self.assertEqual(result["events"][0]["result"]["execution"], "not_started")

        approved = worker.execute_approved(request, [])
        self.assertEqual(approved["selected_by"], "user_approved")
        self.assertEqual(mcp.calls, [("owner_shell_execute", {
            "command": "Get-Process", "api_token": "NOT-TO-BE-SHOWN",
        })])

    def test_explicitly_prohibited_high_impact_action_never_creates_approval(self):
        mcp = FakeMCP([HIGH_IMPACT])
        qwen = FakeQwen([
            tool_call("owner_shell_execute", {"command": "Remove-Item C:\\temp\\x"}),
            {"role": "assistant", "content": "Запрещённое действие не выполнено."},
            {"role": "assistant", "content": "Подтверждаю: действие не выполнялось."},
        ])
        result = Agent(qwen, lambda: mcp).run(
            [], "Не запускай команду; только проверь статус", force_tools=False,
        )
        self.assertTrue(task_explicitly_prohibits_action("Не запускай команду"))
        self.assertEqual(result["approval_requests"], [])
        self.assertEqual(result["events"][0]["type"], "task_intent_required")
        self.assertEqual(result["events"][0]["result"]["status"], "user_prohibited_action")
        self.assertEqual(mcp.calls, [])

    def test_task_tool_calls_execute_once_with_exact_schema_arguments(self):
        mcp = FakeMCP()
        qwen = FakeQwen([tool_call(), {"role": "assistant", "content": "По результату: тест"}])
        result = Agent(qwen, lambda: mcp).run([], "Исследуй DNS")
        self.assertEqual(mcp.calls, [("dns_research", {"domain": "example.test"})])
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(result["selected_by"], "native")
        self.assertIn("тест", result["answer"])
        self.assertEqual(result["approval_requests"], [])
        self.assertTrue(qwen.inputs[-2]["tools"])  # First pass has tools.
        self.assertFalse(qwen.inputs[-1]["tools"])  # Second-pass audit is read-only.

    def test_expired_approval_never_executes(self):
        mcp = FakeMCP()
        qwen = FakeQwen([])
        approval = {"tool": "dns_research", "args": {"domain": "example.test"},
                    "schema_hash": schema_digest(NEW), "created_at": time.time()-APPROVAL_TTL_SECONDS-1}
        with self.assertRaises(BackendError):
            Agent(qwen, lambda: mcp).execute_approved(approval, [])
        self.assertEqual(mcp.calls, [])

    def test_approval_remains_valid_during_human_consultation(self):
        mcp = FakeMCP()
        qwen = FakeQwen([{"role": "assistant", "content": "Инструмент выполнен."}])
        approval = {"tool": "dns_research", "args": {"domain": "example.test"},
                    "schema_hash": schema_digest(NEW),
                    "created_at": time.time() - 1800}
        result = Agent(qwen, lambda: mcp).execute_approved(approval, [])
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(mcp.calls, [("dns_research", {"domain": "example.test"})])

    def test_tool_schema_changed_after_approval_rejected(self):
        mcp = FakeMCP([CHANGED])
        qwen = FakeQwen([])
        approval = {"tool": "dns_research", "args": {"domain": "example.test"},
                    "schema_hash": schema_digest(NEW), "created_at": time.time()}
        with self.assertRaises(BackendError):
            Agent(qwen, lambda: mcp).execute_approved(approval, [])
        self.assertEqual(mcp.calls, [])

    def test_action_description_explicitly_requires_approval(self):
        desc = action_description("dns_research","unreviewed",{"domain":"example.test"})
        self.assertEqual(desc["approval"], "required")
        self.assertEqual(desc["execution"], "not_started")
        self.assertIn("Агент запрашивает", desc["purpose"])


if __name__=="__main__":
    unittest.main()
