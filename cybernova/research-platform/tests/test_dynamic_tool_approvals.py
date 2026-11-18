"""Offline regression suite for dynamic MCP discovery and explicit approvals."""
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import Agent, BackendError
from console.tool_policy import (
    ToolPolicyError, discovered_tools, model_tools, validate_dynamic_arguments,
    safe_preview, schema_digest, action_description,
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
        self.assertIn("Requires user approval", model_tools([NEW])[0]["function"]["description"])

    def test_invalid_names_and_duplicates_ignored(self):
        found = discovered_tools([NEW, NEW, {"name": "x;rm -rf", "inputSchema": {}}])
        self.assertEqual(len(found), 1)

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

    def test_new_tool_proposal_no_execution(self):
        mcp = FakeMCP()
        qwen = FakeQwen([tool_call(), {"role": "assistant", "content": "Нужен допуск"}])
        result = Agent(qwen, lambda: mcp).run([], "Проверь DNS")
        self.assertEqual(mcp.calls, [])
        self.assertEqual(result["tool_calls"], 0)
        self.assertEqual(result["events"][0]["type"], "approval_required")
        self.assertEqual(result["events"][0]["execution"], "not_started")
        self.assertEqual(result["approval_requests"][0]["tool"], "dns_research")

    def test_approved_tool_calls_exact_args_once(self):
        mcp = FakeMCP()
        qwen = FakeQwen([tool_call(), {"role": "assistant", "content": "Нужен допуск"},
                         {"role": "assistant", "content": "По результату: тест"}])
        agent = Agent(qwen, lambda: mcp)
        response = agent.run([], "Исследуй DNS")
        proposal = response["approval_requests"][0]
        result = agent.execute_approved(proposal, [
            {"role": "user", "content": "Исследуй DNS"},
            {"role": "assistant", "content": response["answer"]},
        ])
        self.assertEqual(mcp.calls, [("dns_research", {"domain": "example.test"})])
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(result["selected_by"], "user_approved")
        self.assertIn("тест", result["answer"])
        self.assertFalse(qwen.inputs[-1]["tools"])

    def test_expired_approval_never_executes(self):
        mcp = FakeMCP()
        qwen = FakeQwen([])
        approval = {"tool": "dns_research", "args": {"domain": "example.test"},
                    "schema_hash": schema_digest(NEW), "created_at": time.time()-900}
        with self.assertRaises(BackendError):
            Agent(qwen, lambda: mcp).execute_approved(approval, [])
        self.assertEqual(mcp.calls, [])

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


if __name__=="__main__":
    unittest.main()
