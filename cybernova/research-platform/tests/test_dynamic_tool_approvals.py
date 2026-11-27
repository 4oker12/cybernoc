"""Offline regression suite for dynamic MCP discovery and explicit approvals."""
import sys
import time
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import Agent, BackendError, APPROVAL_TTL_SECONDS, _diagnostic_tool_args
from console.gpt_tool_runtime import route_model_tool_rows
from console.tool_policy import (
    MAX_ADVERTISED, MAX_DISCOVERED, ToolPolicyError, discovered_tools, model_tools, validate_dynamic_arguments,
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

    def test_large_catalog_routes_exact_tool_without_exceeding_provider_budget(self):
        rows = [
            {"name": f"dynamic_tool_{i:03d}", "description": "Fixture",
             "inputSchema": {"type": "object", "properties": {}}}
            for i in range(159)
        ] + [NEW]
        self.assertEqual(len(discovered_tools(rows, limit=MAX_DISCOVERED)), 160)
        mcp = FakeMCP(rows)
        model = FakeQwen([tool_call(), {"content": "DNS проверен"}])
        with patch("console.agent.diagnostic_event") as log:
            result = Agent(model, lambda: mcp).run([], "Вызови dns_research для example.test")
        offered = model.inputs[0]["tools"]
        self.assertLessEqual(len(offered), MAX_ADVERTISED)
        self.assertIn("dns_research", [item["function"]["name"] for item in offered])
        self.assertEqual(mcp.calls, [("dns_research", {"domain": "example.test"})])
        self.assertEqual(result["tool_calls"], 1)
        ready = [call.kwargs for call in log.call_args_list if call.args == ("tool_catalog_ready",)]
        self.assertEqual(ready[0]["discovered_count"], 160)
        self.assertEqual(ready[0]["omitted_count"], 160 - len(offered))

    def test_weather_task_does_not_advertise_terminal_or_computer_tools(self):
        rows = [
            {"name": "google_search", "description": "Search", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "research_source_open", "description": "Open source", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "browser_navigate", "description": "Navigate", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "browser_read_page", "description": "Read page", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "terminal_run", "description": "Run command", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "terminal_status", "description": "Terminal status", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "computer_status", "description": "Computer status", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "github_list_repositories", "description": "GitHub", "inputSchema": {"type": "object", "properties": {}}},
        ]
        selected = route_model_tool_rows(rows, "Какая погода сегодня в Киеве?", limit=MAX_ADVERTISED)
        names = {row["name"] for row in selected}
        self.assertTrue({"google_search", "research_source_open"} <= names)
        self.assertFalse({"terminal_run", "terminal_status", "computer_status",
                          "github_list_repositories"} & names)

    def test_explicit_terminal_task_advertises_terminal_but_not_browser(self):
        rows = [
            {"name": "terminal_run", "description": "Run command", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "terminal_status", "description": "Terminal status", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "browser_navigate", "description": "Navigate", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "google_search", "description": "Search", "inputSchema": {"type": "object", "properties": {}}},
        ]
        selected = route_model_tool_rows(rows, "Выполни команду PowerShell Get-Location", limit=MAX_ADVERTISED)
        names = {row["name"] for row in selected}
        self.assertTrue({"terminal_run", "terminal_status"} <= names)
        self.assertFalse({"browser_navigate", "google_search"} & names)

    def test_explicit_group_selection_is_preserved(self):
        rows = [
            {"name": "terminal_run", "description": "Run command", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "browser_navigate", "description": "Navigate", "inputSchema": {"type": "object", "properties": {}}},
        ]
        selected = route_model_tool_rows(rows, "Какая погода сегодня?", limit=MAX_ADVERTISED,
                                         selected_groups=["terminal"])
        self.assertEqual([row["name"] for row in selected], ["terminal_run"])

    def test_browser_read_routes_only_read_capabilities_and_honors_denial(self):
        names = ["browser_navigate", "browser_snapshot", "browser_read_page", "browser_find_text",
                 "browser_submit", "browser_login", "terminal_run", "terminal_status",
                 "computer_system_overview", "github_repo_info"]
        rows = [{"name": name} for name in names]
        task = "Открой https://example.com и проверь H1. Не используй терминал."
        offered = [row["name"] for row in route_model_tool_rows(rows, task, limit=128)]
        self.assertEqual(offered, names[:4])
        self.assertEqual(offered, [row["name"] for row in route_model_tool_rows(
            list(reversed(rows)), task, limit=128)])

    def test_manual_group_does_not_widen_exact_named_tool(self):
        rows = [{"name": "terminal_run"}, {"name": "browser_read_page"}]
        offered = route_model_tool_rows(rows, "Вызови terminal_run", limit=128,
                                         selected_groups=["browser"])
        self.assertEqual([row["name"] for row in offered], ["browser_read_page"])

    def test_cumulative_token_ceiling_disabled_by_default(self):
        mcp = FakeMCP()
        first = tool_call()
        first["_usage"] = {"input_tokens": 600000, "output_tokens": 20}
        model = FakeQwen([first, {"content": "Фактический итог"}])
        with patch.dict("os.environ", {"CYBERNOVA_AGENT_INPUT_TOKEN_BUDGET": "0"}):
            result = Agent(model, lambda: mcp).run([], "Вызови dns_research для example.test")
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(result["usage"]["input_tokens"], 600000)
        self.assertNotIn("stop_reason", result)
        self.assertEqual(result["answer"], "Фактический итог")

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


    def test_diagnostic_argument_previews_redact_free_text_and_commands(self):
        browser_args = _diagnostic_tool_args(
            "browser_fill", {"field_label": "Password", "value": "private-secret"}
        )
        self.assertNotIn("private-secret", str(browser_args))
        self.assertEqual(browser_args["value"], {"type": "str", "chars": 14})

        command = "Write-Output private-secret"
        terminal_args = _diagnostic_tool_args(
            "terminal_run",
            {
                "command": command, "shell": "powershell",
                "cwd": r"C:\Users\PrivateUser", "timeout_seconds": 30,
                "max_output_chars": 1000,
            },
        )
        self.assertNotIn("private-secret", str(terminal_args))
        self.assertNotIn("PrivateUser", str(terminal_args))
        self.assertEqual(terminal_args["command_chars"], len(command))
        self.assertEqual(terminal_args["shell"], "powershell")

        url_args = _diagnostic_tool_args(
            "browser_navigate", {"url": "https://example.org/path?token=secret"}
        )
        self.assertEqual(url_args["url"], "https://example.org/path")
        self.assertNotIn("secret", str(url_args))


if __name__=="__main__":
    unittest.main()
