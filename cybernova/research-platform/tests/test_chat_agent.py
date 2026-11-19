"""No-network tests for the provider-neutral Cybernova model↔MCP loop."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import (
    Agent, _arguments, _allowed_http, _safe_args, _tool_schema,
    BackendError, MCPClient, OllamaClient, BASE_SYSTEM,
)

TOOLS = [
    {"name": "gateway_status", "description": "Status", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "http_get", "description": "Limited GET", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "ip_network_summary", "description": "CIDR", "inputSchema": {"type": "object", "properties": {"cidr": {"type": "string"}}, "required": ["cidr"]}},
    {"name": "arbitrary_shell", "description": "Requires human approval", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
]
def calls(*items):
    return {"role": "assistant", "content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}} for name, args in items
    ]}
class FakeMCP:
    def __init__(self):
        self.calls=[]
    def initialize(self):
        return TOOLS
    def call(self, name, args):
        self.calls.append((name,args))
        if name=="gateway_status":
            return {"ok":True,"authorized_hosts":["simnet.ua"]},False
        if name=="http_get":
            return {"ok":True,"http_status":200,"url":args["url"],"server_header":"nginx"},False
        if name=="ip_network_summary":
            return {"ok":True,"network":"192.0.2.0/24"},False
        return {"ok":False,"error":"unknown"},True

class FakeOllama:
    model="cybernova-test"
    def __init__(self, messages):self.messages=list(messages);self.prompts=[]
    def chat(self,messages,tools=None,**kwargs):
        self.prompts.append((messages,tools,kwargs))
        if not self.messages:raise AssertionError("Unexpected LLM call")
        return self.messages.pop(0)

class AgentTests(unittest.TestCase):
    def test_shared_profile_is_provider_neutral_and_contains_project_background(self):
        self.assertIn("единственной активной моделью", BASE_SYSTEM)
        self.assertIn("локальная Qwen Heretic", BASE_SYSTEM)
        self.assertIn("облачный DeepSeek", BASE_SYSTEM)
        self.assertIn("разработчик самой Cybernova", BASE_SYSTEM)
        self.assertIn("Chromium/Playwright", BASE_SYSTEM)
        self.assertIn("ИССЛЕДОВАТЕЛЬСКАЯ МИССИЯ CYBERNOVA", BASE_SYSTEM)
        self.assertIn("РАЗБОР НЕЧЁТКОГО ЗАПРОСА", BASE_SYSTEM)
        self.assertNotIn("Рекомендация Qwen", BASE_SYSTEM)

    def test_reasoning_content_is_kept_in_agent_tool_loop(self):
        mcp=FakeMCP()
        first=calls(("ip_network_summary",{"cidr":"192.0.2.7/24"}))
        first["reasoning_content"]="Select subnet summary tool."
        lm=FakeOllama([first,{"role":"assistant","content":"Сеть 192.0.2.0/24."}])
        Agent(lm,lambda:mcp).run([],"Проверь подсеть",force_tools=False)
        assistant_turn=next(x for x in lm.prompts[1][0] if x.get("tool_calls"))
        self.assertEqual(assistant_turn["reasoning_content"],"Select subnet summary tool.")

    def test_all_registered_tools_visible_to_active_model(self):
        names = [t["function"]["name"] for t in _tool_schema(TOOLS, False)]
        self.assertEqual(names, ["gateway_status", "http_get", "ip_network_summary",
                                 "arbitrary_shell"])
        self.assertIn("Requires user approval",
                      _tool_schema(TOOLS)[-1]["function"]["description"])

    def test_one_native_tool_call_then_reasoned_answer(self):
        mcp=FakeMCP();lm=FakeOllama([calls(("ip_network_summary",{"cidr":"192.0.2.7/24"})),
                                   {"role":"assistant","content":"Сеть 192.0.2.0/24."}])
        out=Agent(lm,lambda:mcp).run([],"Проверь подсеть")
        self.assertEqual(out["tool_calls"],1)
        self.assertEqual(out["selected_by"],"native")
        self.assertEqual(mcp.calls,[("ip_network_summary",{"cidr":"192.0.2.7/24"})])
        self.assertIn("192.0.2.0/24",out["answer"])

    def test_new_tool_is_proposed_not_executed(self):
        mcp=FakeMCP();lm=FakeOllama([calls(("arbitrary_shell",{"command":"id"})),
                                   {"role":"assistant","content":"Нужно разрешение"}])
        out=Agent(lm,lambda:mcp).run([],"Вызови shell")
        self.assertEqual(mcp.calls,[])
        self.assertEqual(out["tool_calls"],0)
        self.assertEqual(out["events"][0]["type"],"approval_required")
        self.assertEqual(out["events"][0]["result"]["status"],"approval_required")
        self.assertEqual(out["approval_requests"][0]["args"],{"command":"id"})
        self.assertIn("нужны отдельные разрешения",out["answer"])

    def test_external_get_rejected_even_when_checkbox_enabled(self):
        mcp=FakeMCP();lm=FakeOllama([calls(("http_get",{"url":"https://example.org/"})),
                                   {"role":"assistant","content":"Цель запрещена"}])
        out=Agent(lm,lambda:mcp).run([],"Проверь example.org",public_get=True)
        self.assertTrue(out["events"][0]["is_error"])
        self.assertEqual(mcp.calls,[("gateway_status",{})])

    def test_get_rejected_when_checkbox_off(self):
        mcp=FakeMCP();lm=FakeOllama([calls(("http_get",{"url":"https://simnet.ua/"})),
                                   {"role":"assistant","content":"Не разрешено"}])
        out=Agent(lm,lambda:mcp).run([],"GET",public_get=False)
        self.assertEqual(mcp.calls,[])
        self.assertTrue(out["events"][0]["is_error"])

    def test_get_allowed_only_for_preapproved_host(self):
        mcp=FakeMCP();lm=FakeOllama([calls(("http_get",{"url":"https://simnet.ua/"})),
                                   {"role":"assistant","content":"HTTP 200"}])
        out=Agent(lm,lambda:mcp).run([],"GET",public_get=True)
        self.assertEqual(out["tool_calls"],1)
        self.assertEqual(mcp.calls[-1][0],"http_get")
        self.assertEqual(out["answer"],"HTTP 200")

    def test_get_budget_only_three_calls(self):
        mcp=FakeMCP();lm=FakeOllama([
            calls(*[("http_get",{"url":"https://simnet.ua/"}) for _ in range(4)]),
            {"role":"assistant","content":"Done"},
        ])
        out=Agent(lm,lambda:mcp).run([],"Four GET",public_get=True)
        self.assertEqual(len([x for x in mcp.calls if x[0]=="http_get"]),3)
        self.assertIn("public_http_budget_exhausted",str(out["events"]))

    def test_json_fallback_is_model_selected_and_validated(self):
        mcp=FakeMCP()
        lm=FakeOllama([
            {"role":"assistant","content":"No native calls"},
            {"role":"assistant","content":'{"calls":[{"name":"ip_network_summary","arguments":{"cidr":"192.0.2.7/24"}}]}'},
            {"role":"assistant","content":"CIDR confirmed"},
        ])
        out=Agent(lm,lambda:mcp).run([],"Check CIDR",force_tools=True)
        self.assertEqual(out["selected_by"],"model_json_fallback")
        self.assertEqual(out["tool_calls"],1)
        self.assertEqual(out["answer"],"CIDR confirmed")

    def test_invalid_json_fallback_does_not_execute(self):
        mcp=FakeMCP()
        lm=FakeOllama([
            {"role":"assistant","content":"No native calls"},
            {"role":"assistant","content":"This is not JSON"},
        ])
        out=Agent(lm,lambda:mcp).run([],"Check status",force_tools=True)
        self.assertEqual(out["tool_calls"],0)
        self.assertEqual(mcp.calls,[])
        self.assertEqual(out["answer"],"No native calls")

    def test_strict_parameters(self):
        with self.assertRaises(BackendError):
            _arguments("gateway_status",{"shell":"/bin/bash"})
        with self.assertRaises(BackendError):
            _arguments("ip_network_summary",{"cidr":12})
        with self.assertRaises(BackendError):
            _arguments("arbitrary_shell",{})

    def test_http_url_boundary(self):
        allowed={"simnet.ua"}
        self.assertTrue(_allowed_http("https://simnet.ua/robots.txt",allowed))
        for url in ("https://sub.simnet.ua/","https://simnet.ua.evil.test/",
                    "https://simnet.ua@evil.test/","http://simnet.ua/",
                    "https://simnet.ua:8443/","https://simnet.ua/#frag",
                    "https://127.0.0.1/"):
            self.assertFalse(_allowed_http(url,allowed))

    def test_safe_args_removes_query_string(self):
        x=_safe_args("http_get",{"url":"https://simnet.ua/hello?token=secret"})
        self.assertNotIn("secret",str(x))
        self.assertEqual(x["url"],"https://simnet.ua/hello")

    def test_backend_not_used_when_no_tools(self):
        class NoMCP:
            def __call__(self):raise BackendError("missing")
        lm=FakeOllama([{"role":"assistant","content":"MCP unavailable, answer limited"}])
        out=Agent(lm,NoMCP()).run([],"Что доступно?")
        self.assertIn("MCP unavailable",out["answer"])
        self.assertEqual(out["events"][0]["type"],"mcp_error")

    def test_automatic_tools_are_default_and_optional(self):
        mcp = FakeMCP()
        lm = FakeOllama([
            {"role": "assistant", "content": "Объясню без инструментов."},
            {"role": "assistant", "content": '{"calls":[]}'},
        ])
        out = Agent(lm, lambda:mcp).run([], "Просто объясни термин")
        self.assertEqual(out["tool_calls"], 0)
        self.assertEqual(out["selected_by"], "none")
        self.assertEqual(mcp.calls, [])
        self.assertEqual(len(lm.prompts), 2)
        self.assertIn("http_get", [t["function"]["name"] for t in lm.prompts[0][1]])
        self.assertEqual(out["answer"], "Объясню без инструментов.")

    def test_always_offers_http_but_denies_out_of_scope(self):
        mcp = FakeMCP()
        lm = FakeOllama([
            calls(("http_get", {"url": "https://evil.example.net/"})),
            {"role": "assistant", "content": "Запрос не выполнен"},
        ])
        out = Agent(lm, lambda:mcp).run([], "Проверь evil.example.net")
        self.assertEqual(out["events"][0]["type"], "scope_change_required")
        self.assertEqual(out["events"][0]["result"]["reason"],
                         "http_target_outside_gateway_scope")
        self.assertNotIn("http_get", [name for name, _ in mcp.calls])

    def test_empty_and_long_user_prompt_rejected(self):
        with self.assertRaises(ValueError):Agent(FakeOllama([]),lambda:FakeMCP()).run([]," ")
        with self.assertRaises(ValueError):Agent(FakeOllama([]),lambda:FakeMCP()).run([],"a"*10001)


if __name__=="__main__":
    unittest.main()
