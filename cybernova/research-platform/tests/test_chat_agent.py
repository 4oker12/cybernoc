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
from console.model_providers import OpenAICompatibleClient

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

class FakeLocalToolRuntime:
    def __init__(self, *, image=False):
        self.calls = []
        self.image = image
        schema = {
            "type": "object", "properties": {}, "required": [],
            "additionalProperties": False,
        }
        self.tools = [{
            "type": "function", "name": "computer_system_overview",
            "description": "Inspect local Windows system.",
            "parameters": schema,
        }]
        self.tool_map = {item["name"]: item for item in self.tools}

    def mcp_tools(self, groups=None):
        return [{
            "name": item["name"], "description": item["description"],
            "inputSchema": item["parameters"],
        } for item in self.tools
            if not groups or "computer" in groups]

    def call(self, name, args, *, authorized_targets=None, user_messages=None,
             enabled_groups=None):
        self.calls.append((name, args, set(authorized_targets or ()), user_messages, set(enabled_groups or ())))
        if self.image:
            return {"ok": True, "image_data_url": "data:image/png;base64,AAAA"}, False
        return {"ok": True, "os": "Windows", "cpu_count": 8}, False


class AgentTests(unittest.TestCase):
    def test_shared_profile_is_provider_neutral_and_contains_project_background(self):
        self.assertIn("ChatGPT в основном проектном чате пользователя", BASE_SYSTEM)
        self.assertIn("локальный исполнитель Cybernova", BASE_SYSTEM)
        self.assertIn("Qwen3-Coder Heretic 30B", BASE_SYSTEM)
        self.assertIn("DeepSeek API", BASE_SYSTEM)
        self.assertIn("разработчиком самой", BASE_SYSTEM)
        self.assertIn("Chromium/Playwright", BASE_SYSTEM)
        self.assertIn("Первоначальный исполнитель проекта", BASE_SYSTEM)
        self.assertIn("передаёшь отчёт координатору", BASE_SYSTEM)
        self.assertIn("ИССЛЕДОВАТЕЛЬСКАЯ МИССИЯ CYBERNOVA", BASE_SYSTEM)
        self.assertIn("РАЗБОР НЕЧЁТКОГО ЗАПРОСА", BASE_SYSTEM)
        self.assertIn("ОБЩИЙ ИНСТРУМЕНТАЛЬНЫЙ СТАНДАРТ", BASE_SYSTEM)
        self.assertIn("computer_package_install", BASE_SYSTEM)
        self.assertIn("computer_archive_extract", BASE_SYSTEM)
        self.assertIn("browser_follow_link", BASE_SYSTEM)
        self.assertIn("google_search", BASE_SYSTEM)
        self.assertNotIn("Рекомендация Qwen", BASE_SYSTEM)

    def test_user_and_mode_profiles_are_added_as_system_context(self):
        mcp=FakeMCP()
        lm=FakeOllama([{"role":"assistant","content":"Готово."}])
        Agent(lm,lambda:mcp).run(
            [],"Привет",force_tools=False,
            user_context="ОБЩИЙ ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ",
            profile_instructions="ИНСТРУКЦИИ РЕЖИМА",
        )
        system_text="\n".join(
            item["content"] for item in lm.prompts[0][0]
            if item.get("role")=="system"
        )
        self.assertIn("ОБЩИЙ ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ",system_text)
        self.assertIn("ИНСТРУКЦИИ РЕЖИМА",system_text)

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

    def test_deepseek_agent_receives_the_same_local_computer_tool_catalog(self):
        mcp = FakeMCP()
        local = FakeLocalToolRuntime()
        lm = FakeOllama([
            calls(("computer_system_overview", {})),
            {"role": "assistant", "content": "Windows: 8 logical CPUs."},
        ])
        out = Agent(lm, lambda: mcp, local_tool_runtime=local).run(
            [], "Проверь локальный компьютер и example.com", force_tools=False,
            scope={"hosts": ["scope.example"]},
        )
        self.assertEqual(out["tool_calls"], 1)
        self.assertEqual(local.calls[0][0], "computer_system_overview")
        self.assertEqual(local.calls[0][4], set())
        self.assertIn("example.com", local.calls[0][2])
        self.assertIn("scope.example", local.calls[0][2])
        self.assertEqual(
            local.calls[0][3],
            [{"role": "user", "content": "Проверь локальный компьютер и example.com"}],
        )
        self.assertEqual(mcp.calls, [])
        advertised = [tool["function"]["name"] for tool in lm.prompts[0][1]]
        self.assertIn("computer_system_overview", advertised)

    def test_selected_tool_bundle_limits_advertised_tools_and_runtime(self):
        local = FakeLocalToolRuntime()
        lm = FakeOllama([
            calls(("computer_system_overview", {})),
            {"role": "assistant", "content": "Windows доступна."},
        ])
        out = Agent(lm, lambda: FakeMCP(), local_tool_runtime=local).run(
            [], "Проверь компьютер", force_tools=False, tool_groups=["computer"],
        )
        advertised = [tool["function"]["name"] for tool in lm.prompts[0][1]]
        self.assertEqual(advertised, ["computer_system_overview"])
        self.assertEqual(out["tool_calls"], 1)
        self.assertEqual(local.calls[0][0], "computer_system_overview")
        self.assertEqual(local.calls[0][4], {"computer"})

    def test_tools_disabled_skips_mcp_and_local_tool_catalog(self):
        factory_calls = []
        local = FakeLocalToolRuntime()
        lm = FakeOllama([{"role": "assistant", "content": "Обычный текстовый ответ."}])

        def factory():
            factory_calls.append(True)
            return FakeMCP()

        out = Agent(lm, factory, local_tool_runtime=local).run(
            [], "Ответь без инструментов.", tools_enabled=False,
        )

        self.assertEqual(factory_calls, [])
        self.assertEqual(lm.prompts[0][1], [])
        self.assertEqual(out["tool_calls"], 0)
        system_text = "\n".join(
            item["content"] for item in lm.prompts[0][0]
            if item.get("role") == "system"
        )
        self.assertNotIn("ОБЩИЙ ИНСТРУМЕНТАЛЬНЫЙ СТАНДАРТ", system_text)
        self.assertNotIn("computer_system_overview", system_text)

    def test_ollama_client_captures_provider_token_counters(self):
        client = OllamaClient(transport=lambda *_: {
            "message": {"role": "assistant", "content": "ok"},
            "prompt_eval_count": 41, "eval_count": 9,
        })
        result = client.chat([{"role": "user", "content": "test"}])
        self.assertEqual(result["_usage"]["input_tokens"], 41)
        self.assertEqual(result["_usage"]["output_tokens"], 9)
        self.assertEqual(result["_usage"]["total_tokens"], 50)
        self.assertEqual(result["_usage"]["provider"], "Ollama")

    def test_openai_compatible_client_captures_usage_fields(self):
        client = OpenAICompatibleClient(
            base_url="http://127.0.0.1:12345/v1/chat/completions",
            model="test-model", api_key="",
            transport=lambda *_: {
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 77, "completion_tokens": 13, "total_tokens": 90},
            },
        )
        result = client.chat([{"role": "user", "content": "test"}])
        self.assertEqual(result["_usage"]["input_tokens"], 77)
        self.assertEqual(result["_usage"]["output_tokens"], 13)
        self.assertEqual(result["_usage"]["total_tokens"], 90)
        self.assertEqual(result["_usage"]["provider"], "OpenAI-compatible")

    def test_agent_reports_actual_token_usage_across_model_rounds(self):
        first = calls(("ip_network_summary", {"cidr": "192.0.2.7/24"}))
        first["_usage"] = {"input_tokens": 120, "output_tokens": 15}
        final = {"role": "assistant", "content": "Сеть 192.0.2.0/24.",
                 "_usage": {"input_tokens": 180, "output_tokens": 25}}
        out = Agent(FakeOllama([first, final]), lambda: FakeMCP()).run(
            [], "Проверь подсеть", force_tools=False,
        )
        self.assertEqual(out["usage"]["input_tokens"], 300)
        self.assertEqual(out["usage"]["output_tokens"], 40)
        self.assertEqual(out["usage"]["total_tokens"], 340)
        self.assertEqual(out["usage"]["requests"], 2)
        self.assertTrue(out["usage"]["complete"])

    def test_shared_local_tools_remain_available_when_remote_mcp_is_down(self):
        local = FakeLocalToolRuntime()
        lm = FakeOllama([
            calls(("computer_system_overview", {})),
            {"role": "assistant", "content": "Windows доступна."},
        ])
        def broken_mcp():
            raise BackendError("mcp_offline")
        out = Agent(lm, broken_mcp, local_tool_runtime=local).run(
            [], "Проверь компьютер", force_tools=False,
        )
        self.assertEqual(out["tool_calls"], 1)
        self.assertEqual(local.calls[0][0], "computer_system_overview")
        self.assertIn("mcp_error", [event["type"] for event in out["events"]])

    def test_text_only_deepseek_adapter_does_not_receive_base64_screenshots(self):
        local = FakeLocalToolRuntime(image=True)
        agent = Agent(FakeOllama([]), lambda: FakeMCP(), local_tool_runtime=local)
        result, failed = agent._call_registered_tool(
            "computer_system_overview", {}, mcp=None,
        )
        self.assertFalse(failed)
        self.assertNotIn("image_data_url", result)
        self.assertFalse(result["visual_input"]["forwarded_to_model"])

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

    def test_security_case_triggers_privacy_filtered_google_search(self):
        class ResearchMCP(FakeMCP):
            def initialize(self):
                return TOOLS + [{
                    "name": "google_search", "description": "Public Google search",
                    "inputSchema": {"type": "object", "properties": {
                        "query": {"type": "string"}}, "required": ["query"],
                        "additionalProperties": False},
                }]
            def call(self, name, args):
                self.calls.append((name, args))
                if name == "google_search":
                    return {"ok": True, "result_count": 1,
                            "results": [{"title": "Official CVE advisory"}]}, False
                return super().call(name, args)
        mcp=ResearchMCP()
        lm=FakeOllama([
            {"role":"assistant","content":"No native calls"},
            {"role":"assistant","content":'{"calls":[]}'},
            {"role":"assistant","content":"Нашёл официальный advisory."},
        ])
        out=Agent(lm,lambda:mcp).run(
            [],"Найди реальные кейсы CVE-2026-12345 для internal.example "
               "и 10.0.0.4; уязвимость в Apache.",
            scope={"hosts":["internal.example"]},
        )
        self.assertEqual(out["selected_by"],"google_research_fallback")
        self.assertEqual(out["tool_calls"],1)
        self.assertEqual(mcp.calls[0][0],"google_search")
        query=mcp.calls[0][1]["query"]
        self.assertIn("CVE-2026-12345",query)
        self.assertNotIn("internal.example",query)
        self.assertNotIn("10.0.0.4",query)
        self.assertEqual(out["answer"],"Нашёл официальный advisory.")

    def test_google_research_is_added_even_when_model_selects_another_tool(self):
        class ResearchMCP(FakeMCP):
            def initialize(self):
                return TOOLS + [{
                    "name": "google_search", "description": "Public Google search",
                    "inputSchema": {"type": "object", "properties": {
                        "query": {"type": "string"}}, "required": ["query"],
                        "additionalProperties": False},
                }]
            def call(self, name, args):
                if name == "google_search":
                    self.calls.append((name, args))
                    return {"ok": True, "result_count": 1, "results": []}, False
                return super().call(name, args)
        mcp=ResearchMCP()
        lm=FakeOllama([
            calls(("ip_network_summary",{"cidr":"192.168.1.0/24"})),
            {"role":"assistant","content":"Параллельно проверил публичные advisories."},
        ])
        out=Agent(lm,lambda:mcp).run(
            [],"Оцени потенциальную уязвимость CVE-2026-12345 и найди реальные кейсы.",
            scope={"hosts":["internal.example"]},
        )
        self.assertEqual([name for name,_ in mcp.calls],
                         ["ip_network_summary","google_search"])
        self.assertEqual(out["tool_calls"],2)
        self.assertIn("CVE-2026-12345",mcp.calls[-1][1]["query"])

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
