"""No-network tests for the provider-neutral Cybernova model↔MCP loop."""
import json
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import (
    Agent, _arguments, _allowed_http, _safe_args, _tool_schema,
    BackendError, MCPClient, OllamaClient, BASE_SYSTEM,
    _extract_dsml_calls, _clean_model_answer, _compact_context,
    _restore_reasoning_history,
)
from console.model_providers import OpenAICompatibleClient, ModelConfigError, _normalize_context

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

class FakeVisionClient(FakeOllama):
    provider = "OpenAI-compatible"
    model = "deepseek-flash"


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
        self.assertIn("напрямую сообщаешь пользователю короткий статус и результат", BASE_SYSTEM)
        self.assertIn("Не формируй отдельный отчёт ChatGPT-координатору", BASE_SYSTEM)
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

    def test_previous_turn_reasoning_survives_history_rebuild(self):
        persisted = [
            {"role": "user", "content": "Предыдущий запрос"},
            {"role": "assistant", "content": "Ответ, сохранённый в журнале"},
        ]
        in_memory = [
            {"role": "user", "content": "Предыдущий запрос"},
            {
                "role": "assistant",
                "content": "Ответ, сохранённый в журнале с дополнительной частью",
                "reasoning_content": "private DeepSeek continuation state",
            },
        ]
        restored = _restore_reasoning_history(persisted, in_memory)
        self.assertEqual(
            restored[-1]["reasoning_content"],
            "private DeepSeek continuation state",
        )
        self.assertNotIn("reasoning_content", persisted[-1])

    def test_deepseek_legacy_assistant_history_is_preserved_as_archival_context(self):
        normalized = _normalize_context(
            [
                {"role": "user", "content": "Old request"},
                {"role": "assistant", "content": "Old visible answer"},
                {"role": "user", "content": "Continue"},
            ],
            require_reasoning=True,
        )
        self.assertEqual(normalized[1]["role"], "system")
        self.assertIn("Old visible answer", normalized[1]["content"])
        self.assertNotIn("reasoning_content", normalized[1])

    def test_deepseek_tool_turn_without_reasoning_is_rejected_before_http(self):
        with self.assertRaises(ModelConfigError) as raised:
            _normalize_context(
                [{
                    "role": "assistant", "content": "",
                    "tool_calls": [{"id": "call_1", "function": {
                        "name": "computer_screenshot", "arguments": "{}",
                    }}],
                }],
                require_reasoning=True,
            )
        self.assertEqual(str(raised.exception), "deepseek_reasoning_state_missing_for_tool_turn")

    def test_deepseek_thinking_payload_uses_current_protocol(self):
        captured = {}
        def transport(payload):
            captured.update(payload)
            return {"choices": [{"message": {
                "role": "assistant", "content": "ok",
                "reasoning_content": "private reasoning",
            }}]}
        client = OpenAICompatibleClient(
            base_url="https://api.deepseek.com", model="deepseek-flash",
            api_key="sk-test", transport=transport,
        )
        client.chat(
            [{"role": "user", "content": "test"}],
            tools=[{"type": "function", "function": {
                "name": "test_tool", "parameters": {"type": "object"},
            }}],
        )
        self.assertEqual(captured["thinking"], {"type": "enabled"})
        self.assertEqual(captured["reasoning_effort"], "high")
        self.assertNotIn("temperature", captured)

    def test_deepseek_model_list_uses_authenticated_models_endpoint(self):
        urls = []
        client = OpenAICompatibleClient(
            base_url="https://api.deepseek.com", model="deepseek-flash",
            api_key="sk-test",
            models_transport=lambda url: (urls.append(url) or {
                "object": "list", "data": [{"id": "deepseek-flash"}],
            }),
        )
        self.assertEqual(client.list_models(), ["deepseek-flash"])
        self.assertEqual(urls, ["https://api.deepseek.com/models"])

    def test_deepseek_flash_receives_desktop_screenshot_as_user_image(self):
        local = FakeLocalToolRuntime(image=True)
        first = calls(("computer_system_overview", {}))
        first["reasoning_content"] = "Need the screenshot to inspect the UI."
        lm = FakeVisionClient([
            first,
            {"role": "assistant", "content": "На снимке виден интерфейс приложения."},
        ])
        out = Agent(lm, lambda: FakeMCP(), local_tool_runtime=local).run(
            [], "Изучи интерфейс AdsPower", force_tools=False,
            tool_groups=["computer"],
        )
        self.assertEqual(out["tool_calls"], 1)
        user_message = next(
            item for item in lm.prompts[1][0] if item.get("role") == "user"
        )
        self.assertIsInstance(user_message["content"], list)
        image_block = next(
            item for item in user_message["content"] if item.get("type") == "image_url"
        )
        self.assertEqual(image_block["image_url"]["url"], "data:image/png;base64,AAAA")
        self.assertTrue(out["events"][0]["result"]["visual_input"]["forwarded_to_model"])
        self.assertNotIn("image_data_url", json.dumps(out["events"], ensure_ascii=False))
        self.assertNotIn("AAAA", json.dumps(out["events"], ensure_ascii=False))

    def test_image_blocks_survive_deepseek_context_normalization(self):
        image = "data:image/jpeg;base64,AAAA"
        normalized = _normalize_context([{
            "role": "user",
            "content": [
                {"type": "text", "text": "Inspect this window."},
                {"type": "image_url", "image_url": {"url": image}},
            ],
        }])
        self.assertEqual(normalized[0]["content"][0]["text"], "Inspect this window.")
        self.assertEqual(normalized[0]["content"][1]["image_url"]["url"], image)

    def test_prior_turn_reasoning_is_forwarded_to_the_next_model_request(self):
        lm = FakeOllama([
            {"role": "assistant", "content": "Новый ответ.", "reasoning_content": "new reasoning"},
            {"role": "assistant", "content": "## Повторная проверка\nПроверено."},
        ])
        prior = [{
            "role": "assistant", "content": "Предыдущий ответ.",
            "reasoning_content": "prior reasoning must be passed unchanged",
        }]
        Agent(lm, lambda: FakeMCP()).run(
            prior, "Продолжи", tools_enabled=False, force_tools=False,
        )
        prior_turn = next(
            item for item in lm.prompts[0][0]
            if item.get("role") == "assistant" and item.get("content") == "Предыдущий ответ."
        )
        self.assertEqual(
            prior_turn["reasoning_content"],
            "prior reasoning must be passed unchanged",
        )

    def test_simple_conversation_turn_skips_unneeded_second_pass(self):
        lm = FakeOllama([{
            "role": "assistant",
            "content": "Короткий ответ.",
            "reasoning_content": "first-pass reasoning",
        }])
        outcome = Agent(lm, lambda: FakeMCP()).run(
            [], "Сформируй ответ", tools_enabled=False, force_tools=False,
        )
        self.assertEqual(outcome["answer"], "Короткий ответ.")
        self.assertEqual(outcome["review"]["status"], "not_required")
        self.assertEqual(len(lm.prompts), 1)
        self.assertEqual(outcome["_history_reasoning_content"], "first-pass reasoning")

    def test_controller_developer_fallback_keeps_reasoning_content(self):
        class DeveloperMCP(FakeMCP):
            def initialize(self):
                return TOOLS + [{
                    "name": "dev_list",
                    "description": "List repository files",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"limit": {"type": "integer"}},
                    },
                }]

            def call(self, name, args):
                if name == "dev_list":
                    self.calls.append((name, args))
                    return {"ok": True, "files": ["README.md"]}, False
                return super().call(name, args)

        mcp = DeveloperMCP()
        lm = FakeOllama([
            {
                "role": "assistant",
                "content": "Начинаю проверку проекта.",
                "reasoning_content": "The controller should inspect the repository tree.",
            },
            {"role": "assistant", "content": "Структура проекта получена."},
            {"role": "assistant", "content": "Проверка результата завершена."},
        ])
        outcome = Agent(lm, lambda: mcp).run(
            [], "Изучи проект и проверь код", force_tools=False,
        )
        self.assertEqual(outcome["review"]["status"], "completed")
        self.assertEqual(outcome["answer"], "Проверка результата завершена.")
        synthetic_turn = next(
            item for item in lm.prompts[1][0]
            if item.get("role") == "assistant" and item.get("tool_calls")
        )
        self.assertEqual(
            synthetic_turn["reasoning_content"],
            "The controller should inspect the repository tree.",
        )

    def test_all_registered_tools_visible_to_active_model(self):
        names = [t["function"]["name"] for t in _tool_schema(TOOLS, False)]
        self.assertEqual(names, ["gateway_status", "http_get", "ip_network_summary",
                                 "arbitrary_shell"])
        self.assertIn("Autonomous when relevant",
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

    def test_missing_output_usage_is_not_reported_as_zero(self):
        reply = {"role": "assistant", "content": "Answer",
                 "_usage": {"input_tokens": 17, "cached_tokens": 0}}
        out = Agent(FakeOllama([reply])).run([], "Hello", tools_enabled=False)
        usage = out["usage"]
        self.assertEqual(usage["input_tokens"], 17)
        self.assertEqual(usage["cached_tokens"], 0)
        self.assertIsNone(usage["output_tokens"])
        self.assertIsNone(usage["total_tokens"])
        self.assertFalse(usage["complete"])

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

    def test_unreviewed_high_impact_tool_runs_when_current_task_requests_it(self):
        mcp=FakeMCP();lm=FakeOllama([calls(("arbitrary_shell",{"command":"id"})),
                                   {"role":"assistant","content":"Вызов инструмента выполнен; вернулась ошибка неизвестного обработчика."}])
        out=Agent(lm,lambda:mcp).run([],"Вызови shell")
        self.assertEqual(mcp.calls,[("arbitrary_shell",{"command":"id"})])
        self.assertEqual(out["tool_calls"],1)
        self.assertEqual(out["events"][0]["type"],"tool_result")
        self.assertTrue(out["events"][0]["is_error"])
        self.assertEqual(out["approval_requests"],[])

    def test_unreviewed_high_impact_tool_is_not_run_without_task_intent(self):
        mcp=FakeMCP();lm=FakeOllama([calls(("arbitrary_shell",{"command":"id"})),
                                   {"role":"assistant","content":"Команда не запускалась."}])
        out=Agent(lm,lambda:mcp).run([],"Покажи краткий статус проекта")
        self.assertEqual(mcp.calls,[])
        self.assertEqual(out["tool_calls"],0)
        self.assertEqual(out["events"][0]["type"],"task_intent_required")
        self.assertEqual(out["approval_requests"],[])

    def test_unreviewed_read_only_tool_runs_without_per_call_approval(self):
        class ReadMCP(FakeMCP):
            def initialize(self):
                return TOOLS + [{
                    "name":"external_status","description":"Read service status.",
                    "inputSchema":{"type":"object","properties":{},"required":[],"additionalProperties":False},
                }]
            def call(self,name,args):
                self.calls.append((name,args))
                return {"ok":True,"status":"online"},False
        mcp=ReadMCP()
        lm=FakeOllama([calls(("external_status",{})),
                       {"role":"assistant","content":"Сервис online."}])
        out=Agent(lm,lambda:mcp).run([],"Проверь статус сервиса")
        self.assertEqual(mcp.calls,[("external_status",{})])
        self.assertEqual(out["tool_calls"],1)
        self.assertEqual(out["events"][0]["type"],"tool_result")
        self.assertEqual(out["approval_requests"],[])

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
        self.assertEqual(len(lm.prompts), 1)
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


    def test_deepseek_dsml_text_call_is_normalized_and_executed(self):
        mcp = FakeMCP()
        dsml = (
            '< | | DSML | | calls>< | | DSML | | invoke name="ip_network_summary">'
            '< | | DSML | | parameter name="cidr" string="true">192.0.2.7/24'
            '</ | | DSML | | parameter></ | | DSML | | invoke></ | | DSML | | calls>'
        )
        lm = FakeOllama([
            {"role": "assistant", "content": dsml},
            {"role": "assistant", "content": "Подсеть: 192.0.2.0/24."},
        ])
        out = Agent(lm, lambda: mcp).run([], "Проверь подсеть", force_tools=False)
        self.assertEqual(out["tool_calls"], 1)
        self.assertEqual(out["selected_by"], "dsml_content")
        self.assertEqual(mcp.calls, [("ip_network_summary", {"cidr": "192.0.2.7/24"})])
        self.assertEqual(out["answer"], "Подсеть: 192.0.2.0/24.")
        self.assertNotIn("DSML", out["answer"])

    def test_dsml_typed_parameters_are_decoded(self):
        dsml = (
            '<｜DSML｜function_calls><｜DSML｜invoke name="dev_read">'
            '<｜DSML｜parameter name="path" string="true">agent.py</｜DSML｜parameter>'
            '<｜DSML｜parameter name="start_line" string="false">520</｜DSML｜parameter>'
            '<｜DSML｜parameter name="end_line" string="false">600</｜DSML｜parameter>'
            '</｜DSML｜invoke></｜DSML｜function_calls>'
        )
        calls, cleaned, found = _extract_dsml_calls(dsml, {"dev_read"})
        self.assertTrue(found)
        self.assertEqual(cleaned, "")
        self.assertEqual(calls[0]["function"]["arguments"], {
            "path": "agent.py", "start_line": 520, "end_line": 600,
        })

    def test_html_escaped_dsml_is_canonicalized_and_never_exposed(self):
        escaped = (
            '&lt;&#124;DSML&#124;calls&gt;&lt;&#124;DSML&#124;invoke name=&quot;dev_read&quot;&gt;'
            '&lt;&#124;DSML&#124;parameter name=&quot;path&quot; string=&quot;true&quot;&gt;a.py'
            '&lt;/&#124;DSML&#124;parameter&gt;&lt;/&#124;DSML&#124;invoke&gt;&lt;/&#124;DSML&#124;calls&gt;'
        )
        calls, cleaned, found = _extract_dsml_calls(escaped, {"dev_read"})
        self.assertTrue(found)
        self.assertEqual(cleaned, "")
        self.assertEqual(calls[0]["function"]["arguments"], {"path": "a.py"})
        self.assertEqual(_clean_model_answer(escaped), "")

    def test_partial_and_unicode_dsml_never_enter_final_answer(self):
        fragments = (
            '< | | DSML | | invoke name="dev_read">broken',
            'Предисловие: ＜｜DSML｜invoke name="dev_read">broken',
            '&lt;｜DSML｜function_calls&gt;&lt;｜DSML｜invoke name=&quot;dev_read&quot;&gt;',
        )
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                self.assertEqual(_clean_model_answer(fragment), "")

    def test_quoted_dsml_in_prose_is_never_executed(self):
        example = (
            'В документации встречается: <｜DSML｜calls><｜DSML｜invoke name="dev_read">'
            '<｜DSML｜parameter name="path" string="true">a.py</｜DSML｜parameter>'
            '</｜DSML｜invoke></｜DSML｜calls>'
        )
        calls, cleaned, found = _extract_dsml_calls(example, {"dev_read"})
        self.assertTrue(found)
        self.assertEqual(calls, [])
        self.assertEqual(cleaned, "В документации встречается:")
    def test_fenced_protocol_sample_is_preserved_as_educational_code(self):
        sample = '```text\n<｜DSML｜invoke name="dev_read">example\n```'
        self.assertEqual(_clean_model_answer(sample), sample)
    def test_empty_model_answer_gets_a_text_only_retry(self):
        lm = FakeOllama([
            {"role": "assistant", "content": ""},
            {"role": "assistant", "content": "Проверка завершена."},
        ])
        out = Agent(lm, lambda: FakeMCP()).run(
            [], "Ответь обычным текстом", tools_enabled=False,
        )
        self.assertEqual(out["answer"], "Проверка завершена.")
        self.assertEqual(len(lm.prompts), 2)  # Two text-only attempts; no tool evidence to review.
        self.assertEqual(lm.prompts[1][1], [])

    def test_round_limit_uses_finalizer_and_never_returns_dsml(self):
        mcp = FakeMCP()
        dsml = (
            '<｜DSML｜function_calls><｜DSML｜invoke name="ip_network_summary">'
            '<｜DSML｜parameter name="cidr" string="true">192.0.2.7/24'
            '</｜DSML｜parameter></｜DSML｜invoke></｜DSML｜function_calls>'
        )
        lm = FakeOllama([
            calls(("ip_network_summary", {"cidr": "192.0.2.7/24"})),
            {"role": "assistant", "content": dsml},
            {"role": "assistant", "content": "Итог: сеть 192.0.2.0/24."},
        ])
        with patch("console.agent.MAX_ROUNDS", 2):
            out = Agent(lm, lambda: mcp).run([], "Проверь подсеть", force_tools=False)
        self.assertEqual(out["tool_calls"], 1)
        self.assertEqual(out["answer"], "Итог: сеть 192.0.2.0/24.")
        self.assertNotIn("DSML", out["answer"])
        self.assertEqual(len(lm.prompts), 4)  # Includes second-pass audit.

    def test_routine_read_skips_extra_review_but_preserves_evidence(self):
        runtime = FakeLocalToolRuntime()
        runtime.tools[0]["name"] = "terminal_status"
        runtime.tool_map = {"terminal_status": runtime.tools[0]}
        model = FakeOllama([calls(("terminal_status", {})),
                           {"role": "assistant", "content": "Windows"}])
        answer = Agent(model, lambda: FakeMCP(), local_tool_runtime=runtime).run(
            [], "Check the terminal status",
        )
        self.assertEqual(len(model.prompts), 2)
        self.assertEqual(answer["review"]["scope"], "routine_read")
        self.assertEqual(answer["events"][0]["result"]["os"], "Windows")

    def test_compact_context_deduplicates_equal_browser_snapshots(self):
        page = {"ok": True, "url": "https://example.com", "title": "Example",
                "visible_text": "body", "form_fields": [{"label": "Name"}]}
        messages = [{"role": "user", "content": "Read the page"}]
        for index, result in enumerate((page, {**page, "http_status": 200},
                                        {**page, "form_fields": [{"label": "Email"}]})):
            messages.extend([
                {"role": "assistant", "tool_calls": [{"id": f"call_{index}",
                  "function": {"name": "browser_snapshot", "arguments": "{}"}}]},
                {"role": "tool", "tool_name": "browser_snapshot", "content": json.dumps(result)},
            ])
        results = [json.loads(item["content"]) for item in _compact_context(messages)
                   if item["role"] == "tool"]
        self.assertEqual(results[0], page)
        self.assertEqual(results[1]["http_status"], 200)
        self.assertNotIn("visible_text", results[1])
        self.assertEqual(results[2]["form_fields"], [{"label": "Email"}])
        self.assertEqual(results[2]["page_content"], "changed_fields_only")
        self.assertNotIn("visible_text", results[2])

    def test_large_browser_observation_remains_valid_and_keeps_controls(self):
        page = {"ok": True, "url": "https://example.com/form", "visible_text": "a" * 6500,
                "links": [{"name": "Link", "url": "https://example.com/" + "a" * 150}] * 35,
                "buttons": [{"name": "Continue", "id": "next"}],
                "form_fields": [{"label": "Name", "id": "name"}]}
        messages = [
            {"role": "user", "content": "Read the form"},
            {"role": "assistant", "tool_calls": [
                {"function": {"name": "browser_snapshot", "arguments": "{}"}}
            ]},
            {"role": "tool", "tool_name": "browser_snapshot", "content": json.dumps(page)},
        ]
        content = _compact_context(messages)[-1]["content"]
        observation = json.loads(content)
        self.assertLessEqual(len(content), 3500)
        self.assertTrue(observation["observation_truncated"])
        self.assertEqual(observation["form_fields"], page["form_fields"])
        self.assertEqual(observation["buttons"], page["buttons"])

    def test_compact_context_keeps_recent_tool_pairs_and_bounds_payloads(self):
        messages = [{"role": "system", "content": "system"}, {"role": "user", "content": "task"}]
        for index in range(12):
            call = {"function": {"name": "tool_" + str(index), "arguments": {"index": index}}}
            messages.append({"role": "assistant", "content": "", "tool_calls": [call]})
            messages.append({"role": "tool", "tool_name": "tool_" + str(index), "content": "x" * 6000})
        compact = _compact_context(messages)
        self.assertEqual(sum(len(item.get("tool_calls", [])) for item in compact), 8)
        tool_results = [item for item in compact if item.get("role") == "tool"]
        self.assertEqual(len(tool_results), 8)
        self.assertTrue(all(len(item["content"]) <= 3500 for item in tool_results))
        normalized = _normalize_context(compact)
        self.assertEqual(sum(item.get("role") == "tool" for item in normalized), 8)
        self.assertTrue(any("tool_0" in item.get("content", "") for item in compact if item.get("role") == "assistant"))
        self.assertTrue(any("tool_11" in call["function"]["name"]
                            for item in compact for call in item.get("tool_calls", [])))


if __name__=="__main__":
    unittest.main()
