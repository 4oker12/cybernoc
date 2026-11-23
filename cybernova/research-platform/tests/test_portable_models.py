"""No-network tests of pluggable local/hosted model providers."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
from urllib.error import HTTPError
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from console.model_providers import (
    OpenAICompatibleClient, ModelConfigError, _endpoint, _normalize_context,
    build_model_client, provider_name,
)
from console.agent import OllamaClient, Agent, BASE_SYSTEM


class ModelProviderTests(unittest.TestCase):
    def test_default_is_legacy_ollama(self):
        with patch.dict(os.environ, {"CYBERNOVA_LLM_PROVIDER":"ollama"}):
            self.assertIsInstance(build_model_client(),OllamaClient)
            self.assertIsInstance(Agent().ollama,OllamaClient)

    def test_selected_remote_provider_uses_same_agent_interface(self):
        with patch.dict(os.environ, {
            "CYBERNOVA_LLM_PROVIDER":"openai_compatible",
            "CYBERNOVA_LLM_BASE_URL":"https://llm.example/v1",
            "CYBERNOVA_LLM_API_KEY":"test-not-real-key",
            "CYBERNOVA_MODEL":"hosted-test-model",
            "CYBERNOVA_LLM_API_KEY_FILE":"",
        }):
            backend=build_model_client()
            self.assertIsInstance(backend,OpenAICompatibleClient)
            self.assertIsInstance(Agent().ollama,OpenAICompatibleClient)
            self.assertEqual(backend.endpoint,"https://llm.example/v1/chat/completions")
            self.assertEqual(backend.model,"hosted-test-model")

    def test_remote_https_required_and_bad_urls_rejected(self):
        for value in ("http://llm.example/v1",
                      "https://name:pass@llm.example/v1",
                      "https://llm.example/v1?password=secret",
                      "https://llm.example/v1#fragment",
                      "file:///etc/passwd",
                      "https://llm.example/evil\nheader:x"):
            with self.assertRaises(ModelConfigError,msg=value):
                _endpoint(value)
        self.assertEqual(_endpoint("http://ollama:11434/v1"),
                         "http://ollama:11434/v1/chat/completions")

    def test_remote_requires_key_but_local_does_not(self):
        with patch.dict(os.environ, {
            "CYBERNOVA_LLM_API_KEY":"",
            "CYBERNOVA_LLM_API_KEY_FILE":"",
        }):
            with self.assertRaises(ModelConfigError):
                OpenAICompatibleClient(base_url="https://hosted.example/v1",model="test")
            client=OpenAICompatibleClient(base_url="http://127.0.0.1:8000/v1",model="test")
            self.assertEqual(client.api_key,"")

    def test_secrets_loaded_from_file_not_logged(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Path(temp)/"api_key"
            f.write_text("test-remote-api-key\n")
            with patch.dict(os.environ,{
                "CYBERNOVA_LLM_API_KEY":"",
                "CYBERNOVA_LLM_API_KEY_FILE":str(f),
            }):
                backend=OpenAICompatibleClient(base_url="https://api.example/v1",model="x")
                self.assertEqual(backend.api_key,"test-remote-api-key")

    def test_tools_translated_from_remote_chat_completion(self):
        payloads=[]
        def transport(payload):
            payloads.append(payload)
            return {
                "choices":[{"message":{
                    "role":"assistant","content":"",
                    "tool_calls":[{"id":"call_A","type":"function",
                        "function":{"name":"gateway_status","arguments":"{}"}}]
                }}],
            }
        c=OpenAICompatibleClient(
            base_url="https://api.example/v1",model="model",
            api_key="example-test-key",transport=transport,
        )
        answer=c.chat([{"role":"system","content":"System"},
                       {"role":"user","content":"Check"}],
                      tools=[{"type":"function","function":{
                          "name":"gateway_status","parameters":{"type":"object"}
                      }}])
        self.assertEqual(answer["tool_calls"][0]["function"]["name"],"gateway_status")
        self.assertEqual(payloads[0]["tools"][0]["function"]["name"],"gateway_status")

    def test_deepseek_thinking_tool_call_round_trips_reasoning_content(self):
        transmitted=[]
        def transport(payload):
            transmitted.append(payload)
            return {"choices":[{"message":{
                "role":"assistant","content":"",
                "reasoning_content":"I should inspect the subnet tool.",
                "tool_calls":[{"id":"call_deepseek_1","type":"function",
                    "function":{"name":"ip_network_summary",
                                "arguments":"{\"cidr\":\"192.0.2.7/24\"}"}}]
            }}]}
        backend=OpenAICompatibleClient(
            base_url="https://api.deepseek.com",model="deepseek-flash",
            api_key="test-deepseek-key",transport=transport,
        )
        tools=[{"type":"function","function":{
            "name":"ip_network_summary",
            "parameters":{"type":"object","properties":{"cidr":{"type":"string"}}}
        }}]
        answer=backend.chat([{"role":"system","content":BASE_SYSTEM},
                             {"role":"user","content":"Проверь подсеть"}],tools=tools)
        self.assertEqual(backend.endpoint,"https://api.deepseek.com/chat/completions")
        self.assertEqual(transmitted[0]["thinking"],{"type":"enabled"})
        self.assertEqual(answer["reasoning_content"],"I should inspect the subnet tool.")
        self.assertEqual(answer["tool_calls"][0]["id"],"call_deepseek_1")
        normalized=_normalize_context([
            {"role":"system","content":BASE_SYSTEM},
            {"role":"user","content":"Проверь подсеть"},
            {"role":"assistant","content":answer["content"],
             "reasoning_content":answer["reasoning_content"],
             "tool_calls":answer["tool_calls"]},
            {"role":"tool","content":"{\"network\":\"192.0.2.0/24\"}"},
        ])
        self.assertEqual(normalized[2]["reasoning_content"],
                         "I should inspect the subnet tool.")
        self.assertEqual(normalized[3]["tool_call_id"],"call_deepseek_1")

    def test_pro_model_sends_high_and_max_reasoning_effort(self):
        sent = []
        def transport(payload):
            sent.append(payload)
            return {"choices": [{"message": {"content": "ok"}}]}
        client = OpenAICompatibleClient(
            base_url="https://api.deepseek.com", model="deepseek-v4-pro",
            api_key="test-deepseek-key", transport=transport)
        for effort in ("high", "max"):
            with patch.dict(os.environ, {
                "CYBERNOVA_DEEPSEEK_THINKING": "enabled",
                "CYBERNOVA_DEEPSEEK_REASONING_EFFORT": effort,
            }):
                client.chat([{"role": "user", "content": "test"}])
        self.assertEqual([p["model"] for p in sent],
                         ["deepseek-v4-pro", "deepseek-v4-pro"])
        self.assertEqual([p["reasoning_effort"] for p in sent], ["high", "max"])
        self.assertTrue(all(p["thinking"] == {"type": "enabled"} for p in sent))

    def test_deepseek_can_be_disabled_from_thinking_mode(self):
        transmitted=[]
        def transport(payload):
            transmitted.append(payload)
            return {"choices":[{"message":{"content":"ok"}}]}
        backend=OpenAICompatibleClient(
            base_url="https://api.deepseek.com",model="deepseek-flash",
            api_key="test-deepseek-key",transport=transport,
        )
        with patch.dict(os.environ,{"CYBERNOVA_DEEPSEEK_THINKING":"disabled"}):
            backend.chat([{"role":"user","content":"test"}])
        self.assertEqual(transmitted[0]["thinking"],{"type":"disabled"})

    def test_hosted_model_receives_shared_cybernova_profile(self):
        transmitted=[]
        class EmptyMCP:
            def initialize(self):
                return []
        def transport(payload):
            transmitted.append(payload)
            return {"choices":[{"message":{"role":"assistant","content":"Профиль получен."}}]}
        backend=OpenAICompatibleClient(
            base_url="https://api.deepseek.com",model="deepseek-flash",
            api_key="test-deepseek-key",transport=transport,
        )
        result=Agent(backend,mcp_factory=EmptyMCP).run(
            [],"Проверь наличие своего рабочего профиля",force_tools=False
        )
        self.assertEqual(result["answer"],"Профиль получен.")
        system=transmitted[0]["messages"][0]
        self.assertEqual(system["role"],"system")
        self.assertIn("ChatGPT в основном проектном чате пользователя",system["content"])
        self.assertIn("локальный исполнитель Cybernova",system["content"])
        self.assertIn("разработчиком самой",system["content"])
        self.assertIn("Chromium/Playwright",system["content"])

    def test_controller_tool_history_translated_to_valid_openai_protocol(self):
        messages=[
            {"role":"user","content":"Run"},
            {"role":"assistant","content":"",
             "tool_calls":[{"function":{"name":"gateway_status","arguments":{}}},
                           {"function":{"name":"ip_network_summary","arguments":{"cidr":"192.0.2.1/24"}}}]},
            {"role":"tool","tool_name":"gateway_status","content":"{\"ok\":true}"},
            {"role":"tool","tool_name":"ip_network_summary","content":"{\"ok\":true}"},
        ]
        converted=_normalize_context(messages)
        calls=converted[1]["tool_calls"]
        self.assertEqual(len(calls),2)
        self.assertEqual([x["tool_call_id"] for x in converted[2:]], [x["id"] for x in calls])
        self.assertEqual(converted[3]["role"],"tool")
        with self.assertRaises(ModelConfigError):
            _normalize_context([{"role":"tool","content":"orphan"}])

    def test_reasoning_model_uses_completion_tokens_without_forced_temperature(self):
        transmitted=[]
        def transport(payload):
            transmitted.append(payload)
            return {"choices":[{"message":{"content":"Проверено"}}]}
        with patch.dict(os.environ,{
            "CYBERNOVA_LLM_TOKEN_PARAMETER":"",
            "CYBERNOVA_LLM_TEMPERATURE":"",
        }):
            backend=OpenAICompatibleClient(
                base_url="https://api.example/v1",model="gpt-6",
                api_key="test-no-real-key",transport=transport,
            )
            self.assertEqual(backend.chat([{"role":"user","content":"Проверка"}])["content"],
                             "Проверено")
        self.assertIn("max_completion_tokens",transmitted[0])
        self.assertNotIn("max_tokens",transmitted[0])
        self.assertNotIn("temperature",transmitted[0])

    def test_compatibility_parameters_are_opt_in_and_validated(self):
        transmitted=[]
        def transport(payload):
            transmitted.append(payload)
            return {"choices":[{"message":{"content":"ok"}}]}
        backend=OpenAICompatibleClient(base_url="https://api.example/v1",
                                       model="provider-model",
                                       api_key="test-no-real-key",transport=transport)
        with patch.dict(os.environ,{
            "CYBERNOVA_LLM_TOKEN_PARAMETER":"max_tokens",
            "CYBERNOVA_LLM_TEMPERATURE":"0.2",
        }):
            backend.chat([{"role":"user","content":"test"}])
        self.assertEqual(transmitted[-1]["max_tokens"],4096)
        self.assertEqual(transmitted[-1]["temperature"],0.2)
        with patch.dict(os.environ,{"CYBERNOVA_LLM_TOKEN_PARAMETER":"unsafe_key",
                                     "CYBERNOVA_LLM_TEMPERATURE":""}):
            with self.assertRaises(ModelConfigError):
                backend.chat([{"role":"user","content":"test"}])
        with patch.dict(os.environ,{"CYBERNOVA_LLM_TOKEN_PARAMETER":"max_tokens",
                                     "CYBERNOVA_LLM_TEMPERATURE":"not_a_number"}):
            with self.assertRaises(ModelConfigError):
                backend.chat([{"role":"user","content":"test"}])

    def test_http_400_exposes_only_redacted_provider_error_metadata(self):
        backend=OpenAICompatibleClient(
            base_url="https://api.example/v1",model="deepseek-flash",
            api_key="test-api-key",transport=None,
        )
        body=json.dumps({"error":{
            "type":"invalid_request_error",
            "code":"unsupported_parameter",
            "param":"messages[3].reasoning_content",
            "message":"Unsupported parameter reasoning_content; api_key=sk-1234567890ABCDEFGHIJ",
        }}).encode()
        class RejectingOpener:
            def open(self,*args,**kwargs):
                raise HTTPError("https://api.example/v1/chat/completions",400,
                                "Bad Request",{},io.BytesIO(body))
        with patch("console.model_providers.request.build_opener",
                   return_value=RejectingOpener()):
            with self.assertRaises(ModelConfigError) as ctx:
                backend._request({"model":"deepseek-flash"})
        self.assertEqual(str(ctx.exception),"llm_http_400")
        self.assertIn("unsupported_parameter",ctx.exception.safe_detail)
        self.assertIn("reasoning_content",ctx.exception.safe_detail)
        self.assertNotIn("sk-1234567890ABCDEFGHIJ",ctx.exception.safe_detail)

    def test_agent_failure_includes_sanitized_provider_reason(self):
        class FailingClient:
            provider="OpenAI-compatible"
            model="deepseek-flash"
            def chat(self,*args,**kwargs):
                raise ModelConfigError(
                    "llm_http_400",
                    safe_detail="type=invalid_request_error; param=reasoning_content; message=Unsupported parameter",
                )
        result=Agent(FailingClient()).run(
            [],"Проверь состояние",tools_enabled=False,force_tools=False,
        )
        self.assertIn("Ошибка исполнения: llm_http_400",result["answer"])
        self.assertIn("Деталь провайдера:",result["answer"])
        self.assertIn("reasoning_content",result["answer"])
        self.assertEqual(result["error_code"],"llm_http_400")

    def test_json_mode_and_provider_errors_never_echo_credentials(self):
        def transport(payload):
            self.assertEqual(payload["response_format"],{"type":"json_object"})
            return {"choices":[{"message":{"content":"{\"questions\":[]}"}}]}
        c=OpenAICompatibleClient(base_url="https://api.example/v1",
                                 api_key="secret-key-not-log",model="model",
                                 transport=transport)
        self.assertEqual(c.chat([{"role":"user","content":"hi"}],json_mode=True)["content"],
                         "{\"questions\":[]}")
        bad=OpenAICompatibleClient(base_url="https://api.example/v1",
                                  api_key="secret-key-not-log",model="model",
                                  transport=lambda _:{"bad":"payload"})
        with self.assertRaises(ModelConfigError) as ctx:
            bad.chat([{"role":"user","content":"hi"}])
        self.assertNotIn("secret-key-not-log",str(ctx.exception))


if __name__=="__main__":
    unittest.main()
