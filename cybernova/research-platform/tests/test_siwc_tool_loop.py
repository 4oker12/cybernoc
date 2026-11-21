"""Offline function-calling loop tests for Account GPT."""
from pathlib import Path
import json
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import siwc_inference


def sse(response):
    return [b"data: " + json.dumps({
        "type": "response.completed", "response": response,
    }).encode("utf-8") + b"\n"]


class FakeStream:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def __iter__(self):
        return iter(self.events)


class FakeOpener:
    def __init__(self, tool_name="terminal_status"):
        self.requests = []
        self.tool_name = tool_name

    def open(self, req, **_):
        payload = json.loads(req.data)
        self.requests.append(payload)
        has_additional_tools = any(
            item.get("type") == "additional_tools" for item in payload.get("input", [])
        )
        if len(self.requests) == 1 and has_additional_tools:
            return FakeStream(sse({
                "output": [{
                    "type": "function_call",
                    "call_id": "call_terminal_1",
                    "name": self.tool_name,
                    "arguments": "{}",
                }]
            }))
        return FakeStream(sse({
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "Проверка завершена."}],
            }]
        }))


class FakeRuntime:
    def __init__(self, tool_name="terminal_status", result=None):
        self.tools = [{
            "type": "function", "name": tool_name,
            "description": "Test local tool.",
            "parameters": {"type": "object", "properties": {},
                           "required": [], "additionalProperties": False},
            "strict": True,
        }]
        self.result = result or {"ok": True, "os": "Windows", "cmd_exe": True, "terminal": "Windows CMD"}
        self.calls = []

    def call(self, name, args, *, authorized_targets=None, user_messages=None):
        self.calls.append((name, args, authorized_targets, user_messages))
        return self.result, False


class AccountGPTToolLoopTests(unittest.TestCase):
    def test_model_selects_tool_then_receives_result_and_continues(self):
        opener = FakeOpener()
        runtime = FakeRuntime()
        receipts = []
        with patch.object(siwc_inference, "models", return_value=[
                 {"slug": "gpt-6.2-sol", "display_name": "GPT"},
             ]), \
             patch.object(siwc_inference.connection, "access", return_value="test-token"), \
             patch.object(siwc_inference.request, "build_opener", return_value=opener):
            result = siwc_inference.chat(
                "gpt-6.2-sol",
                [{"role": "user", "content": "Проверь локальный терминал."}],
                tool_runtime=runtime,
                authorized_targets={"185.238.114.6"},
                on_tool_event=receipts.append,
            )

        self.assertEqual(result["answer"], "Проверка завершена.")
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(len(result["tool_events"]), 1)
        self.assertEqual(receipts, result["tool_events"])
        self.assertEqual(runtime.calls[0][0], "terminal_status")
        self.assertEqual(runtime.calls[0][2], {"185.238.114.6"})
        self.assertEqual(runtime.calls[0][3], [{"role": "user", "content": "Проверь локальный терминал."}])
        self.assertEqual(opener.requests[0]["tool_choice"], "auto")
        self.assertNotIn("tools", opener.requests[0])
        self.assertEqual(opener.requests[0]["input"][0]["type"], "additional_tools")
        second_input = opener.requests[1]["input"]
        self.assertTrue(any(item.get("type") == "function_call" for item in second_input))
        self.assertTrue(any(item.get("type") == "function_call_output" for item in second_input))
        self.assertFalse(opener.requests[0]["store"])

    def test_screenshot_is_returned_to_model_as_image_content(self):
        opener = FakeOpener(tool_name="browser_screenshot")
        runtime = FakeRuntime(
            tool_name="browser_screenshot",
            result={
                "ok": True, "url": "https://example.com/",
                "image_data_url": "data:image/jpeg;base64,ZmFrZQ==",
            },
        )
        with patch.object(siwc_inference, "models", return_value=[
                 {"slug": "gpt-6.2-sol", "display_name": "GPT"},
             ]), \
             patch.object(siwc_inference.connection, "access", return_value="test-token"), \
             patch.object(siwc_inference.request, "build_opener", return_value=opener):
            result = siwc_inference.chat(
                "gpt-6.2-sol",
                [{"role": "user", "content": "Посмотри страницу визуально."}],
                tool_runtime=runtime,
            )
        second_input = opener.requests[1]["input"]
        function_output = next(
            item for item in second_input if item.get("type") == "function_call_output"
        )
        self.assertIsInstance(function_output["output"], list)
        self.assertEqual(function_output["output"][1]["type"], "input_image")
        self.assertNotIn("image_data_url", result["tool_events"][0]["result"])
        self.assertEqual(result["tool_events"][0]["result"]["screenshot"],
                         "captured and sent to the model")

    def test_text_only_mode_does_not_send_tools(self):
        opener = FakeOpener()
        with patch.object(siwc_inference, "models", return_value=[
                 {"slug": "gpt-6.2-sol", "display_name": "GPT"},
             ]), \
             patch.object(siwc_inference.connection, "access", return_value="test-token"), \
             patch.object(siwc_inference.request, "build_opener", return_value=opener):
            result = siwc_inference.chat(
                "gpt-6.2-sol",
                [{"role": "user", "content": "Ответь без инструментов."}],
            )
        self.assertEqual(result["answer"], "Проверка завершена.")
        self.assertNotIn("tools", opener.requests[0])
        self.assertFalse(any(
            item.get("type") == "additional_tools" for item in opener.requests[0]["input"]
        ))


if __name__ == "__main__":
    unittest.main()
