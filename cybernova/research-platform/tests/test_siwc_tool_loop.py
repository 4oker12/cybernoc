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
    def __init__(self):
        self.requests = []

    def open(self, req, **_):
        payload = json.loads(req.data)
        self.requests.append(payload)
        if len(self.requests) == 1:
            return FakeStream(sse({
                "output": [{
                    "type": "function_call",
                    "call_id": "call_terminal_1",
                    "name": "terminal_status",
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
    tools = [{
        "type": "function", "name": "terminal_status",
        "description": "Check local executor status.",
        "parameters": {"type": "object", "properties": {},
                       "required": [], "additionalProperties": False},
        "strict": True,
    }]

    def __init__(self):
        self.calls = []

    def call(self, name, args, *, authorized_targets=None):
        self.calls.append((name, args, authorized_targets))
        return {"ok": True, "os": "Windows", "powershell_7": True}, False


class AccountGPTToolLoopTests(unittest.TestCase):
    def test_model_selects_tool_then_receives_result_and_continues(self):
        opener = FakeOpener()
        runtime = FakeRuntime()
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
            )

        self.assertEqual(result["answer"], "Проверка завершена.")
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(len(result["tool_events"]), 1)
        self.assertEqual(runtime.calls[0][0], "terminal_status")
        self.assertEqual(runtime.calls[0][2], {"185.238.114.6"})
        self.assertEqual(opener.requests[0]["tool_choice"], "auto")
        second_input = opener.requests[1]["input"]
        self.assertTrue(any(item.get("type") == "function_call" for item in second_input))
        self.assertTrue(any(item.get("type") == "function_call_output" for item in second_input))
        self.assertFalse(opener.requests[0]["store"])

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


if __name__ == "__main__":
    unittest.main()
