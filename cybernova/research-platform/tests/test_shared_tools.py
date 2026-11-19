"""No-network tests for shared safe terminal, browser and GPT tool handoff."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from fastapi.testclient import TestClient
from console import server, shared_tool_support
from console.safe_terminal import safe_terminal, TERMINAL_COMMANDS
from console.traffic_tools import TrafficToolClient
from console.tool_policy import REVIEWED_TOOLS


class FakeUpstream:
    def initialize(self):
        return []
    def call(self, name, args):
        return {"ok":True,"authorized_hosts":[]},False


class SharedToolTests(unittest.TestCase):
    def test_terminal_rejects_arbitrary_shell(self):
        with tempfile.TemporaryDirectory() as dirname:
            for command in ["rm -rf /", "ls ; echo secret", "git push", "python -c 'print(1)'", "echo abc"]:
                with self.assertRaisesRegex(ValueError, "terminal_command_not_allowlisted"):
                    safe_terminal(command, source=Path(dirname))

    def test_terminal_is_fixed_read_only_argv(self):
        with tempfile.TemporaryDirectory() as dirname:
            calls=[]
            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                return CompletedProcess(argv, 0, stdout=" M file.py\n", stderr="")
            result=safe_terminal("git status",source=Path(dirname),runner=runner)
            self.assertTrue(result["ok"])
            self.assertEqual(calls[0][0],["git","--no-optional-locks","status","--short","--untracked-files=no"])
            self.assertIs(calls[0][1]["shell"],False)
            self.assertEqual(calls[0][1]["timeout"],6)
            self.assertIn("file.py",result["output"])

    def test_secret_named_files_are_hidden(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            for name in ["normal.py", ".env", "credentials.json", "id_rsa", "module"]:
                (root/name).write_text("hello",encoding="utf-8")
            result=safe_terminal("list",source=root)
            self.assertIn("normal.py",result["output"])
            for secret in [".env", "credentials.json", "id_rsa"]:
                self.assertNotIn(secret,result["output"])

    def test_both_modes_advertise_same_three_tools(self):
        client=TrafficToolClient(FakeUpstream(),{},scope={"hosts":[]})
        names={tool["name"] for tool in client.initialize()}
        for item in ["safe_terminal","google_search","research_source_open"]:
            self.assertIn(item,names)
            self.assertIn(item,REVIEWED_TOOLS)

    def test_preflight_search_and_direct_source(self):
        choice=shared_tool_support.choose_safe_tool("Найди реальные кейсы CVE-2026-12345")
        self.assertEqual(choice[0],"google_search")
        choice=shared_tool_support.choose_safe_tool("Открой https://vendor.example/advisory")
        self.assertEqual(choice[0],"research_source_open")
        self.assertEqual(choice[1]["url"],"https://vendor.example/advisory")
        choice=shared_tool_support.choose_safe_tool("Покажи терминал git status")
        self.assertEqual(choice,("safe_terminal",{"command":"git status"}))
        self.assertIsNone(shared_tool_support.choose_safe_tool("Привет"))

    def test_preflight_returns_actual_tool_data_as_untrusted(self):
        with patch.object(shared_tool_support,"research_web_call",
                          return_value=({"ok":True,"results":[{"title":"Advisory","url":"https://vendor.example/x"}]},False)):
            result=shared_tool_support.preflight("Найди уязвимости Apache")
        self.assertEqual(result["events"][0]["name"],"google_search")
        self.assertIn("НЕДОВЕРЕННЫЙ",result["context"])
        self.assertIn("Advisory",result["context"])

    def test_shared_http_api_only_calls_allowlisted_tools(self):
        with patch.object(server,"safe_terminal",return_value={"ok":True,"command":"pwd","output":"workspace"}):
            client=TestClient(server.app,base_url="http://127.0.0.1:18794")
            answer=client.post("/api/tools/run",json={"name":"safe_terminal","argument":"pwd"})
        self.assertEqual(answer.status_code,200,answer.text)
        self.assertEqual(answer.json()["tool"],"safe_terminal")
        self.assertEqual(client.post("/api/tools/run",
                         json={"name":"arbitrary_shell","argument":"echo test"}).status_code,422)

    def test_gpt_receives_tool_observation_without_mcp_shell_access(self):
        calls=[]
        with tempfile.TemporaryDirectory() as dirname:
            from console.siwc_chat_store import GPTChatStore
            store=GPTChatStore(Path(dirname)/"comm.sqlite3")
            def fake(model,messages,**kwargs):
                calls.append(messages)
                return {"answer":"Исследовал бюллетень, подтверждение требует проверки.","source":"mock"}
            with patch.object(server,"gpt_chat_store",return_value=store), \
                 patch.object(server,"chatgpt_chat",side_effect=fake), \
                 patch.object(server,"gpt_tool_preflight",
                              return_value={"context":"\n[REAL TOOL EVENT]", "events":[{"name":"google_search","ok":True}]}):
                client=TestClient(server.app,base_url="http://127.0.0.1:18794")
                response=client.post("/api/siwc/chat",
                                     json={"model":"gpt-test","message":"Найди CVE"})
            self.assertEqual(response.status_code,200,response.text)
            self.assertIn("REAL TOOL EVENT",calls[0][-1]["content"])
            self.assertEqual(response.json()["tool_events"][0]["name"],"google_search")
            saved=store.get_thread(response.json()["thread_id"])
            self.assertNotIn("REAL TOOL EVENT",json.dumps(saved))


if __name__=="__main__":
    unittest.main()
