"""Opt-in live Chromium smoke against a synthetic loopback-only fixture.

No credentials, external account, provider API key or public website required.
The scripted model isolates browser/registry/dispatch from model quality.
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.agent import Agent
from console.gpt_tool_runtime import GPTToolRuntime


@unittest.skipUnless(os.environ.get("CYBERNOVA_LIVE_BROWSER_SMOKE") == "1",
                     "opt-in real Patchright Chromium smoke")
class PatchrightLiveSmoke(unittest.TestCase):
    def test_registered_agent_calls_reach_patchright_and_submit_fixture_once(self):
        posts = []

        class Fixture(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_html(self, body):
                data = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.send_html(
                    '<title>Cybernova fixture</title><h1>Registration fixture</h1>'
                    '<form method="POST" action="/done">'
                    '<label for="display">Display name</label>'
                    '<input id="display" name="display" type="text">'
                    '<button type="submit">Register</button></form>'
                )

            def do_POST(self):
                data = self.rfile.read(int(self.headers["Content-Length"]))
                posts.append(parse_qs(data.decode("utf-8")))
                self.send_html("<title>Done</title><h1>Registration complete</h1>")

        with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = "http://127.0.0.1:" + str(server.server_port) + "/"

            class NoRemote:
                def initialize(self):
                    return []

            class ScriptedModel:
                model = "scripted-browser-smoke"

                def __init__(self):
                    self.calls = iter([
                        ("browser_navigate", {"url": url}),
                        ("browser_fill", {"target": "Display name", "value": "Synthetic",
                                          "human_like": False}),
                        ("browser_submit", {"name": "Register"}),
                    ])

                def chat(self, messages, tools=None, **kwargs):
                    item = next(self.calls, None) if tools else None
                    if item is None:
                        return {"content": "Fixture completed."}
                    name, args = item
                    if name not in {tool["function"]["name"] for tool in tools}:
                        raise AssertionError("Tool not advertised: " + name)
                    return {"content": "", "tool_calls": [
                        {"function": {"name": name, "arguments": args}}
                    ]}

            try:
                with TemporaryDirectory() as folder, patch.dict(os.environ, {
                    "CYBERNOVA_BROWSER_BACKEND": "patchright",
                    "CYBERNOVA_GPT_BROWSER_HEADLESS": "1",
                    "CYBERNOVA_GPT_BROWSER_EPHEMERAL": "1",
                    "CYBERNOVA_GPT_BROWSER_RESTORE_SESSION": "0",
                }):
                    runtime = GPTToolRuntime(browser_profile_dir=folder)
                    try:
                        out = Agent(ScriptedModel(), NoRemote, runtime).run(
                            [], "Register a synthetic test account on " + url,
                            tool_groups=["browser"], force_tools=False,
                            session_id="patchright-ci-fixture",
                            scope={"hosts": ["127.0.0.1"]},
                        )
                        events = [e for e in out["events"] if e.get("type") == "tool_result"]
                        self.assertEqual([e["name"] for e in events], [
                            "browser_navigate", "browser_fill", "browser_submit",
                        ], out)
                        self.assertTrue(all(not e["is_error"] for e in events), events)
                        self.assertEqual(events[0]["result"]["browser_backend"], "patchright")
                        self.assertIn("Registration complete", events[-1]["result"]["visible_text"])
                        self.assertEqual(posts, [{"display": ["Synthetic"]}])
                    finally:
                        runtime.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
