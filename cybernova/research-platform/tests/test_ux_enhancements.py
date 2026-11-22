"""Regression tests for compact, responsive Cybernova conversation UX."""
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import server
from console.tunnel_access import allowed_path
from fastapi.testclient import TestClient


class UXEnhancementTests(unittest.TestCase):
    def test_assets_and_model_settings_routes_are_exposed_by_authenticated_gateway(self):
        for path, method in (
            ("/api/model-config", "GET"),
            ("/api/model-config", "POST"),
            ("/static/ux.css", "GET"),
            ("/static/ux.js", "GET"),
            ("/static/model-settings.js", "GET"),
        ):
            self.assertTrue(allowed_path(path, method), (path, method))
        html = (ROOT / "console/static/index.html").read_text(encoding="utf-8")
        self.assertIn('/static/ux.css', html)
        self.assertIn('/static/ux.js', html)
        self.assertIn('/static/model-settings.js', html)

    def test_model_settings_api_never_returns_the_api_key(self):
        settings = {
            "provider": "openai_compatible",
            "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com",
            "api_key_configured": True,
            "api_key_hint": "Ключ сохранён локально",
            "restart_required": False,
        }
        client = TestClient(server.app, base_url="http://127.0.0.1:18794")
        with patch.object(server, "get_model_settings", return_value=settings):
            response = client.get("/api/model-config")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["settings"]["api_key_configured"])
        self.assertNotIn("api_key", response.json()["settings"])

    def test_model_settings_apply_replaces_active_research_client(self):
        settings = {
            "provider": "openai_compatible", "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com",
            "api_key_configured": True, "api_key_hint": "Ключ сохранён локально",
            "restart_required": False,
        }
        replacement = SimpleNamespace(model="deepseek-chat")
        previous = server.agent.ollama
        client = TestClient(server.app, base_url="http://127.0.0.1:18794")
        try:
            with patch.object(server, "apply_model_settings", return_value=(replacement, settings)):
                response = client.post("/api/model-config", json={
                    "provider": "openai_compatible",
                    "model": "deepseek-chat",
                    "base_url": "https://api.deepseek.com",
                    "api_key": "sk-test-key-value",
                })
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["applied"])
            self.assertIs(server.agent.ollama, replacement)
            self.assertNotIn("sk-test-key-value", response.text)
        finally:
            server.agent.ollama = previous

    def test_tool_calls_are_rendered_as_one_collapsible_batch(self):
        ux = (ROOT / "console/static/ux.js").read_text(encoding="utf-8")
        css = (ROOT / "console/static/ux.css").read_text(encoding="utf-8")
        self.assertIn("tool-batch", ux)
        self.assertIn("Инструменты", ux)
        self.assertIn(".tool-batch", css)
        self.assertIn("followup-questions", css)

    def test_chatgpt_terminal_paste_extension_is_scoped_and_clipboard_only(self):
        import json
        extension = ROOT.parents[1] / "tools" / "chatgpt-terminal-paste"
        manifest = json.loads((extension / "manifest.json").read_text(encoding="utf-8"))
        script = (extension / "content.js").read_text(encoding="utf-8")
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["permissions"], ["clipboardRead"])
        self.assertEqual(
            manifest["content_scripts"][0]["matches"],
            ["https://chatgpt.com/*", "https://chat.openai.com/*"],
        )
        self.assertIn('addEventListener("contextmenu"', script)
        self.assertIn('navigator.clipboard.readText()', script)
        self.assertIn('sendButton.click()', script)
        self.assertIn('composerText(editor).trim()', script)
        for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "chrome.storage"):
            self.assertNotIn(forbidden, script)

    def test_terminal_output_clipboard_control_is_available_in_both_chat_modes(self):
        html = (ROOT / "console/static/index.html").read_text(encoding="utf-8")
        app = (ROOT / "console/static/app.js").read_text(encoding="utf-8")
        self.assertIn('id="pasteOutputButton"', html)
        self.assertIn('navigator.clipboard.readText()', app)
        self.assertIn('Вывод из терминала:', app)
        self.assertIn('проверь и нажми Enter', app)
        self.assertIn('ничего не отправляется автоматически', html.lower())

    def test_selection_ask_and_nonblocking_composer_are_present(self):
        ux = (ROOT / "console/static/ux.js").read_text(encoding="utf-8")
        app = (ROOT / "console/static/app.js").read_text(encoding="utf-8")
        self.assertIn("selection-ask", ux)
        self.assertIn("Разбери выделенный фрагмент", ux)
        self.assertNotIn('$("messageInput").disabled=on;', app)
        self.assertIn('if((mode==="collab"&&(state.qwenRunning||state.gptRunning||state.collabRunning))', app)

    @unittest.skipUnless(shutil.which("node"), "Node runtime unavailable")
    def test_new_frontend_scripts_have_valid_syntax(self):
        paths = [
            ROOT / "console/static" / "ux.js",
            ROOT / "console/static" / "model-settings.js",
            ROOT.parents[1] / "tools" / "chatgpt-terminal-paste" / "content.js",
        ]
        for path in paths:
            result = subprocess.run(
                [shutil.which("node"), "--check", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, str(path) + "\\n" + result.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
