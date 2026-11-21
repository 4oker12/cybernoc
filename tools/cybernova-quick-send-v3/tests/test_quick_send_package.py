import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "extension"

class QuickSendPackageTests(unittest.TestCase):
    def test_manifest_and_scope(self):
        manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertIn("contextMenus", manifest["permissions"])
        self.assertIn("clipboardRead", manifest["permissions"])
        self.assertNotIn("offscreen", manifest["permissions"])
        self.assertIn("http://127.0.0.1/*", manifest["host_permissions"])
        self.assertEqual(set(manifest["host_permissions"]), {
            "https://chatgpt.com/*", "https://chat.openai.com/*", "http://127.0.0.1/*"
        })
        self.assertEqual(set(manifest["content_scripts"][0]["matches"]), {
            "https://chatgpt.com/*", "https://chat.openai.com/*"
        })

    def test_local_port_range_is_enforced_before_injection(self):
        source = (EXT / "service-worker.js").read_text(encoding="utf-8")
        content = (EXT / "content.js").read_text(encoding="utf-8")
        self.assertIn("const LOCAL_PORT_MIN = 18785", source)
        self.assertIn("const LOCAL_PORT_MAX = 18805", source)
        self.assertIn("isAllowedLocalUrl(tab.url)", source)
        self.assertIn("chrome.tabs.onUpdated.addListener", source)
        self.assertIn("MENU_LOCAL_SELECTION", source)
        self.assertIn("localPort >= 18785 && localPort <= 18805", content)
        self.assertIn("http://127.0.0.1/*", (EXT / "manifest.json").read_text(encoding="utf-8"))

    def test_global_selection_and_chatgpt_clipboard_menus(self):
        source = (EXT / "service-worker.js").read_text(encoding="utf-8")
        self.assertIn("contexts: ['selection']", source)
        self.assertIn("contexts: ['editable']", source)
        self.assertIn("documentUrlPatterns", source)

    def test_no_old_bridge_or_socket(self):
        content = "\n".join(p.read_text(encoding="utf-8") for p in EXT.iterdir()
                            if p.is_file() and p.suffix in {".js",".json",".html",".css"}).lower()
        for token in ("vast","18883","18884","websocket","127.0.0.1:18795","chrome.offscreen","offscreen_path"):
            self.assertNotIn(token, content)

    def test_clipboard_read_runs_in_content_script(self):
        source = (EXT / "service-worker.js").read_text(encoding="utf-8")
        content = (EXT / "content.js").read_text(encoding="utf-8")
        self.assertIn("CYBERNOVA_READ_CLIPBOARD_AND_SEND", source)
        self.assertIn("CYBERNOVA_READ_CLIPBOARD_AND_SEND", content)
        self.assertIn("document.hasFocus()", content)
        self.assertIn("navigator.clipboard.readText()", content)
        self.assertNotIn("navigator.clipboard.readText()", source)

    def test_content_script_inserts_and_clicks_send(self):
        source = (EXT / "content.js").read_text(encoding="utf-8")
        self.assertIn("CYBERNOVA_SEND_TEXT", source)
        self.assertIn('button[data-testid="send-button"]', source)
        self.assertIn("sendButton.click()", source)

    @unittest.skipUnless(shutil.which("node"), "Node.js unavailable")
    def test_javascript_syntax(self):
        for name in ("service-worker.js","content.js"):
            result = subprocess.run(["node","--check",str(EXT/name)],
                                    capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)

if __name__ == "__main__":
    unittest.main()
