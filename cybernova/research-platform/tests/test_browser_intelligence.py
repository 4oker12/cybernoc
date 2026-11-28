import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console.browser_intelligence import (  # noqa: E402
    StrategyTracker, compact_action_result, page_digest, recovery_for,
    response_mode, snapshot_delta, verify_expectations,
)


def snap(text, buttons=(), url="https://example.test/", title="T", fields=()):
    return {"ok": True, "url": url, "title": title, "visible_text": text,
            "buttons": list(buttons), "links": [], "form_fields": list(fields),
            "frame_count": 1, "browser": "x", "page_type": "page"}


class DeltaTests(unittest.TestCase):
    def test_text_control_url_and_state_changes(self):
        a = page_digest(snap("Hello\nOld", [{"name": "Open", "id": "o", "expanded": False}]))
        b = page_digest(snap("Hello\nNew", [{"name": "Open", "id": "o", "expanded": True},
                                             {"name": "Extra"}], url="https://example.test/x"))
        d = snapshot_delta(a, b)
        self.assertTrue(d["changed"])
        self.assertEqual(d["text_added"], ["New"])
        self.assertEqual(d["text_removed"], ["Old"])
        self.assertEqual(d["controls_added"][0]["name"], "Extra")
        self.assertEqual(d["control_state_changed"][0]["was"], {"expanded": False})
        self.assertTrue(d["url_changed"])

    def test_rename_with_stable_id_counts_as_change(self):
        a = page_digest(snap("x", [{"name": "Shadow action", "id": "sb"}]))
        b = page_digest(snap("x", [{"name": "Shadow clicked", "id": "sb"}]))
        self.assertEqual(snapshot_delta(a, b)["controls_renamed"][0]["now"], "Shadow clicked")

    def test_identical_pages_report_no_change(self):
        a = page_digest(snap("same"))
        self.assertFalse(snapshot_delta(a, page_digest(snap("same")))["changed"])

    def test_delta_is_bounded(self):
        a = page_digest(snap(""))
        b = page_digest(snap("\n".join(f"line {i}" for i in range(200))))
        d = snapshot_delta(a, b)
        self.assertEqual(len(d["text_added"]), 8)
        self.assertEqual(d["text_added_count"], 200)


class CompactTests(unittest.TestCase):
    def test_click_is_compacted_and_much_smaller(self):
        big = snap("\n".join(f"row {i}" for i in range(300)),
                   [{"name": f"b{i}"} for i in range(30)])
        before = page_digest(big)
        after = dict(big, visible_text=big["visible_text"] + "\nSaved")
        out, digest = compact_action_result("browser_click_button", after, before)
        self.assertEqual(out["snapshot_mode"], "delta")
        self.assertEqual(out["delta"]["text_added"], ["Saved"])
        self.assertNotIn("visible_text", out)
        self.assertLess(len(json.dumps(out)), len(json.dumps(after)) / 5)
        self.assertEqual(digest["state_id"], page_digest(after)["state_id"])

    def test_no_effect_click_gets_recovery_but_fill_does_not(self):
        s = snap("a")
        click, _ = compact_action_result("browser_click_button", dict(s), page_digest(s))
        self.assertEqual(click["effect"], "none_observed")
        self.assertTrue(click["recovery"])
        fill, _ = compact_action_result("browser_fill", dict(s), page_digest(s))
        self.assertEqual(fill["effect"], "input_applied_value_not_echoed")
        self.assertNotIn("recovery", fill)

    def test_errors_and_baseline_tools_pass_through(self):
        err = {"ok": False, "error": "x"}
        self.assertIs(compact_action_result("browser_click_button", err, None)[0], err)
        full = snap("a")
        self.assertIs(compact_action_result("browser_navigate", full, None)[0], full)

    def test_mode_parsing(self):
        self.assertEqual(response_mode(None), "compact")
        self.assertEqual(response_mode(" FULL "), "full")
        self.assertEqual(response_mode("weird"), "compact")


class VerifyTests(unittest.TestCase):
    def test_checks_return_booleans_only(self):
        s = snap("Order confirmed 42", [{"name": "Done", "id": "d"}], url="https://e.test/thanks")
        r = verify_expectations(s, expect_text=["order CONFIRMED"], absent_text=["Error"],
                                url_contains="/thanks", control="d")
        self.assertTrue(r["verified"], r)
        self.assertNotIn("Order confirmed", json.dumps(r))

    def test_failure_lists_failed_checks(self):
        r = verify_expectations(snap("ok"), expect_text=["missing"], absent_text=["ok"])
        self.assertFalse(r["verified"])
        self.assertEqual(r["failed"], ["text_present", "text_absent"])

    def test_empty_expectations_rejected(self):
        with self.assertRaises(ValueError):
            verify_expectations(snap("x"))
        blank = verify_expectations(snap("x"), expect_text=["  "])
        self.assertFalse(blank["verified"])


class RecoveryTests(unittest.TestCase):
    def test_error_code_mapping(self):
        self.assertIn("id:", recovery_for("ValueError:browser_target_not_unique:3")[0])
        self.assertIn("browser_find_controls", recovery_for("ValueError:browser_target_not_unique:0")[0])
        self.assertTrue(recovery_for("browser_action_timeout"))
        self.assertTrue(recovery_for("something_unknown"))

    def test_escalation_and_reset_and_no_value_retention(self):
        t = StrategyTracker()
        args = {"name": "Buy", "value": "SECRET-123"}
        e = "ValueError:browser_target_not_unique:0"
        self.assertNotIn("escalation", t.record_failure("browser_click_button", args, e))
        self.assertIn("escalation", t.record_failure("browser_click_button", args, e))
        third = t.record_failure("browser_click_button", args, e)
        self.assertTrue(third["change_strategy"])
        self.assertNotIn("SECRET-123", repr(t._recent))
        t.record_success("browser_click_button", args)
        self.assertEqual(t.record_failure("browser_click_button", args, e)["attempts_on_target"], 1)


PAGE = b"""<!doctype html><title>P</title><div id=h></div><script>
document.getElementById('h').attachShadow({mode:'open'}).innerHTML=
'<button id=sb onclick="this.textContent=\\'Shadow clicked\\'">Shadow action</button>';</script>
<div id=items></div><button onclick="more()">Load more</button>
<script>let k=0;function more(){for(let i=0;i<10;i++){k++;const d=document.createElement('div');d.textContent='Item '+k;items.appendChild(d)}}more()</script>
<iframe srcdoc="<p>Inside frame marker</p>"></iframe>"""


class _H(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)


def _chromium_available():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return os.path.exists(p.chromium.executable_path)
    except Exception:
        return False


@unittest.skipUnless(_chromium_available(), "Chromium is not installed")
class LiveBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["CYBERNOVA_GPT_BROWSER_EPHEMERAL"] = "1"
        os.environ["CYBERNOVA_BROWSER_BACKEND"] = "playwright"
        from console.browser_control import BrowserSession, browser_control_call
        cls.call = staticmethod(browser_control_call)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.session = BrowserSession(headless=True)
        cls.session.set_authorized_hosts(["127.0.0.1"])
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        cls.srv.shutdown()

    def test_live_delta_verify_find_text_and_recovery(self):
        c = lambda n, **a: self.call(n, a, self.session)[0]  # noqa: E731
        self.assertTrue(c("browser_navigate", url=self.url)["ok"])
        shadow = c("browser_click_button", name="id:sb")
        self.assertEqual(shadow["delta"]["controls_renamed"][0]["now"], "Shadow clicked")
        more = c("browser_click_button", name="Load more")
        self.assertEqual(more["effect"], "observed")
        self.assertNotIn("visible_text", more)
        found = c("browser_find_text", query="Item 20", max_matches=2)
        self.assertEqual(found["status"], "success")
        framed = c("browser_find_text", query="Inside frame marker", max_matches=2)
        self.assertEqual(framed["matches"][0]["frame_index"], 1)
        ok = c("browser_verify", expect_text=["Item 20"], absent_text=["Error"],
               url_contains=None, control=None)
        self.assertTrue(ok["verified"])
        bad = None
        for _ in range(3):
            bad = c("browser_click_button", name="No such button")
        self.assertFalse(bad["ok"])
        self.assertTrue(bad["change_strategy"])


if __name__ == "__main__":
    unittest.main()
