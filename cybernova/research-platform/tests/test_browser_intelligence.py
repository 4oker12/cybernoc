import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console.browser_intelligence import (  # noqa: E402
    StrategyTracker, ObservationMemory, compact_action_result, page_digest, recovery_for,
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

    def test_frame_focus_and_partial_state(self):
        a = dict(snap("same", [{"name": "Search", "ref": "e1",
                                "spatial": {"focused": False}}]), tab=0)
        b = dict(snap("same", [{"name": "Search", "ref": "e1",
                                "spatial": {"focused": True}}]), tab=0, frame_count=2)
        delta = snapshot_delta(page_digest(a), page_digest(b))
        self.assertTrue(delta["changed"])
        self.assertEqual(delta["frame_count_changed"], {"was": 1, "now": 2})
        self.assertTrue(delta["control_state_changed"][0]["state"]["focused"])
        partial = dict(a, controls_truncated=True)
        out, _ = compact_action_result("browser_click_button", partial, page_digest(partial))
        self.assertIsNone(out["delta"]["changed"])
        self.assertEqual(out["effect"], "unverified_partial_observation")

    def test_different_tab_never_compares_unrelated_controls(self):
        a = page_digest(dict(snap("one"), tab=0))
        b = page_digest(dict(snap("two"), tab=1))
        d = snapshot_delta(a, b)
        self.assertFalse(d["baseline"])
        self.assertIsNone(d["changed"])

    def test_partial_slices_do_not_confirm_an_action_effect(self):
        before = dict(snap("One", [{"name": "First", "ref": "e1"}]),
                      controls_truncated=True, text_truncated=True)
        after = dict(before, visible_text="Two", buttons=[{"name": "Second", "ref": "e2"}])
        result, _ = compact_action_result("browser_click_button", after, page_digest(before))
        self.assertEqual(result["effect"], "unverified_partial_observation")
        self.assertEqual(result["delta"]["controls_added_count"], 1)
        self.assertEqual(result["delta"]["text_added_count"], 1)

    def test_matching_complete_text_scopes_can_confirm_visible_change(self):
        before = dict(snap("One"), text_coverage={"complete": False, "collected_scopes": ["main"]})
        after = dict(before, visible_text="Two")
        self.assertTrue(snapshot_delta(page_digest(before), page_digest(after))["changed"])
        after["text_coverage"] = {"complete": False, "collected_scopes": ["body"]}
        self.assertIsNone(snapshot_delta(page_digest(before), page_digest(after))["changed"])

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

    def test_missing_baseline_does_not_claim_effect(self):
        out, _ = compact_action_result("browser_click_button", snap("new"), None)
        self.assertEqual(out["effect"], "unverified_no_baseline")
        self.assertIsNone(out["delta"]["changed"])

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

    def test_partial_coverage_never_proves_absence(self):
        s = dict(snap("visible"), text_truncated=True, controls_truncated=True)
        r = verify_expectations(s, expect_text=["visible"], absent_text=["hidden"], control="missing")
        self.assertFalse(r["verified"])
        self.assertEqual(r["unknown"], ["text_absent", "control_present"])
        self.assertEqual(r["failed"], [])

    def test_paginated_control_checks_and_exact_typed_identifiers(self):
        snapshot = dict(snap("", [{"name": "Unlabelled"},
                                  {"name": "Panel", "id": "Panel", "ref": "e2"}]), control_offset=2)
        self.assertFalse(page_digest(snapshot)["coverage"]["controls_complete"])
        for target in ("id:", "ref:", " "):
            self.assertEqual(verify_expectations(snapshot, control=target)["failed"], ["control_present"])
        for target in ("id:panel", "ref:E2", "missing"):
            self.assertEqual(verify_expectations(snapshot, control=target)["unknown"], ["control_present"])
        for target in ("id:Panel", "ref:e2"):
            self.assertTrue(verify_expectations(snapshot, control=target)["verified"])

    def test_empty_expectations_rejected(self):
        with self.assertRaises(ValueError):
            verify_expectations(snap("x"))
        blank = verify_expectations(snap("x"), expect_text=["  "])
        self.assertFalse(blank["verified"])


class ObservationMemoryTests(unittest.TestCase):
    def test_reobserve_structure_without_retaining_page_text(self):
        mem = ObservationMemory(window=2, max_refs=2)
        first = dict(snap("private text", [{"name": "secret label", "ref": "e1",
                                           "expanded": False}]), tab=0)
        a = mem.observe(first, "browser_snapshot")
        self.assertEqual(a["current_refs"], 1)
        second = dict(snap("private text", [{"name": "secret label", "ref": "e1",
                                            "expanded": True}]), tab=0)
        b = mem.observe(second, "browser_snapshot")
        self.assertEqual(b["reobserved_refs"], ["e1"])
        self.assertEqual(b["changed_refs"], ["e1"])
        self.assertNotIn("secret label", repr(mem._refs))
        self.assertNotIn("private text", repr(mem._history))
        mem.invalidate()
        c = mem.observe(second, "browser_snapshot")
        self.assertEqual(c["reobserved_refs"], [])
        self.assertEqual(len(c["recent"]), 2)
        self.assertGreater(c["generation"], b["generation"])

    def test_tab_change_invalidates_known_refs(self):
        mem = ObservationMemory()
        s = snap("a", [{"name": "A", "ref": "e1"}])
        mem.observe(dict(s, tab=0), "browser_snapshot")
        result = mem.observe(dict(s, tab=1), "browser_snapshot")
        self.assertEqual(result["reobserved_refs"], [])


class RecoveryTests(unittest.TestCase):
    def test_error_code_mapping(self):
        self.assertIn("id:", recovery_for("ValueError:browser_target_not_unique:3")[0])
        self.assertIn("browser_find_controls", recovery_for("ValueError:browser_target_not_unique:0")[0])
        self.assertTrue(recovery_for("browser_action_timeout"))
        self.assertTrue(recovery_for("something_unknown"))

    def test_repeated_no_effect_requires_strategy_change_on_same_state(self):
        tracker = StrategyTracker()
        args = {"name": "Open", "value": "never retain"}
        first = tracker.record_no_effect("browser_click_button", args, "state1")
        self.assertNotIn("change_strategy", first)
        second = tracker.record_no_effect("browser_click_button", args, "state1")
        self.assertTrue(second["change_strategy"])
        self.assertEqual(tracker.record_no_effect("browser_click_button", args, "state2")["attempts_on_state"], 1)
        tracker.record_success("browser_click_button", args)
        self.assertEqual(tracker.record_no_effect("browser_click_button", args, "state1")["attempts_on_state"], 1)
        self.assertNotIn("never retain", repr(tracker._no_effect))

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
<iframe srcdoc="<p>Inside frame marker</p><button id='frame-action'>Frame button<svg aria-hidden='true' width='18' height='18'><title>Frame symbol</title><circle cx='9' cy='9' r='4'/></svg></button><svg role='img' aria-label='Frame diagram' width='32' height='32'><rect width='30' height='30'/></svg>"></iframe>"""


CARD_PAGE = b"""<!doctype html><title>Cards</title><main>
<div style="display:flex;gap:20px">
  <div><h2>Alpha</h2><p>First item</p><button hidden>Placeholder</button><button>Details</button></div>
  <div><h2>Beta</h2><p>Second item</p><button hidden>Placeholder</button><button aria-describedby="editor">Details<svg aria-hidden="true" width="18" height="18"><circle cx="9" cy="9" r="5"/></svg></button></div>
</div>
<div style="border:1px solid #555;padding:12px;max-width:280px">
 <h2>Unique card</h2><p>Single content group</p><button>Details</button>
</div><div role="textbox"><span id="editor">Editable fixture text</span></div></main>"""


WIDGET_PAGE = b"""<!doctype html><title>Widgets</title>
<div role="listbox" aria-label="Choices" tabindex="0" aria-activedescendant="first"
 onkeydown="if(event.key==='ArrowDown'){this.setAttribute('aria-activedescendant','second');event.preventDefault()}">
 <div role="option" id="first">First</div><div role="option" id="second">Second</div>
</div>
<div role="menuitem" tabindex="0" onclick="document.getElementById('out').textContent='Item opened'">Open item</div>
<div id="out">Nothing opened</div><span tabindex="0">Custom focusable text</span>"""


class _H(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        body = {"/cards": CARD_PAGE, "/widgets": WIDGET_PAGE}.get(self.path, PAGE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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

    def test_live_complex_widget_navigation_and_activation(self):
        c = lambda n, **a: self.call(n, a, self.session)[0]
        self.assertTrue(c("browser_navigate", url=self.url + "widgets")["ok"])
        found = c("browser_find_controls", query="Choices")
        widget = next(row for row in found["buttons"] if row["type"] == "listbox")
        result = c("browser_click_button", name="key:ArrowDown:ref:" + widget["ref"])
        self.assertTrue(result.get("widget_state_changed"), result)
        self.assertEqual(result["widget_state_after"]["active_descendant"], "second")
        found = c("browser_find_controls", query="Open item")
        item = next(row for row in found["buttons"] if row["type"] == "menuitem")
        self.assertTrue(c("browser_click_button", name="activate:ref:" + item["ref"])["ok"])
        self.assertTrue(c("browser_verify", expect_text=["Item opened"])["verified"])
        found = c("browser_find_controls", query="Custom focusable text")
        custom = next(row for row in found["buttons"] if row["type"] == "focus_candidate")
        self.assertTrue(c("browser_click_button", name="focus:ref:" + custom["ref"])["focus_verified"])

    def test_live_ax_shadow_and_frame_correlation(self):
        c = lambda n, **a: self.call(n, a, self.session)[0]
        self.assertTrue(c("browser_navigate", url=self.url)["ok"])
        for name in ("Shadow action", "Frame button"):
            result = c("browser_find_controls", query=name)
            row = next(row for row in result["buttons"] if row["name"] == name)
            self.assertEqual(row.get("accessibility", {}).get("role"), "button", result)
            self.assertIn("top_bounds", row["spatial"])
        capture = c("browser_screenshot")
        self.assertTrue(capture["ok"])
        frame = next(row for row in capture["buttons"] if row["name"] == "Frame button")
        self.assertTrue(frame["spatial"]["top_viewport_intersection"])
        icon_search = c("browser_find_controls", query="Frame symbol")
        icon = next(row for row in icon_search["visual_objects"] if row["kind"] == "icon")
        owner = next(row for row in icon_search["buttons"] if row["name"] == "Frame button")
        self.assertEqual(icon["owner_ref"], owner["ref"])
        self.assertTrue(icon["visual_ref"].startswith("v"))
        self.assertIn("top_bounds", icon["spatial"])
        diagram = next(row for row in capture["visual_objects"] if row.get("label") == "Frame diagram")
        self.assertEqual(diagram["frame_index"], 1)
        self.assertIn("top_bounds", diagram["spatial"])

    def test_live_inferred_card_disambiguates_equal_controls(self):
        c = lambda n, **a: self.call(n, a, self.session)[0]
        self.assertTrue(c("browser_navigate", url=self.url + "cards")["ok"])
        result = c("browser_find_controls", query="Beta")
        buttons = [row for row in result["buttons"] if row["name"] == "Details"]
        self.assertEqual(len(buttons), 1, result)
        groups = buttons[0]["semantic"]["groups"]
        card = next(group for group in groups if group["kind"] == "card_candidate")
        self.assertEqual(card["label"], "Beta")
        self.assertTrue(card["inferred"])
        self.assertEqual(card["ordinal"], 2)
        self.assertNotIn("description", buttons[0]["semantic"])
        self.assertNotIn("Editable fixture text", repr(result))
        icon = next(row for row in result["visual_objects"] if row["kind"] == "icon")
        self.assertEqual(icon["owner_ref"], buttons[0]["ref"])
        self.assertTrue(icon["decorative"])
        single = c("browser_find_controls", query="Unique card")
        detail = next(row for row in single["buttons"] if row["name"] == "Details")
        candidate = next(group for group in detail["semantic"]["groups"] if group["kind"] == "card_candidate")
        self.assertIn("distinct_visual_boundary", candidate["evidence"])
        self.assertNotIn("ordinal", candidate)

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
        ok = c("browser_verify", expect_text=["Item 20"], absent_text=None,
               url_contains=None, control=None)
        self.assertTrue(ok["verified"])
        compact = c("browser_snapshot", mode="compact")
        self.assertTrue(compact["visible_text_preview"])
        refs = [row["ref"] for row in compact["buttons"]]
        self.assertEqual(len(refs), len(set(refs)))
        frame_button = next(row for row in compact["buttons"] if row["name"] == "Frame button")
        searched = c("browser_find_controls", query="Frame button")
        self.assertEqual(searched["buttons"][0]["ref"], frame_button["ref"])
        clicked = c("browser_click_button", name="ref:" + frame_button["ref"])
        self.assertTrue(clicked["ok"], clicked)
        self.assertIn("action_id", clicked)
        bad = None
        for _ in range(3):
            bad = c("browser_click_button", name="No such button")
        self.assertFalse(bad["ok"])
        self.assertTrue(bad["change_strategy"])


if __name__ == "__main__":
    unittest.main()
