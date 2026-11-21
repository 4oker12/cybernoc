"""No-network tests for interactive Chromium controls and request guardrails."""
from pathlib import Path
from unittest.mock import patch
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.browser_control import (
    BROWSER_CONTROL_TOOLS, BROWSER_CONTROL_NAMES, BrowserSession,
    HIGH_IMPACT, _redact_text, _safe_url, validate_public_url,
)


class FakeRequest:
    def __init__(self, url, method="GET"):
        self.url = url
        self.method = method


class FakeRoute:
    def __init__(self, url, method="GET"):
        self.request = FakeRequest(url, method)
        self.continued = False
        self.aborted = False
    def continue_(self):
        self.continued = True
    def abort(self, reason="blockedbyclient"):
        self.aborted = True


class BrowserControlTests(unittest.TestCase):
    def test_tool_catalog_contains_navigation_interaction_and_approval_submit(self):
        names = {item["name"] for item in BROWSER_CONTROL_TOOLS}
        self.assertEqual(names, set(BROWSER_CONTROL_NAMES))
        self.assertTrue({
            "browser_navigate", "browser_snapshot", "browser_follow_link",
            "browser_fill", "browser_select", "browser_click_button",
            "browser_back", "browser_wait", "browser_submit",
            "browser_forward", "browser_reload", "browser_tabs",
            "browser_new_tab", "browser_switch_tab", "browser_close_tab",
            "browser_press", "browser_scroll", "browser_screenshot",
            "browser_console", "browser_network", "browser_find_text",
        }.issubset(names))
        submit = next(x for x in BROWSER_CONTROL_TOOLS if x["name"] == "browser_submit")
        self.assertIn("explicit user approval", submit["description"])

    def test_browser_tools_are_shared_with_the_deepseek_agent(self):
        from console.agent import Agent
        from console.gpt_tool_runtime import GPTToolRuntime
        class Remote:
            def initialize(self):
                return []
            def call(self, name, args):
                return {}, True
        class Model:
            model = "deepseek-test"
            def __init__(self):
                self.tools = []
            def chat(self, messages, tools=None, **kwargs):
                self.tools = tools or []
                return {"content": "done"}
        runtime = GPTToolRuntime()
        model = Model()
        Agent(model, lambda: Remote(), local_tool_runtime=runtime).run(
            [], "Проверь доступные инструменты", force_tools=False,
        )
        deepseek_names = {item["function"]["name"] for item in model.tools}
        gpt_names = {item["name"] for item in runtime.tools}
        for name in ("browser_navigate", "browser_snapshot", "browser_find_text",
                     "browser_follow_link", "browser_tabs", "browser_network"):
            self.assertIn(name, gpt_names)
            self.assertIn(name, deepseek_names)
        self.assertNotIn("browser_submit", gpt_names)
        self.assertNotIn("browser_submit", deepseek_names)


    def test_browser_snapshot_returns_structured_reading_map_without_field_values(self):
        class FakePage:
            url = "https://docs.example.org/guide?session=private"
            def is_closed(self):
                return False
            def evaluate(self, script):
                return {
                    "url": "https://docs.example.org/guide?session=private",
                    "title": "API Documentation",
                    "language": "en",
                    "description": "Installation guide",
                    "canonical": "https://docs.example.org/guide",
                    "page_type": "documentation",
                    "visible_text": "Install the package. Configure the client.",
                    "headings": [{"level": 1, "text": "Installation", "id": "install"}],
                    "landmarks": [{"type": "main", "label": "Main content"}],
                    "links": [{"name": "API reference", "url": "https://docs.example.org/api?token=secret",
                               "kind": "internal", "rel": "", "target": "", "download": False}],
                    "buttons": [{"name": "Search", "type": "button", "disabled": False}],
                    "form_fields": [{"label": "Password", "type": "password", "sensitive": True,
                                     "value": "must-never-appear"}],
                    "tables": [{"caption": "Versions", "headers": ["Version", "Status"],
                               "rows": [["1.0", "Stable"]]}],
                    "search_forms": [{"label": "Search docs", "placeholder": "Search",
                                      "method": "GET", "action": "https://docs.example.org/search"}],
                    "pagination": {"current_page": "1", "next_url": "https://docs.example.org/guide?page=2",
                                   "previous_url": "", "controls": [{"kind": "next", "label": "Next"}]},
                    "focused_element": {"tag": "input", "role": "searchbox", "label": "Search docs",
                                        "type": "search", "sensitive": False},
                    "counts": {"headings": 1, "links": 1, "buttons": 1, "form_fields": 1, "tables": 1},
                    "text_truncated": False
                }
        browser = BrowserSession()
        browser._page = FakePage()
        try:
            result = browser._snapshot()
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["page_type"], "documentation")
        self.assertEqual(result["headings"][0]["text"], "Installation")
        self.assertEqual(result["links"][0]["kind"], "internal")
        self.assertEqual(result["links"][0]["url"], "https://docs.example.org/api")
        self.assertEqual(result["tables"][0]["headers"], ["Version", "Status"])
        self.assertEqual(result["pagination"]["current_page"], "1")
        self.assertNotIn("must-never-appear", str(result))
        self.assertNotIn("token=secret", str(result))

    def test_browser_find_text_returns_bounded_heading_context(self):
        class FakePage:
            url = "https://docs.example.org/guide"
            def is_closed(self):
                return False
            def title(self):
                return "API Documentation"
            def evaluate(self, script, args):
                self.args = args
                return {
                    "matches": [{"heading_context": "Installation", "element": "p",
                                 "role": "", "snippet": "Install the package with pip."}],
                    "total_matches": 1, "scanned_blocks": 12, "scan_limit_reached": False
                }
        browser = BrowserSession()
        browser._page = FakePage()
        try:
            result = browser._dispatch("browser_find_text", {"query": "install", "max_matches": 3})
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["matches"][0]["heading_context"], "Installation")
        self.assertEqual(browser._page.args, {"query": "install", "limit": 3})
        self.assertFalse(result["scan_limit_reached"])

    def test_browser_find_text_rejects_short_queries_and_invalid_limits(self):
        class FakePage:
            url = "https://docs.example.org/"
            def is_closed(self):
                return False
            def title(self):
                return "Docs"
            def evaluate(self, script, args):
                raise AssertionError("evaluate must not run for invalid input")
        browser = BrowserSession()
        browser._page = FakePage()
        try:
            short = browser._dispatch("browser_find_text", {"query": "x"})
            bad_limit = browser._dispatch("browser_find_text", {"query": "install", "max_matches": 99})
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)
        self.assertIn("browser_search_query_invalid", short["error"])
        self.assertIn("browser_search_limit_invalid", bad_limit["error"])

    def test_browser_text_redacts_credentials_and_jwts(self):
        value = "api_key=abc12345 Bearer abcdefghijklmnop eyJabcdefghijk.abcdefghijk.abcdefghijk"
        redacted = _redact_text(value)
        self.assertNotIn("abc12345", redacted)
        self.assertNotIn("abcdefghijklmnop", redacted)
        self.assertNotIn("eyJabcdefghijk", redacted)

    def test_public_https_url_validation_and_query_redaction(self):
        with patch("console.browser_control._resolve_public", return_value=["93.184.215.14"]):
            host, addresses = validate_public_url("https://example.org/article?id=123")
        self.assertEqual(host, "example.org")
        self.assertEqual(addresses, ["93.184.215.14"])
        self.assertEqual(_safe_url("https://example.org/article?id=secret#token"),
                         "https://example.org/article")

    def test_unsafe_url_forms_are_rejected_before_dns(self):
        bad = [
            "http://example.org/",
            "https://user:pass@example.org/",
            "https://example.org:8443/",
            "file:///etc/passwd",
            "https://localhost/",
            "https://127.0.0.1/",
            "https://example.org/\nheader",
        ]
        with patch("console.browser_control._resolve_public") as resolve:
            for url in bad:
                with self.subTest(url=url):
                    with self.assertRaises(ValueError):
                        validate_public_url(url)
            resolve.assert_not_called()

    def test_explicit_user_scope_allows_private_host_and_internal_http(self):
        host, addresses = validate_public_url(
            "http://172.16.0.24:8080/admin", {"172.16.0.24"}
        )
        self.assertEqual(host, "172.16.0.24")
        self.assertEqual(addresses, ["172.16.0.24"])
        with self.assertRaises(ValueError):
            validate_public_url("http://172.16.0.24:8080/admin")
        with self.assertRaises(ValueError):
            validate_public_url(
                "http://169.254.169.254/latest/meta-data",
                {"169.254.169.254"},
            )

    def test_dns_private_or_reserved_address_is_rejected(self):
        rows = [(2, 1, 6, "", ("192.168.1.10", 443))]
        with patch("console.browser_control.socket.getaddrinfo", return_value=rows):
            with self.assertRaisesRegex(ValueError, "private_or_reserved"):
                validate_public_url("https://example.org/")

    def test_browser_route_blocks_private_and_non_https_targets(self):
        browser = BrowserSession()
        try:
            private = FakeRoute("https://127.0.0.1/admin")
            browser._route(private)
            self.assertTrue(private.aborted)
            insecure = FakeRoute("http://example.org/")
            browser._route(insecure)
            self.assertTrue(insecure.aborted)
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_browser_route_requires_one_approved_same_origin_post(self):
        browser = BrowserSession()
        try:
            with patch.object(browser, "_host_is_public", return_value=True):
                denied = FakeRoute("https://example.org/order", "POST")
                browser._route(denied)
                self.assertTrue(denied.aborted)

                browser._allow_post_origin = "https://example.org"
                browser._allow_post_remaining = 1
                allowed = FakeRoute("https://example.org/order", "POST")
                browser._route(allowed)
                self.assertTrue(allowed.continued)
                self.assertEqual(browser._allow_post_remaining, 0)

                second = FakeRoute("https://example.org/confirm", "POST")
                browser._route(second)
                self.assertTrue(second.aborted)

                cross_origin = FakeRoute("https://payments.example.net/pay", "POST")
                browser._allow_post_remaining = 1
                browser._route(cross_origin)
                self.assertTrue(cross_origin.aborted)
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_browser_network_reports_safe_headers_without_sensitive_headers(self):
        browser = BrowserSession()
        try:
            with patch.object(browser, "_ensure"):
                result = browser._dispatch("browser_network", {})
            self.assertFalse(result["request_response_bodies_captured"])
            self.assertFalse(result["sensitive_headers_captured"])
            self.assertTrue(result["safe_response_headers_captured"])
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_browser_controls_include_full_tab_and_diagnostics_surface(self):
        names = {item["name"] for item in BROWSER_CONTROL_TOOLS}
        self.assertTrue({
            "browser_tabs", "browser_new_tab", "browser_switch_tab",
            "browser_close_tab", "browser_forward", "browser_reload",
            "browser_press", "browser_scroll", "browser_console", "browser_network",
        }.issubset(names))

    def test_high_impact_labels_require_manual_user_action(self):
        for label in (
            "Pay now", "Confirm booking", "Оплатить", "Оформить заказ",
            "Delete account", "Unsubscribe", "Cancel service", "Log out",
            "Удалить", "Отключить услугу", "/account/unsubscribe?token=secret",
        ):
            self.assertRegex(label, HIGH_IMPACT)
        for label in ("Search trains", "Find tickets", "Continue reading"):
            self.assertIsNone(HIGH_IMPACT.search(label))


if __name__ == "__main__":
    unittest.main()
