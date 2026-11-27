"""No-network tests for interactive Chromium controls and request guardrails."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from unittest.mock import Mock, patch
import sys
import unittest
from threading import RLock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.browser_control import (
    BROWSER_CONTROL_TOOLS, BROWSER_CONTROL_NAMES, BrowserSession,
    HIGH_IMPACT, IRREVERSIBLE_SUBMIT_TARGET, PAYMENT_SUBMIT_TARGET,
    _payment_field_kind, _redact_text, _safe_url, validate_public_url,
    _disable_profile_session_restore, _locate_across_frames,
    _browser_field_is_sensitive,
)


class FakeRequest:
    def __init__(self, url, method="GET"):
        self.url = url
        self.method = method


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.disposed = False
    def dispose(self):
        self.disposed = True


class FakeRoute:
    def __init__(self, url, method="GET", status=200, headers=None):
        self.request = FakeRequest(url, method)
        self.continued = False
        self.aborted = False
        self.response = FakeResponse(status, headers)
        self.fetch_args = None
        self.fulfilled = None
    def continue_(self):
        self.continued = True
    def abort(self, reason="blockedbyclient"):
        self.aborted = True
    def fetch(self, **kwargs):
        self.fetch_args = kwargs
        return self.response
    def fulfill(self, **kwargs):
        self.fulfilled = kwargs


class BrowserControlTests(unittest.TestCase):
    def test_default_chromium_is_headless_on_windows_unless_opted_out(self):
        with patch.dict("os.environ", {"CYBERNOVA_GPT_BROWSER_HEADLESS": ""}):
            session = BrowserSession()
            try:
                self.assertFalse(session._headless)
            finally:
                session.close()
        with patch.dict("os.environ", {"CYBERNOVA_GPT_BROWSER_HEADLESS": "1"}):
            session = BrowserSession()
            try:
                self.assertTrue(session._headless)
            finally:
                session.close()
        with patch.dict("os.environ", {}, clear=True):
            session = BrowserSession()
            try:
                self.assertTrue(session._headless)
            finally:
                session.close()

    def test_tool_catalog_contains_navigation_interaction_and_approval_submit(self):
        names = {item["name"] for item in BROWSER_CONTROL_TOOLS}
        self.assertEqual(names, set(BROWSER_CONTROL_NAMES))
        self.assertTrue({
            "browser_navigate", "browser_snapshot", "browser_follow_link",
            "browser_fill", "browser_select", "browser_click_button",
            "browser_read_page", "browser_read_table", "browser_find_controls",
            "browser_set_checked", "browser_register", "browser_login",
            "browser_back", "browser_wait", "browser_submit",
            "browser_forward", "browser_reload", "browser_tabs",
            "browser_new_tab", "browser_switch_tab", "browser_close_tab",
            "browser_press", "browser_scroll", "browser_screenshot",
            "browser_console", "browser_network", "browser_submit_payment",
        }.issubset(names))
        submit = next(x for x in BROWSER_CONTROL_TOOLS if x["name"] == "browser_submit")
        self.assertIn("explicitly requested ordinary POST form", submit["description"])

    def test_payment_submit_tool_is_blocked_without_protected_chat_approval(self):
        session = BrowserSession.__new__(BrowserSession)
        session._closed = False
        session._payment_submit_authorized = False
        session._ensure = lambda: None
        with self.assertRaisesRegex(ValueError, "payment_submit_requires_chat_confirmation"):
            session._dispatch(
                "browser_submit_payment", {"name": "Verify payment method"},
            )

    def test_payment_field_detection_uses_autocomplete_and_accessible_metadata(self):
        self.assertEqual(
            _payment_field_kind({"autocomplete": "cc-number"}), "card_number",
        )
        self.assertEqual(
            _payment_field_kind({"autocomplete": "cc-csc"}), "cvv",
        )
        self.assertEqual(
            _payment_field_kind({"name": "expMonth"}), "expiry_month",
        )
        self.assertEqual(
            _payment_field_kind({"placeholder": "MM/YY"}), "expiry",
        )
        self.assertEqual(
            _payment_field_kind({"labels": "Name on card"}), "cardholder_name",
        )
        self.assertEqual(
            _payment_field_kind({"autocomplete": "cc-postal-code"}),
            "billing_postal_code",
        )
        self.assertEqual(
            _payment_field_kind({"autocomplete": "section-billing address-line1"}),
            "billing_address_line1",
        )
        self.assertEqual(
            _payment_field_kind({"autocomplete": "section-billing address-level2"}),
            "billing_city",
        )
        self.assertEqual(
            _payment_field_kind({"autocomplete": "section-billing address-level1"}),
            "billing_region",
        )
        self.assertEqual(
            _payment_field_kind({"autocomplete": "section-billing country"}),
            "billing_country",
        )
        self.assertTrue(PAYMENT_SUBMIT_TARGET.search("Verify payment method"))
        self.assertFalse(PAYMENT_SUBMIT_TARGET.search("Delete account"))

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
                self.tool_history = []
            def chat(self, messages, tools=None, **kwargs):
                self.tools = tools or []
                self.tool_history.append(self.tools)
                return {"content": "done"}
        runtime = GPTToolRuntime()
        model = Model()
        Agent(model, lambda: Remote(), local_tool_runtime=runtime).run(
            [], "Проверь доступные инструменты", force_tools=False,
        )
        deepseek_names = {item["function"]["name"] for item in model.tool_history[0]}
        self.assertEqual(len(model.tool_history), 1)  # No redundant review pass without tool activity.
        gpt_names = {item["name"] for item in runtime.tools}
        for name in ("browser_navigate", "browser_snapshot", "browser_find_text",
                     "browser_follow_link", "browser_tabs", "browser_network",
                     "browser_read_page", "browser_read_table", "browser_find_controls",
                     "browser_set_checked", "browser_register", "browser_login"):
            self.assertIn(name, gpt_names)
            self.assertIn(name, deepseek_names)
        self.assertIn("browser_submit", gpt_names)
        self.assertIn("browser_submit", deepseek_names)

    def test_registration_targets_are_not_classified_as_irreversible(self):
        for target in ("Sign up", "Register", "Create account", "New account", "Join", "Регистрация", "Создать аккаунт"):
            with self.subTest(target=target):
                self.assertIsNone(IRREVERSIBLE_SUBMIT_TARGET.search(target))
        for target in ("Pay now", "Place order", "Delete account", "Unsubscribe"):
            with self.subTest(target=target):
                self.assertIsNotNone(IRREVERSIBLE_SUBMIT_TARGET.search(target))

    def test_browser_submit_requires_explicit_current_user_intent_and_dispatches_when_requested(self):
        from console.gpt_tool_runtime import GPTToolRuntime
        runtime = GPTToolRuntime()

        denied, failed = runtime._call_impl(
            "browser_submit", {"name": "Send"},
            user_messages=[{"role": "user", "content": "Изучи страницу и проверь поля."}],
            conversation_key="browser-submit-test",
        )
        self.assertTrue(failed)
        self.assertEqual(denied["error"], "browser_submit_requires_explicit_user_intent")

        class FakeSession:
            def set_authorized_hosts(self, hosts):
                self.authorized_hosts = set(hosts or [])

        entry = {"session": FakeSession(), "call_lock": RLock()}
        with (
            patch.object(runtime._browser_pool, "acquire", return_value=("test", entry)),
            patch.object(runtime._browser_pool, "release"),
            patch("console.gpt_tool_runtime.browser_control_call",
                  return_value=({"ok": True, "approved_post_requests_allowed": 1}, False)) as dispatch,
        ):
            result, failed = runtime._call_impl(
                "browser_submit", {"name": "Send"},
                user_messages=[{"role": "user", "content": "Сохрани заполненную форму."}],
                conversation_key="browser-submit-test",
            )
        self.assertFalse(failed)
        self.assertTrue(result["ok"])
        dispatch.assert_called_once_with("browser_submit", {"name": "Send"}, entry["session"])

    def test_persistent_profile_disables_tab_restore_without_deleting_login_data(self):
        with TemporaryDirectory() as temp:
            profile = Path(temp)
            default = profile / "Default"
            default.mkdir()
            preferences = default / "Preferences"
            original = {
                "profile": {"exit_type": "Normal", "name": "Cybernova"},
                "session": {"restore_on_startup": 1, "startup_urls": ["https://example.org"]},
                "intl": {"accept_languages": "ru,en"},
            }
            preferences.write_text(json.dumps(original), encoding="utf-8")
            cookies = default / "Cookies"
            cookies.write_bytes(b"preserve-existing-cookie-database")

            self.assertTrue(_disable_profile_session_restore(profile))
            updated = json.loads(preferences.read_text(encoding="utf-8"))
            backup = json.loads(
                (default / "Preferences.cybernova-backup").read_text(encoding="utf-8")
            )
            self.assertEqual(updated["session"]["restore_on_startup"], 5)
            self.assertEqual(updated["session"]["startup_urls"], ["https://example.org"])
            self.assertEqual(updated["profile"], original["profile"])
            self.assertEqual(updated["intl"], original["intl"])
            self.assertEqual(backup["session"]["restore_on_startup"], 1)
            self.assertEqual(cookies.read_bytes(), b"preserve-existing-cookie-database")
            self.assertFalse(_disable_profile_session_restore(profile))

    def test_ensure_closes_restored_tabs_and_creates_a_fresh_page_after_routes(self):
        class FakePage:
            def __init__(self):
                self.closed = False
                self.handlers = []

            def close(self):
                self.closed = True

            def is_closed(self):
                return self.closed

            def set_default_timeout(self, *_):
                return None

            def on(self, event, callback):
                self.handlers.append((event, callback))

        class FakeContext:
            def __init__(self):
                self.pages = [FakePage(), FakePage()]
                self.events = []

            def route(self, *_):
                self.events.append("route")

            def route_web_socket(self, *_):
                self.events.append("websocket_route")

            def new_page(self):
                self.events.append("new_page")
                page = FakePage()
                self.pages.append(page)
                return page

        context = FakeContext()

        class FakeChromium:
            def launch_persistent_context(self, **_):
                return context

        class FakePlaywright:
            chromium = FakeChromium()

        class FakeManager:
            def start(self):
                return FakePlaywright()

        sync_api = ModuleType("playwright.sync_api")
        sync_api.sync_playwright = lambda: FakeManager()
        playwright = ModuleType("playwright")
        playwright.__path__ = []
        playwright.sync_api = sync_api

        with TemporaryDirectory() as temp:
            profile = Path(temp)
            default = profile / "Default"
            default.mkdir()
            (default / "Preferences").write_text(
                json.dumps({"session": {"restore_on_startup": 5}}),
                encoding="utf-8",
            )
            browser = BrowserSession(headless=True, profile_dir=profile)
            try:
                with patch.dict(sys.modules, {
                    "playwright": playwright,
                    "playwright.sync_api": sync_api,
                }), patch.dict("os.environ", {
                    "CYBERNOVA_GPT_BROWSER_EPHEMERAL": "",
                    "CYBERNOVA_GPT_BROWSER_RESTORE_SESSION": "0",
                    "CYBERNOVA_BROWSER_BACKEND": "playwright",
                }):
                    browser._ensure()
                self.assertTrue(all(page.closed for page in context.pages[:2]))
                self.assertIs(browser._page, context.pages[-1])
                self.assertLess(context.events.index("route"),
                                context.events.index("new_page"))
            finally:
                browser._executor.shutdown(wait=False, cancel_futures=True)

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
            with patch("console.browser_control.validate_public_url", return_value=("forms.example.net", ["8.8.8.8"])):
                denied = FakeRoute("https://example.org/order", "POST")
                browser._route(denied)
                self.assertTrue(denied.aborted)
                self.assertEqual(browser._blocked[-1]["suggested_tool"], "browser_submit")

                # One user-approved POST may go to the exact visible form action origin.
                browser._allow_post_origin = "https://forms.example.net"
                browser._allow_post_remaining = 1
                allowed = FakeRoute("https://forms.example.net/submit", "POST")
                browser._route(allowed)
                self.assertFalse(allowed.continued)
                self.assertIs(allowed.fulfilled["response"], allowed.response)
                self.assertTrue(allowed.response.disposed)
                self.assertEqual(allowed.fetch_args["max_redirects"], 0)
                self.assertEqual(allowed.fetch_args["max_retries"], 0)
                self.assertEqual(browser._post_http_status, 200)
                self.assertEqual(browser._post_outcome, "http_response_observed")
                self.assertEqual(browser._allow_post_remaining, 0)

                second = FakeRoute("https://forms.example.net/confirm", "POST")
                browser._route(second)
                self.assertTrue(second.aborted)

                cross_origin = FakeRoute("https://payments.example.net/pay", "POST")
                browser._allow_post_remaining = 1
                browser._route(cross_origin)
                self.assertTrue(cross_origin.aborted)
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_form_action_rejects_unrelated_post_and_unsafe_redirect(self):
        browser = BrowserSession()
        try:
            with patch("console.browser_control.validate_public_url",
                       return_value=("forms.example.net", ["8.8.8.8"])):
                browser._allow_post_origin = "https://forms.example.net"
                browser._allow_post_url = "https://forms.example.net/submit"
                browser._allow_post_remaining = 1
                unrelated = FakeRoute("https://forms.example.net/other", "POST")
                browser._route(unrelated)
                self.assertTrue(unrelated.aborted)
                self.assertEqual(browser._allow_post_remaining, 1)
                redirect = FakeRoute(browser._allow_post_url, "POST", status=307,
                                     headers={"location": "/again"})
                browser._route(redirect)
                self.assertEqual(redirect.fulfilled["status"], 409)
                self.assertEqual(browser._post_http_status, 307)
                self.assertEqual(browser._post_outcome, "redirect_requires_manual_review")
                self.assertTrue(redirect.response.disposed)
                self.assertEqual(browser._allow_post_remaining, 0)
                browser._allow_post_remaining = 1
                error = FakeRoute(browser._allow_post_url, "POST", status=400)
                browser._route(error)
                self.assertEqual(browser._post_http_status, 400)
                self.assertEqual(browser._post_outcome, "http_error")
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



    def test_browser_fill_tool_schema_exposes_expanded_locator_and_input_options(self):
        fill = next(item for item in BROWSER_CONTROL_TOOLS if item["name"] == "browser_fill")
        properties = fill["inputSchema"]["properties"]
        self.assertTrue({"label", "target", "value", "coords", "clear", "human_like"}.issubset(properties))
        self.assertEqual(
            fill["inputSchema"]["required"],
            ["label", "target", "value", "coords", "clear", "human_like"],
        )

    def test_browser_fill_locator_searches_nested_frames_and_data_agent_id(self):
        class Element:
            def __init__(self, **overrides):
                self.metadata = {
                    "tag": "input", "type": "email", "editable": True,
                    "disabled": False, "read_only": False, "id": "",
                    "name": "email", "placeholder": "", "aria_label": "",
                    "autocomplete": "email", "role": "textbox", "labels": "Email",
                    "data_agent_id": "",
                }
                self.metadata.update(overrides)

        class Locator:
            def __init__(self, elements=None):
                self.elements = list(elements or [])
            def count(self):
                return len(self.elements)
            def nth(self, index):
                return Locator([self.elements[index]])
            def is_visible(self):
                return True
            def is_enabled(self):
                return True
            def evaluate(self, _script):
                return self.elements[0].metadata

        class Frame:
            def __init__(self):
                self.labels = {}
                self.placeholders = {}
                self.roles = {}
                self.selectors = {}
            def get_by_label(self, name, exact=True):
                return self.labels.get((name, exact), Locator())
            def get_by_placeholder(self, name, exact=True):
                return self.placeholders.get((name, exact), Locator())
            def get_by_role(self, role, name=None, exact=True):
                return self.roles.get((role, name, exact), Locator())
            def locator(self, selector):
                return self.selectors.get(selector, Locator())

        main, child = Frame(), Frame()
        page = type("FakePage", (), {})()
        page.main_frame = main
        page.frames = [main, child]
        email = Element()
        child.labels[("Email", True)] = Locator([email])
        found = _locate_across_frames(page, "Email")
        self.assertIs(found.elements[0], email)

        marked = Element(data_agent_id="email-control")
        main.selectors['[data-agent-id="email-control"]'] = Locator([marked])
        found = _locate_across_frames(page, "email-control")
        self.assertIs(found.elements[0], marked)

    def test_browser_fill_locator_accepts_explicit_css_and_rejects_ambiguity(self):
        class Element:
            metadata = {
                "tag": "input", "type": "text", "editable": True,
                "disabled": False, "read_only": False, "id": "email",
                "name": "email", "placeholder": "", "aria_label": "",
                "autocomplete": "", "role": "textbox", "labels": "",
                "data_agent_id": "",
            }
        class Locator:
            def __init__(self, elements=None):
                self.elements = list(elements or [])
            def count(self): return len(self.elements)
            def nth(self, index): return Locator([self.elements[index]])
            def is_visible(self): return True
            def is_enabled(self): return True
            def evaluate(self, _script): return self.elements[0].metadata
        class Frame:
            def __init__(self):
                self.selectors = {}
                self.labels = {}
            def locator(self, selector): return self.selectors.get(selector, Locator())
            def get_by_label(self, name, exact=True): return self.labels.get((name, exact), Locator())
            def get_by_placeholder(self, name, exact=True): return Locator()
            def get_by_role(self, role, name=None, exact=True): return Locator()
        main = Frame()
        page = type("FakePage", (), {"main_frame": main, "frames": [main]})()
        element = Element()
        main.selectors['input[name="email"]'] = Locator([element])
        found = _locate_across_frames(page, 'input[name="email"]')
        self.assertIs(found.elements[0], element)

        first, second = Element(), Element()
        main.labels[("Email", True)] = Locator([first, second])
        with self.assertRaisesRegex(ValueError, "browser_field_not_unique_or_interactable"):
            _locate_across_frames(page, "Email")

    def test_browser_fill_sensitive_fields_remain_in_protected_owner_input_path(self):
        self.assertTrue(_browser_field_is_sensitive({
            "tag": "input", "type": "password", "autocomplete": "current-password",
        }, "Password"))
        self.assertTrue(_browser_field_is_sensitive({
            "tag": "input", "type": "text", "autocomplete": "one-time-code",
        }, "Verification code"))
        self.assertTrue(_browser_field_is_sensitive({
            "tag": "input", "type": "text", "autocomplete": "cc-number",
        }, "Card number"))
        self.assertFalse(_browser_field_is_sensitive({
            "tag": "input", "type": "email", "autocomplete": "email",
        }, "Email address"))

    def test_browser_fill_dispatch_keeps_legacy_label_and_uses_frame_locator(self):
        class Element:
            def __init__(self):
                self.metadata = {
                    "tag": "input", "type": "email", "editable": True,
                    "disabled": False, "read_only": False, "id": "",
                    "name": "email", "placeholder": "", "aria_label": "",
                    "autocomplete": "email", "role": "textbox", "labels": "Email",
                    "data_agent_id": "",
                }
                self.filled = None
        class Locator:
            def __init__(self, elements=None):
                self.elements = list(elements or [])
            def count(self): return len(self.elements)
            def nth(self, index): return Locator([self.elements[index]])
            def is_visible(self): return True
            def is_enabled(self): return True
            def evaluate(self, _script): return self.elements[0].metadata
            def fill(self, value, timeout=None): self.elements[0].filled = value
        class Frame:
            def __init__(self, element):
                self.element = element
            def locator(self, _selector): return Locator()
            def get_by_label(self, name, exact=True):
                return Locator([self.element]) if name == "Email" and exact else Locator()
            def get_by_placeholder(self, _name, exact=True): return Locator()
            def get_by_role(self, _role, name=None, exact=True): return Locator()
        element = Element()
        frame = Frame(element)
        page = type("FakePage", (), {"main_frame": frame, "frames": [frame]})()
        session = BrowserSession(headless=True)
        try:
            session._ensure = lambda: None
            session._page = page
            session._snapshot = lambda: {"ok": True}
            result = session._dispatch("browser_fill", {
                "label": "Email", "value": "operator@example.net", "human_like": False,
            })
            self.assertTrue(result["ok"])
            self.assertEqual(element.filled, "operator@example.net")
        finally:
            session._executor.shutdown(wait=False, cancel_futures=True)


    def test_browser_fill_locator_supports_aria_textbox_controls(self):
        class Element:
            metadata = {
                "tag": "div", "type": "text", "editable": True,
                "content_editable": False, "disabled": False, "read_only": False,
                "id": "custom-email", "name": "", "placeholder": "",
                "aria_label": "Email address", "autocomplete": "",
                "role": "textbox", "labels": "", "data_agent_id": "",
            }
        class Locator:
            def __init__(self, elements=None): self.elements = list(elements or [])
            def count(self): return len(self.elements)
            def nth(self, index): return Locator([self.elements[index]])
            def is_visible(self): return True
            def is_enabled(self): return True
            def evaluate(self, _script): return self.elements[0].metadata
        class Frame:
            def __init__(self): self.roles = {}
            def locator(self, _selector): return Locator()
            def get_by_label(self, _name, exact=True): return Locator()
            def get_by_placeholder(self, _name, exact=True): return Locator()
            def get_by_role(self, role, name=None, exact=True):
                return self.roles.get((role, name, exact), Locator())
        frame = Frame()
        page = type("FakePage", (), {"main_frame": frame, "frames": [frame]})()
        element = Element()
        frame.roles[("textbox", "Email", False)] = Locator([element])
        found = _locate_across_frames(page, "Email")
        self.assertIs(found.elements[0], element)


    def test_browser_fill_supports_guarded_viewport_coordinates(self):
        class Element:
            metadata = {
                "tag": "input", "type": "text", "editable": True,
                "content_editable": False, "disabled": False, "read_only": False,
                "id": "email", "name": "email", "placeholder": "",
                "aria_label": "", "autocomplete": "email", "role": "textbox",
                "labels": "Email", "data_agent_id": "",
            }
        class Locator:
            def __init__(self, element): self.element = element
            def count(self): return 1
            def evaluate(self, _script): return self.element.metadata
        class Keyboard:
            def __init__(self): self.inserted = []
            def insert_text(self, value): self.inserted.append(value)
            def press(self, _key): pass
        class Mouse:
            def __init__(self): self.clicked = None
            def click(self, x, y): self.clicked = (x, y)
        element = Element()
        class Page:
            url = "https://example.net/signup"
            def __init__(self):
                self.keyboard = Keyboard()
                self.mouse = Mouse()
            def evaluate(self, _script, arg=None):
                return {"width": 640, "height": 480} if arg is None else element.metadata
            def locator(self, selector):
                return Locator(element) if selector == ":focus" else type("Empty", (), {"count": lambda self: 0})()
        page = Page()
        session = BrowserSession(headless=True)
        try:
            session._ensure = lambda: None
            session._page = page
            session._snapshot = lambda: {"ok": True}
            result = session._dispatch("browser_fill", {
                "coords": [24, 36], "value": "operator@example.net",
                "clear": False, "human_like": False,
            })
            self.assertTrue(result["ok"])
            self.assertEqual(page.mouse.clicked, (24.0, 36.0))
            self.assertEqual(page.keyboard.inserted, ["operator@example.net"])
        finally:
            session._executor.shutdown(wait=False, cancel_futures=True)

    def test_owner_input_refuses_sensitive_field_in_cross_origin_iframe(self):
        class Element:
            def __init__(self):
                self.metadata = {
                    "tag": "input", "type": "password", "editable": True,
                    "content_editable": False, "disabled": False, "read_only": False,
                    "id": "password", "name": "password", "placeholder": "",
                    "aria_label": "Password", "autocomplete": "current-password",
                    "role": "textbox", "labels": "Password", "data_agent_id": "",
                    "origin": "https://third-party.example",
                }
                self.filled = None
        class Locator:
            def __init__(self, element): self.element = element
            def count(self): return 1
            def nth(self, index): return self
            def is_visible(self): return True
            def is_enabled(self): return True
            def evaluate(self, _script): return self.element.metadata
            def fill(self, value, timeout=None): self.element.filled = value
        class Frame:
            def __init__(self, locator): self.locator_item = locator
            def locator(self, _selector): return type("Empty", (), {"count": lambda self: 0})()
            def get_by_label(self, name, exact=True):
                return self.locator_item if name == "Password" and exact else type("Empty", (), {"count": lambda self: 0})()
            def get_by_placeholder(self, _name, exact=True): return type("Empty", (), {"count": lambda self: 0})()
            def get_by_role(self, _role, name=None, exact=True): return type("Empty", (), {"count": lambda self: 0})()
        element = Element()
        frame = Frame(Locator(element))
        class Page:
            url = "https://accounts.example/signup"
            main_frame = frame
            frames = [frame]
            def evaluate(self, _script): return "https://accounts.example"
        session = BrowserSession(headless=True)
        try:
            session._ensure = lambda: None
            session._page = Page()
            with self.assertRaisesRegex(ValueError, "owner_browser_origin_mismatch"):
                session._fill_owner_input(
                    "Password", "not-a-real-secret", "password",
                    "https://accounts.example",
                )
            self.assertIsNone(element.filled)
        finally:
            session._executor.shutdown(wait=False, cancel_futures=True)

    def test_snapshot_keeps_scrolled_viewport_controls_on_long_pages(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is not installed")
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
            except Exception as exc:
                if "Executable doesn't exist" in str(exc):
                    self.skipTest("Playwright Chromium is not installed")
                raise
            try:
                context = browser.new_context(viewport={"width": 800, "height": 600})
                page = context.new_page()
                links = "".join(
                    f'<a href="https://example.org/{index}" style="display:block;height:40px">'
                    f'Link {index}</a>' for index in range(150)
                )
                page.set_content(links + '<button id="last-action">Last action</button>')
                session = BrowserSession(headless=True)
                try:
                    session._context = context
                    session._page = page
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    snapshot = session._snapshot()
                    self.assertIn("Last action", [item["name"] for item in snapshot["buttons"]])
                    self.assertTrue(next(item for item in snapshot["buttons"]
                                         if item["name"] == "Last action")["in_viewport"])
                    capture = session._dispatch("browser_screenshot", {})
                    self.assertEqual(capture["tab"], snapshot["tab"])
                    self.assertTrue(capture["image_data_url"].startswith("data:image/jpeg;base64,"))
                    self.assertEqual([item["id"] for item in capture["buttons"]], ["last-action"])
                    self.assertTrue(capture["links"])
                    self.assertTrue(all(item["in_viewport"] for item in capture["links"]))

                    page.set_content("""
                        <a id="picture-link" href="https://example.org/guide"><img alt="Guide" width="30" height="30"></a>
                        <iframe srcdoc="<label for='nested'>Nested field</label><input id='nested'>"></iframe>
                        <main><h1>Article</h1><p>Literal sample phrase</p>
                        <table><tr><th>Name</th></tr><tr><td>Example row</td></tr></table></main>
                    """)
                    page.frame_locator("iframe").locator("#nested").wait_for()
                    found = session._dispatch("browser_find_controls", {"query": "Guide"})
                    self.assertEqual(found["links"][0]["name"], "Guide")
                    self.assertEqual(found["links"][0]["id"], "picture-link")
                    nested = session._dispatch("browser_find_controls", {"query": "Nested field"})
                    self.assertEqual(nested["form_fields"][0]["frame_index"], 1)
                    filled = session._dispatch("browser_fill", {"label": "Nested field", "value": "sample"})
                    self.assertTrue(filled["field_verified"])
                    self.assertEqual(page.frame_locator("iframe").locator("#nested").input_value(), "sample")
                    self.assertTrue(session._dispatch("browser_find_text", {
                        "query": "Literal sample phrase", "max_matches": 3})["matches"])
                    self.assertIn("Literal sample phrase", session._dispatch("browser_read_page", {"offset": 0})["text"])
                    self.assertEqual(session._dispatch("browser_read_table", {
                        "frame_index": 0, "table_index": 0, "row_offset": 0})["rows"][-1], ["Example row"])

                    page.set_content("""
                        <div><h2>Plus</h2><input type=radio name=plan aria-label=Plan checked></div>
                        <div><h2>Free</h2><input type=radio name=plan aria-label=Plan></div>
                    """)
                    choices = session._snapshot()["form_fields"]
                    self.assertEqual([(item["choice_context"], item["checked"]) for item in choices],
                                     [("Plus", True), ("Free", False)])
                    result = session._dispatch("browser_set_checked",
                                               {"label": "context:Free", "checked": True})
                    self.assertTrue(result["field_verified"])
                    self.assertEqual([item["checked"] for item in result["form_fields"]],
                                     [False, True])
                    page.locator("h2").first.evaluate("(heading) => heading.textContent = 'Free'")
                    with self.assertRaisesRegex(ValueError, "browser_target_context_not_unique"):
                        session._dispatch("browser_set_checked",
                                          {"label": "context:Free", "checked": True})
                finally:
                    session._executor.shutdown(wait=False, cancel_futures=True)
                    context.close()
            finally:
                browser.close()

    def test_perception_tools_use_closed_required_schemas(self):
        tools = {row["name"]: row["inputSchema"] for row in BROWSER_CONTROL_TOOLS}
        for name in ("browser_find_controls", "browser_read_page", "browser_read_table", "browser_find_text"):
            self.assertIn(name, tools)
            self.assertFalse(tools[name]["additionalProperties"])
            self.assertEqual(set(tools[name]["properties"]), set(tools[name]["required"]))

    def test_targeted_control_discovery_preserves_current_query(self):
        session = BrowserSession()
        self.addCleanup(session._executor.shutdown, wait=False)
        with patch.object(session, "_ensure"), patch.object(
                session, "_snapshot", return_value={"ok": True}) as snapshot:
            self.assertEqual(session._dispatch("browser_find_controls", {"query": "  Search   field "}),
                             {"ok": True})
            snapshot.assert_called_once_with(control_query="Search field")
            with self.assertRaisesRegex(ValueError, "browser_control_query_invalid"):
                session._dispatch("browser_find_controls", {"query": " "})

    def test_frame_target_resolution_rejects_cross_frame_ambiguity(self):
        session = BrowserSession()
        self.addCleanup(session._executor.shutdown, wait=False)
        main, child, second = Mock(), Mock(), Mock()
        session._page = main
        main.main_frame = Mock()
        main.frames = [main.main_frame, child]
        self.assertEqual(session._frame_contexts(), [main, child])
        with patch.object(session, "_unique", side_effect=[None, second]):
            self.assertIs(session._unique_across(lambda frame: frame), second)
        with patch.object(session, "_unique", side_effect=[main, second]):
            with self.assertRaisesRegex(ValueError, "browser_target_not_unique:2"):
                session._unique_across(lambda frame: frame)

    def test_button_search_falls_back_to_exact_visible_text(self):
        session = BrowserSession()
        self.addCleanup(session._executor.shutdown, wait=False)
        session._page = Mock()
        page = session._page
        named_button, all_buttons = Mock(), Mock()
        page.get_by_role.side_effect = [all_buttons, named_button]
        named_button.filter.return_value.count.return_value = 0
        fallback = all_buttons.and_.return_value.filter.return_value
        fallback.count.return_value = 1
        fallback.is_enabled.return_value = True
        self.assertIs(session._one("button", "Continue"), fallback)
        page.get_by_text.assert_called_once_with("Continue", exact=True)

    def test_registration_has_separate_intent_and_destructive_actions_stay_manual(self):
        from console.tool_policy import task_intent_matches
        self.assertIn("browser_register", BROWSER_CONTROL_NAMES)
        self.assertTrue(task_intent_matches("browser_register", "", "Register a test account."))
        self.assertFalse(task_intent_matches("browser_register", "", "Inspect the form."))
        self.assertFalse(task_intent_matches("browser_register", "", "Do not register an account."))
        self.assertTrue(task_intent_matches("browser_login", "", "Log in to the test account."))
        self.assertFalse(task_intent_matches("browser_login", "", "Inspect the login page."))
        for target in (
            "Pay now", "Place order", "Delete account",
        ):
            with self.subTest(target=target):
                self.assertIsNotNone(IRREVERSIBLE_SUBMIT_TARGET.search(target))

if __name__ == "__main__":
    unittest.main()
