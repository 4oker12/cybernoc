"""No-network tests for interactive Chromium controls and request guardrails."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch
import sys
import threading
import time
import unittest
from threading import RLock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.browser_control import (
    BROWSER_CONTROL_TOOLS, BROWSER_CONTROL_NAMES, BrowserSession,
    HIGH_IMPACT, IRREVERSIBLE_SUBMIT_TARGET, PAYMENT_SUBMIT_TARGET,
    _payment_field_kind, _redact_text, _safe_url, validate_public_url,
    _disable_profile_session_restore, _locate_across_frames,
    _browser_field_is_sensitive, _classify_page_type,
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


class FakeWebSocket:
    def __init__(self, url):
        self.url = url
        self.connected = False
        self.closed = None
    def connect_to_server(self):
        self.connected = True
    def close(self, **kwargs):
        self.closed = kwargs


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
            "browser_console", "browser_network_session", "browser_submit_payment",
        }.issubset(names))
        submit = next(x for x in BROWSER_CONTROL_TOOLS if x["name"] == "browser_submit")
        self.assertIn("approve the exact method and target", submit["description"])
        self.assertIn("Supports the form's declared HTTP method", submit["description"])
        follow = next(x for x in BROWSER_CONTROL_TOOLS if x["name"] == "browser_follow_link")
        self.assertIn("url:<URL>", follow["description"])

    def test_websocket_policy_allows_public_wss_and_scoped_internal_ws_only(self):
        session = BrowserSession.__new__(BrowserSession)
        session._authorized_hosts = set()
        session._blocked = []

        public = FakeWebSocket("wss://example.test/socket")
        with patch("console.browser_control.validate_public_url",
                   return_value=("example.test", ["93.184.216.34"])) as validate:
            session._route_web_socket(public)
        validate.assert_called_once_with("https://example.test/socket", set())
        self.assertTrue(public.connected)
        self.assertIsNone(public.closed)

        insecure_public = FakeWebSocket("ws://example.test/socket")
        with patch("console.browser_control.validate_public_url") as validate:
            session._route_web_socket(insecure_public)
        validate.assert_not_called()
        self.assertFalse(insecure_public.connected)
        self.assertEqual(insecure_public.closed["code"], 1008)
        self.assertEqual(session._blocked[-1]["reason"], "websocket_target_not_allowed")

        private_wss = FakeWebSocket("wss://192.168.1.10/socket")
        session._route_web_socket(private_wss)
        self.assertFalse(private_wss.connected)
        self.assertEqual(private_wss.closed["code"], 1008)

        session._authorized_hosts = {"router.local"}
        scoped_internal = FakeWebSocket("ws://router.local:8080/events")
        with patch("console.browser_control.validate_public_url",
                   return_value=("router.local", ["192.0.2.10"])) as validate:
            session._route_web_socket(scoped_internal)
        validate.assert_called_once_with(
            "http://router.local:8080/events", {"router.local"},
        )
        self.assertTrue(scoped_internal.connected)

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
                     "browser_follow_link", "browser_tabs", "browser_network_session",
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

    def test_browser_submit_uses_in_chat_confirmation_without_requiring_repeated_intent(self):
        from console.gpt_tool_runtime import GPTToolRuntime
        from console.owner_input import OwnerInputBroker

        runtime = GPTToolRuntime()
        broker = OwnerInputBroker()
        session_id = "deepseek:" + "p" * 32

        class FakeSession:
            def set_authorized_hosts(self, hosts):
                self.authorized_hosts = set(hosts or [])
            def set_write_approval_handler(self, handler):
                self.write_approval_handler = handler

        entry = {"session": FakeSession(), "call_lock": RLock()}
        outcome = {}
        def dispatch(name, args, session):
            details = {
                "method": "POST", "url": "https://example.test/save",
                "request_label": "POST https://example.test/save",
                "resource_type": "form", "action_label": args["name"],
                "page_origin": "https://example.test",
                "target_origin": "https://example.test",
            }
            return {"ok": session.write_approval_handler(details)}, False

        def run_call():
            outcome["value"] = runtime._call_impl(
                "browser_submit", {"name": "Send"},
                user_messages=[{"role": "user", "content": "Изучи страницу и проверь поля."}],
                conversation_key=session_id,
            )

        with (
            patch.object(runtime._browser_pool, "acquire", return_value=("test", entry)),
            patch.object(runtime._browser_pool, "release"),
            patch("console.gpt_tool_runtime.owner_input_broker", broker),
            patch("console.gpt_tool_runtime.browser_control_call", side_effect=dispatch),
        ):
            worker = threading.Thread(target=run_call)
            worker.start()
            deadline = time.monotonic() + 2
            pending = None
            while time.monotonic() < deadline and pending is None:
                pending = broker.pending(session_id)
                time.sleep(0.01)
            self.assertIsNotNone(pending)
            self.assertEqual(pending["input_type"], "browser_action_confirmation")
            broker.submit(session_id, pending["request_id"], decision=True)
            worker.join(3)
        self.assertFalse(worker.is_alive())
        result, failed = outcome["value"]
        self.assertFalse(failed)
        self.assertTrue(result["ok"])

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
                self.websocket_handler = None

            def route(self, *_):
                self.events.append("route")

            def route_web_socket(self, _pattern, handler):
                self.events.append("websocket_route")
                self.websocket_handler = handler

            def new_page(self):
                self.events.append("new_page")
                page = FakePage()
                self.pages.append(page)
                return page

        context = FakeContext()

        class FakeChromium:
            def __init__(self):
                self.launch_options = None

            def launch_persistent_context(self, **options):
                self.launch_options = options
                return context

        fake_chromium = FakeChromium()

        class FakePlaywright:
            chromium = fake_chromium

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
                self.assertEqual(fake_chromium.launch_options["service_workers"], "allow")
                self.assertTrue(fake_chromium.launch_options["no_viewport"])
                self.assertNotIn("viewport", fake_chromium.launch_options)
                self.assertLess(context.events.index("route"),
                                context.events.index("websocket_route"))
                self.assertLess(context.events.index("websocket_route"),
                                context.events.index("new_page"))
                self.assertTrue(callable(context.websocket_handler))
            finally:
                browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_service_worker_network_fetch_remains_routed(self):
        api_hits = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    body = b"""<!doctype html><script>
                    (async () => {
                      if (!navigator.serviceWorker.controller) {
                        await navigator.serviceWorker.register('/sw.js');
                        await navigator.serviceWorker.ready;
                        location.reload();
                        return;
                      }
                      const response = await fetch('/api/data');
                      window.__swResult = await response.text();
                    })().catch(error => { window.__swError = String(error); });
                    </script>"""
                    content_type = "text/html"
                elif self.path == "/sw.js":
                    body = b"""self.addEventListener('fetch', event => {
                      if (new URL(event.request.url).pathname === '/api/data')
                        event.respondWith(fetch(event.request));
                    });"""
                    content_type = "application/javascript"
                elif self.path == "/api/data":
                    api_hits.append(self.path)
                    body = b"service-worker-network-ok"
                    content_type = "text/plain"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        browser = BrowserSession(headless=True)
        routed_worker_fetches = []
        original_route = browser._route

        def observe_route(route):
            if route.request.url.endswith("/api/data"):
                routed_worker_fetches.append(route.request.url)
            return original_route(route)

        browser._route = observe_route
        browser._authorized_hosts = {"127.0.0.1"}
        try:
            with patch.dict("os.environ", {
                "CYBERNOVA_GPT_BROWSER_EPHEMERAL": "1",
                "CYBERNOVA_GPT_BROWSER_HEADLESS": "1",
                "CYBERNOVA_BROWSER_BACKEND": "patchright",
            }):
                try:
                    browser._ensure()
                except ValueError as exc:
                    if "chromium_not_installed" in str(exc):
                        self.skipTest("Patchright/Playwright Chromium is not installed")
                    raise
            browser._page.goto(
                "http://127.0.0.1:%s/" % server.server_address[1],
                wait_until="load",
            )
            browser._page.wait_for_function(
                "() => window.__swResult === 'service-worker-network-ok'",
                timeout=15000,
            )
            self.assertEqual(browser._page.evaluate("window.__swResult"),
                             "service-worker-network-ok")
            self.assertTrue(api_hits)
            self.assertTrue(routed_worker_fetches)
        finally:
            browser.close()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

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

    def test_browser_route_requires_one_approved_same_origin_write(self):
        browser = BrowserSession()
        try:
            with patch("console.browser_control.validate_public_url", return_value=("forms.example.net", ["8.8.8.8"])):
                denied = FakeRoute("https://example.org/order", "POST")
                browser._route(denied)
                self.assertTrue(denied.aborted)
                self.assertEqual(browser._blocked[-1]["reason"], "write_request_requires_owner_confirmation")

                # One owner-approved write may go to the exact visible form action origin.
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

    def test_browser_route_requires_chat_confirmation_for_each_unsafe_method(self):
        browser = BrowserSession()
        approved = []
        browser._active_action = {"tool": "browser_click_button", "label": "Save settings"}
        browser.set_write_approval_handler(lambda details: approved.append(details) or True)
        try:
            with patch("console.browser_control.validate_public_url",
                       return_value=("example.test", ["8.8.8.8"])):
                for method in ("POST", "PUT", "PATCH", "DELETE"):
                    route = FakeRoute("https://example.test/api/settings", method)
                    browser._route(route)
                    self.assertFalse(route.aborted)
                    self.assertIs(route.fulfilled["response"], route.response)
                self.assertEqual([item["method"] for item in approved],
                                 ["POST", "PUT", "PATCH", "DELETE"])
                self.assertTrue(all(item["action_label"] == "Save settings" for item in approved))
                self.assertEqual(browser._allowed_request_count, 4)

                browser.set_write_approval_handler(lambda _details: False)
                denied = FakeRoute("https://example.test/api/settings", "DELETE")
                browser._route(denied)
                self.assertTrue(denied.aborted)
                self.assertEqual(browser._blocked[-1]["reason"], "owner_declined_or_expired")

                browser._active_action = None
                background_approvals = []
                browser.set_write_approval_handler(
                    lambda details: background_approvals.append(details) or True
                )
                background = FakeRoute("https://example.test/api/settings", "POST")
                browser._route(background)
                self.assertFalse(background.aborted)
                self.assertEqual(len(background_approvals), 1)
                self.assertEqual(background_approvals[0]["action_label"],
                                 "background page request")

                browser.set_write_approval_handler(lambda _details: False)
                declined_background = FakeRoute(
                    "https://example.test/api/settings", "POST"
                )
                browser._route(declined_background)
                self.assertTrue(declined_background.aborted)
                self.assertEqual(browser._blocked[-1]["reason"],
                                 "owner_declined_or_expired")

                safe = FakeRoute("https://example.test/api/settings", "GET")
                browser._route(safe)
                self.assertTrue(safe.continued)
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
                result = browser._dispatch("browser_network_session", {})
            self.assertFalse(result["request_response_bodies_captured"])
            self.assertFalse(result["sensitive_headers_captured"])
            self.assertTrue(result["safe_response_headers_captured"])
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_network_request_is_visible_while_response_is_delayed(self):
        browser = BrowserSession()
        try:
            request = SimpleNamespace(
                url="https://example.test/api/data?access_token=private-value",
                method="GET", resource_type="fetch",
            )
            browser._on_request(request)
            with patch.object(browser, "_ensure"):
                result = browser._dispatch("browser_network_session", {})
            self.assertEqual(len(result["events"]), 1)
            event = result["events"][0]
            self.assertEqual(event["state"], "pending")
            self.assertEqual(event["state_history"], ["started", "pending"])
            self.assertEqual(event["url"], "https://example.test/api/data")
            self.assertNotIn("private-value", str(result))
            self.assertNotIn("path-secret", _safe_url(
                "https://example.test/password=path-secret?access_token=private-value"
            ))
            self.assertEqual(event["session_id"], browser._network_session_id)
            self.assertTrue(event["request_id"])
            self.assertLessEqual(event["timestamp_started"], event["timestamp_updated"])
            self.assertIn(id(request), browser._request_started)

            response = SimpleNamespace(
                request=request, url=request.url, status=200, ok=True,
                headers={"content-type": "application/json",
                         "set-cookie": "session=secret"},
            )
            browser._on_response(response)
            self.assertIs(result["events"][0], event)
            self.assertEqual(event["state"], "response_received")
            self.assertEqual(event["status"], 200)
            self.assertEqual(event["safe_response_headers"],
                             {"content-type": "application/json"})
            browser._on_request_finished(request)
            self.assertEqual(event["state"], "completed")
            self.assertEqual(event["state_history"],
                             ["started", "pending", "response_received", "completed"])
            self.assertNotIn(id(request), browser._request_started)
            self.assertEqual(len(browser._network_events), 1)
            self.assertNotIn("session=secret", str(event))
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_network_http_error_completes_and_transport_failures_are_classified(self):
        browser = BrowserSession()
        try:
            http_error = SimpleNamespace(url="https://example.test/missing",
                                         method="GET", resource_type="fetch")
            browser._on_request(http_error)
            browser._on_response(SimpleNamespace(
                request=http_error, url=http_error.url, status=503,
                ok=False, headers={},
            ))
            browser._on_request_finished(http_error)
            self.assertEqual(browser._network_events[-1]["state"], "completed")
            self.assertEqual(browser._network_events[-1]["status"], 503)
            self.assertFalse(browser._network_events[-1]["ok"])

            cases = (
                ("net::ERR_BLOCKED_BY_CLIENT", "blocked", "blocked_by_client"),
                ("net::ERR_ABORTED", "cancelled", "request_aborted"),
                ("net::ERR_TIMED_OUT", "timed_out", "network_timeout"),
                ("net::ERR_CONNECTION_RESET password=private-value",
                 "failed", "request_failed"),
            )
            for failure, state, safe_reason in cases:
                with self.subTest(state=state):
                    request = SimpleNamespace(
                        url="https://example.test/api?secret=private-value",
                        method="GET", resource_type="fetch", failure=failure,
                    )
                    browser._on_request(request)
                    browser._on_request_failed(request)
                    event = browser._network_events[-1]
                    self.assertEqual(event["state"], state)
                    self.assertEqual(event["state_history"],
                                     ["started", "pending", state])
                    self.assertEqual(event["failure"], safe_reason)
                    self.assertNotIn("private-value", str(event))
                    self.assertNotIn(id(request), browser._request_started)
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_browser_controls_include_full_tab_and_diagnostics_surface(self):
        names = {item["name"] for item in BROWSER_CONTROL_TOOLS}
        self.assertTrue({
            "browser_tabs", "browser_new_tab", "browser_switch_tab",
            "browser_close_tab", "browser_forward", "browser_reload",
            "browser_press", "browser_scroll", "browser_console", "browser_network_session",
        }.issubset(names))

    def test_find_text_zero_scan_does_not_claim_absence(self):
        browser = BrowserSession()
        try:
            browser._page = SimpleNamespace(
                url="https://example.test/", title=lambda: "Test",
                frames=[object(), object()],
            )
            browser._find_text = lambda *_: {"matches": [], "scanned_blocks": 0,
                                             "candidate_blocks": 0, "root_scope": "body"}
            with patch.object(browser, "_ensure"):
                result = browser._dispatch("browser_find_text", {"query": "missing",
                                                                 "max_matches": 3})
            self.assertEqual(result["status"], "not_covered")
            self.assertFalse(result["coverage"]["complete"])
            self.assertEqual(result["coverage"]["frames_skipped"], 1)
            self.assertIn("no_visible_text_blocks", result["coverage"]["skip_reasons"])
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

    def test_console_degradation_and_network_window_report_coverage(self):
        browser = BrowserSession()
        try:
            browser._backend = "patchright"
            browser._console_events = []
            with patch.object(browser, "_ensure"):
                console = browser._dispatch("browser_console", {})
                self.assertEqual(console["status"], "partial")
                self.assertTrue(console["degraded"])
                self.assertFalse(console["console_api_available"])
                self.assertTrue(console["pageerror_available"])
                self.assertFalse(console["coverage"]["complete"])

                browser._network_events = [{"state": "completed"} for _ in range(65)]
                browser._network_total_observed = 68
                network = browser._dispatch("browser_network_session", {})
            self.assertEqual(network["status"], "truncated")
            # Returned window is intentionally capped for token efficiency.
            returned = len(network["events"])
            self.assertLessEqual(returned, 30)
            self.assertEqual(network["coverage"]["omitted_events"], 65 - returned)
            self.assertEqual(network["coverage"]["dropped_events"], 3)
            self.assertFalse(network["coverage"]["complete"])
        finally:
            browser._executor.shutdown(wait=False, cancel_futures=True)

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

    def test_chromium_browser_capabilities(self):
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
                    self.assertTrue(filled["ok"])
                    self.assertEqual(page.frame_locator("iframe").locator("#nested").input_value(), "sample")
                    self.assertTrue(session._dispatch("browser_find_text", {
                        "query": "Literal sample phrase", "max_matches": 3})["matches"])
                    self.assertIn("Literal sample phrase", session._dispatch("browser_read_page", {"offset": 0})["text"])
                    self.assertEqual(session._dispatch("browser_read_table", {
                        "frame_index": 0, "table_index": 0, "row_offset": 0})["rows"][-1], ["Example row"])

                    page.set_content("""
                        <details><summary>Details</summary><p>Main page</p></details>
                        <iframe srcdoc="<details><summary>Details</summary><p>Frame result</p></details>"></iframe>
                    """)
                    page.frame_locator("iframe").locator("summary").wait_for()
                    self.assertNotIn("Frame result", session._dispatch("browser_read_page", {"offset": 0})["text"])
                    found = session._dispatch("browser_find_controls", {"query": "Details"})
                    target = next(item for item in found["buttons"] if item["frame_index"] == 1)
                    self.assertFalse(target["expanded"])
                    opened = session._dispatch("browser_click_button", {"name": target["action_target"]})
                    self.assertTrue(opened["disclosure_changed"])
                    self.assertTrue(opened["expanded_after"])
                    self.assertIn("Frame result", opened["visible_text"])
                    self.assertFalse(page.locator("details").evaluate("el => el.open"))
                    with self.assertRaisesRegex(ValueError, "browser_target_disclosure_stale"):
                        session._dispatch("browser_click_button", {"name": target["action_target"]})

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

                    page.set_content('<section id="main-tabs"></section><demo-tabs></demo-tabs>')
                    page.evaluate("""() => {
                        const make = (root, label) => {
                            root.innerHTML = '<div role=tablist aria-label="' + label + '">' +
                                '<button role=tab aria-selected=false aria-controls=result>Summary</button>' +
                                '<button role=tab aria-disabled=true aria-selected=false aria-controls=result>Locked</button>' +
                                '<button role=tab aria-selected=false aria-controls=missing>Broken</button>' +
                                '</div><div id=result role=tabpanel hidden>' + label +
                                ' evidence<span hidden>not visible</span>' +
                                '<div contenteditable>editable value</div></div>' +
                                '<div id=missing role=tabpanel hidden>Still hidden</div>';
                            root.querySelector('[aria-controls=result]').onclick = (event) => {
                                event.target.setAttribute('aria-selected', 'true');
                                setTimeout(() => {root.querySelector('#result').hidden = false;}, 80);
                            };
                            root.querySelector('[aria-controls=missing]').onclick = (event) => {
                                event.target.setAttribute('aria-selected', 'true');
                            };
                        };
                        make(document.querySelector('#main-tabs'), 'Main');
                        make(document.querySelector('demo-tabs').attachShadow({mode:'open'}), 'Archive');
                    }""")
                    found = session._dispatch("browser_find_controls", {"query": "Summary"})
                    self.assertEqual({row["group"] for row in found["buttons"]}, {"Main", "Archive"})
                    archive = next(row for row in found["buttons"] if row["group"] == "Archive")
                    self.assertEqual(archive["shadow_host"], "demo-tabs")
                    activated = session._dispatch("browser_click_button", {"name": archive["action_target"]})
                    self.assertTrue(activated["tab_verified"])
                    self.assertTrue(activated["tab_clicked"])
                    self.assertEqual(activated["widget_state_after"]["panel_text"], "Archive evidence")
                    self.assertEqual(page.locator("#main-tabs [role=tab]").first.get_attribute("aria-selected"), "false")
                    locked = session._dispatch("browser_find_controls", {"query": "Locked"})
                    self.assertTrue(all("action_target" not in row for row in locked["buttons"]))
                    broken = session._dispatch("browser_find_controls", {"query": "Broken"})
                    bad_target = next(row["action_target"] for row in broken["buttons"]
                                      if row["group"] == "Archive")
                    rejected = session._dispatch("browser_click_button", {"name": bad_target})
                    self.assertFalse(rejected["tab_verified"])
                    self.assertTrue(rejected["widget_state_after"]["selected"])
                    self.assertFalse(rejected["widget_state_after"]["panel_visible"])
                    fresh = session._dispatch("browser_find_controls", {"query": "Summary"})
                    stale = next(row["action_target"] for row in fresh["buttons"] if row["group"] == "Main")
                    page.locator("#main-tabs [role=tab]").first.evaluate(
                        "el => el.setAttribute('aria-controls', 'missing')")
                    with self.assertRaisesRegex(ValueError, "browser_target_tab_stale"):
                        session._dispatch("browser_click_button", {"name": stale})
                    page.locator("#main-tabs").evaluate("""root => {
                        root.insertAdjacentHTML('beforeend', '<div id=missing role=tabpanel>Duplicate</div>');
                    }""")
                    duplicate = session._dispatch("browser_find_controls", {"query": "Summary"})
                    main_target = next(row["action_target"] for row in duplicate["buttons"]
                                       if row["group"] == "Main")
                    with self.assertRaisesRegex(ValueError, "browser_target_tab_stale"):
                        session._dispatch("browser_click_button", {"name": main_target})
                finally:
                    session._executor.shutdown(wait=False, cancel_futures=True)
                    context.close()
            finally:
                browser.close()

    def test_navigation_reports_access_limits_without_inferring_cause(self):
        session = BrowserSession()
        try:
            with patch.object(session, "_snapshot", return_value={"ok": True, "url": "https://example.org"}):
                result = session._navigation_snapshot(Mock(status=403))
            self.assertFalse(result["ok"])
            self.assertEqual(result["http_status"], 403)
            self.assertEqual(result["status"], "browser_access_limited")
        finally:
            session.close()

    def test_page_type_classifier_uses_url_and_visible_semantics(self):
        self.assertEqual(
            _classify_page_type(
                "https://playwright.dev/python/docs/intro", "Installation | Playwright Python",
                "Install and use Playwright", [{"text": "Installation"}], [], [],
            ),
            "documentation",
        )
        self.assertEqual(
            _classify_page_type("https://example.org/search?q=router", "Search results", "",
                                [], [], []),
            "search_results",
        )
        self.assertEqual(
            _classify_page_type("https://example.org/contact", "Contact", "Send us a message",
                                [], [{"label": "Email"}], []),
            "form",
        )
        self.assertEqual(
            _classify_page_type("https://example.org/data", "Inventory", "",
                                [{"text": "Inventory"}], [], [{"rows": 4}]),
            "data_table",
        )

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

    def test_snapshot_mode_and_error_classification(self):
        from console.browser_control import _classify_browser_error, BROWSER_CONTROL_TOOLS
        # Tool schema exposes mode and pagination
        snapshot_tool = next(t for t in BROWSER_CONTROL_TOOLS if t["name"] == "browser_snapshot")
        props = snapshot_tool["inputSchema"]["properties"]
        self.assertIn("mode", props)
        self.assertTrue({"orientation", "compact", "full"}.issubset(set(props["mode"]["enum"])))
        self.assertIn("control_offset", props)
        self.assertIn("control_limit", props)

        classified = _classify_browser_error(ValueError("browser_no_open_page"))
        self.assertEqual(classified["error"], "browser_no_open_page")
        self.assertIn("browser_navigate", classified["alternatives"])

        classified = _classify_browser_error(TimeoutError("Timeout 20000ms exceeded"))
        self.assertEqual(classified["error"], "browser_timeout")

        classified = _classify_browser_error(ValueError("browser_target_not_interactable"))
        self.assertEqual(classified["error"], "browser_target_not_interactable")
        self.assertTrue(any("scroll" in str(x) or "snapshot" in str(x) for x in classified["alternatives"]))

        classified = _classify_browser_error(ValueError("browser_arguments_invalid"))
        self.assertEqual(classified["error"], "browser_arguments_invalid")


    def test_stable_ref_parse_and_stale_verification(self):
        session = BrowserSession()
        self.addCleanup(session._executor.shutdown, wait=False)
        self.assertEqual(session._parse_ref("e12"), "e12")
        self.assertEqual(session._parse_ref("ref:e3"), "e3")
        self.assertEqual(session._parse_ref("data-cybernova-ref:e9"), "e9")
        self.assertIsNone(session._parse_ref("Submit"))
        self.assertIsNone(session._parse_ref("v12"))
        self.assertIsNone(session._parse_ref("id:foo"))
        # No stored meta -> stale
        with self.assertRaisesRegex(ValueError, "browser_target_stale"):
            session._verify_ref("e1")
        session._page = Mock()
        session._page.is_closed.return_value = False
        session._page.url = "https://example.com/app"
        session._element_refs["e1"] = {
            "frame_index": 0,
            "page_url": "https://example.com/app",
            "frame_url": "https://example.com/app",
            "fingerprint": "button||btn-ok|ok|OK|",
            "tag": "button", "role": "", "text": "OK", "id": "btn-ok",
            "shadow_path": "", "name": "",
        }
        # Navigated page invalidates refs
        session._page.url = "https://example.com/other"
        with self.assertRaisesRegex(ValueError, "browser_target_stale"):
            session._verify_ref("e1")

    def test_collect_elements_js_includes_shadow_walk(self):
        from console.browser_control import _collect_elements_js
        js = _collect_elements_js()
        self.assertIn("shadowRoot", js)
        self.assertIn("data-cybernova-ref", js)
        self.assertIn("fingerprint", js)


class SemanticContextTests(unittest.TestCase):
    def test_semantic_context_is_bounded_and_redacted(self):
        from console.browser_control import _semantic_context
        result = _semantic_context({
            "groups": [{"kind": "form", "label": "Search products"},
                       {"kind": "invalid", "label": "do not expose"},
                       {"kind": "article", "label": "person@example.com"}],
            "description": "password=example-secret",
            "controls": ["results", "not a valid id"],
            "has_popup": "listbox",
            "value": "do not expose",
        })
        self.assertEqual(result["groups"][0], {"kind": "form", "label": "Search products"})
        self.assertEqual(result["groups"][1]["label"], "[REDACTED EMAIL]")
        self.assertEqual(result["description"], "[REDACTED SECRET]")
        self.assertEqual(result["controls"], ["results"])
        self.assertEqual(result["has_popup"], "listbox")
        self.assertNotIn("value", result)

    def test_collector_searches_group_context(self):
        from console.browser_control import _collect_elements_js
        js = _collect_elements_js()
        self.assertIn("semanticOf(el).groups", js)
        self.assertIn("semantic: semanticOf(el)", js)
        self.assertIn("aria-controls", js)
        self.assertIn("el.form", js)


class SpatialContextTests(unittest.TestCase):
    def test_screenshot_requests_the_same_units_as_top_bounds(self):
        session = BrowserSession.__new__(BrowserSession)
        session._ensure = Mock()
        session._page = Mock(viewport_size={"width": 320, "height": 240})
        session._page.screenshot.return_value = b"fixture"
        session._frame_contexts = Mock(return_value=[])
        session._snapshot = Mock(return_value={"url": "https://example.test/", "title": "Fixture",
                                               "tab": 0, "links": [], "buttons": [], "form_fields": []})

        def add_coverage(result, **_):
            result["accessibility_coverage"] = {"complete": False}

        session._with_ax_evidence = Mock(side_effect=add_coverage)
        result = session._dispatch("browser_screenshot", {})
        self.assertEqual(session._page.screenshot.call_args.kwargs["scale"], "css")
        self.assertEqual(result["correlation"]["coordinate_units"], "css_pixels")
        self.assertFalse(result["correlation"]["atomic"])

    def test_action_baseline_does_not_follow_a_recycled_tab_index(self):
        session = BrowserSession.__new__(BrowserSession)
        session._page = object()
        session._response_mode = "compact"
        session._last_digest = None
        session._strategy = Mock()
        session._apply_intelligence("browser_snapshot", {}, {"ok": True, "tab": 0, "visible_text": "Before"})
        session._page = object()
        result = session._apply_intelligence(
            "browser_click_button", {}, {"ok": True, "tab": 0, "visible_text": "After"}
        )
        self.assertEqual(result["effect"], "unverified_no_baseline")

    def test_spatial_coordinate_space_is_explicit(self):
        from console.browser_control import _spatial_context
        raw = {"bounds": {"x": -5, "y": 20, "width": 40, "height": 30},
               "center_hit": "other", "focused": False}
        self.assertEqual(_spatial_context(raw, 0)["space"], "top_viewport")
        self.assertEqual(_spatial_context(raw, 2)["space"], "frame_viewport")
        self.assertEqual(_spatial_context(raw, 2)["center_hit"], "other")
        self.assertFalse(_spatial_context(raw, 0)["focused"])
        self.assertEqual(_spatial_context({"bounds": {"x": "unsafe"}}, 0), {})


class RefInteractionTests(unittest.TestCase):
    def test_hover_and_focus_use_verified_ref(self):
        session = BrowserSession.__new__(BrowserSession)
        locator = Mock()
        session._verify_ref = Mock(return_value=(Mock(), locator))
        session._snapshot = Mock(return_value={"ok": True})
        for interaction in ("hover", "focus"):
            result = session._interact_ref(interaction, "ref:e12")
            self.assertEqual(result["interaction"], interaction)
            self.assertEqual(result["interaction_ref"], "e12")
        locator.hover.assert_called_once_with(timeout=8000)
        locator.focus.assert_called_once_with(timeout=8000)
        with self.assertRaisesRegex(ValueError, "browser_interaction_requires_ref"):
            session._interact_ref("hover", "arbitrary CSS")

    def test_widget_navigation_keys_are_targeted_and_activation_keys_rejected(self):
        session = BrowserSession.__new__(BrowserSession)
        locator = Mock()
        locator.evaluate.side_effect = [{"focused": True, "active_descendant": "first"},
                                        {"focused": True, "active_descendant": "second"}]
        session._verify_ref = Mock(return_value=(Mock(), locator))
        session._snapshot = Mock(return_value={"ok": True})
        result = session._interact_ref("key:ArrowDown", "ref:e12")
        self.assertTrue(result["widget_state_changed"])
        self.assertEqual(result["widget_state_after"]["active_descendant"], "second")
        locator.press.assert_called_once_with("ArrowDown", timeout=8000)
        for key in ("Enter", "Space", "Control+A"):
            with self.assertRaisesRegex(ValueError, "browser_widget_navigation_key_not_allowed"):
                session._interact_ref("key:" + key, "ref:e12")
        locator.press.assert_called_once()

    def test_double_click_rejects_form_controls(self):
        session = BrowserSession.__new__(BrowserSession)
        session._page = Mock(url="https://example.test/")
        locator = Mock()
        button = Mock()
        button.evaluate.return_value = {"form": True, "submit": False, "text": "Continue"}
        session._verify_ref = Mock(return_value=(Mock(), locator))
        session._unique = Mock(return_value=button)
        with self.assertRaisesRegex(ValueError, "browser_double_click_requires_ordinary_button"):
            session._interact_ref("double_click", "ref:e12")
        button.dblclick.assert_not_called()


class VisualObjectTests(unittest.TestCase):
    def test_visual_hints_never_expose_source_or_action_target(self):
        from console.browser_control import _visual_object
        raw = {"kind": "icon", "dom_kind": "svg", "label": "person@example.com", "label_source": "aria-labelledby",
               "owner_ref": "e4", "visual_ref": "v8", "bounds": {"x": 2, "y": 3, "width": 18, "height": 18},
               "src": "private", "action_target": "not-allowed", "small": True}
        result = _visual_object(raw, 2)
        self.assertEqual(result["owner_ref"], "e4")
        self.assertEqual(result["visual_ref"], "v8")
        self.assertEqual(result["dom_kind"], "svg")
        self.assertEqual(result["label_source"], "aria-labelledby")
        self.assertEqual(result["label"], "[REDACTED EMAIL]")
        self.assertEqual(result["spatial"]["space"], "frame_viewport")
        self.assertNotIn("src", result)
        self.assertNotIn("action_target", result)


class InferredCardTests(unittest.TestCase):
    def test_card_is_explicitly_inferred_and_sanitized(self):
        from console.browser_control import _semantic_context
        data = {"groups": [{"kind": "card_candidate", "label": "Example card",
                            "inferred": True, "ordinal": 2,
                            "evidence": ["repeated_sibling_structure", "local_control", "untrusted"]},
                           {"kind": "card_candidate", "label": "Unmarked"}]}
        groups = _semantic_context(data)["groups"]
        self.assertEqual(len(groups), 1)
        self.assertTrue(groups[0]["inferred"])
        self.assertEqual(groups[0]["ordinal"], 2)
        self.assertEqual(groups[0]["evidence"], ["repeated_sibling_structure", "local_control"])
        single = _semantic_context({"groups": [{"kind": "card_candidate", "inferred": True,
                                    "evidence": ["distinct_visual_boundary", "visible_title"]}]})
        self.assertIn("distinct_visual_boundary", single["groups"][0]["evidence"])
        self.assertNotIn("ordinal", single["groups"][0])


class NativeAXEvidenceTests(unittest.TestCase):
    def test_ax_properties_never_echo_name_or_value(self):
        from console.browser_control import _ax_properties
        raw = {"role": {"value": "textbox"}, "ignored": False,
               "name": {"value": "secret name"}, "value": {"value": "secret value"},
               "properties": [{"name": "focused", "value": {"value": True}},
                              {"name": "description", "value": {"value": "secret description"}}]}
        evidence = _ax_properties(raw)
        self.assertEqual(evidence, {"role": "textbox", "ignored": False, "state": {"focused": True}})
        self.assertNotIn("secret", repr(evidence))

    def test_native_ax_sample_matches_backend_node_and_detaches(self):
        session = BrowserSession.__new__(BrowserSession)
        session._context = Mock()
        session._page = Mock()
        session._ref_namespace = "fixture"
        locator = Mock()
        locator.bounding_box.return_value = {"x": 10, "y": 20, "width": 30, "height": 40}
        session._verify_ref = Mock(return_value=(session._page, locator))
        cdp = session._context.new_cdp_session.return_value
        responses = {"DOM.performSearch": {"searchId": "s", "resultCount": 1},
                     "DOM.getSearchResults": {"nodeIds": [2]},
                     "DOM.describeNode": {"node": {"backendNodeId": 3}},
                     "DOM.resolveNode": {"object": {"objectId": "o"}},
                     "Runtime.callFunctionOn": {"result": {"value": True}},
                     "Accessibility.getPartialAXTree": {"nodes": [
                         {"backendDOMNodeId": 99, "role": {"value": "wrong"}},
                         {"backendDOMNodeId": 3, "role": {"value": "button"}, "ignored": False}]}}
        cdp.send.side_effect = lambda method, args=None: responses.get(method, {})
        snap = {"buttons": [{"ref": "e1", "frame_index": 0},
                            {"ref": "e2", "frame_index": 1, "shadow_path": "custom-host"}]}
        result = session._with_ax_evidence(snap, viewport={"width": 100, "height": 100})
        for row in result["buttons"]:
            self.assertEqual(row["accessibility"]["role"], "button")
            self.assertTrue(row["spatial"]["top_viewport_intersection"])
        self.assertEqual(result["accessibility_coverage"]["observed_frames"], [0, 1])
        self.assertEqual(result["accessibility_coverage"]["shadow_observed"], 1)
        self.assertFalse(result["accessibility_coverage"]["complete"])
        cdp.detach.assert_called_once()
        self.assertEqual(sum(c.args[0] == "DOM.discardSearchResults" for c in cdp.send.call_args_list), 2)
        responses["Runtime.callFunctionOn"] = {"result": {"value": False}}
        self.assertEqual(session._ax_node_for_ref(cdp, "e1"), {})


if __name__ == "__main__":
    unittest.main()
