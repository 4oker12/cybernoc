"""Tests for Patchright-first Chromium backend selection."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import os
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import browser_backend


class FakeRuntime:
    def __init__(self, name):
        self.name = name
        self.stopped = False

    def stop(self):
        self.stopped = True


class FakeManager:
    def __init__(self, runtime):
        self.runtime = runtime

    def start(self):
        return self.runtime


class BrowserBackendTests(unittest.TestCase):
    def test_patchright_is_the_default_and_playwright_is_fallback(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                browser_backend.backend_order(),
                ("patchright", "playwright"),
            )

    def test_playwright_can_be_selected_explicitly(self):
        with patch.dict(os.environ, {"CYBERNOVA_BROWSER_BACKEND": "playwright"}):
            self.assertEqual(browser_backend.backend_order(), ("playwright",))

    def test_invalid_backend_setting_fails_closed(self):
        with patch.dict(os.environ, {"CYBERNOVA_BROWSER_BACKEND": "firefox"}):
            with self.assertRaisesRegex(ValueError, "browser_backend_invalid"):
                browser_backend.backend_order()

    def test_patchright_launch_failure_falls_back_to_playwright(self):
        patchright_runtime = FakeRuntime("patchright")
        playwright_runtime = FakeRuntime("playwright")
        modules = {
            "patchright.sync_api": SimpleNamespace(
                sync_playwright=lambda: FakeManager(patchright_runtime)
            ),
            "playwright.sync_api": SimpleNamespace(
                sync_playwright=lambda: FakeManager(playwright_runtime)
            ),
        }
        attempts = []

        def fake_import(name):
            return modules[name]

        def launcher(runtime):
            attempts.append(runtime.name)
            if runtime.name == "patchright":
                raise OSError("simulated Patchright launch failure")
            return "browser-ready"

        with patch.dict(os.environ, {}, clear=True), patch.object(
            browser_backend, "import_module", side_effect=fake_import
        ):
            runtime, backend, result, fallback_reason = (
                browser_backend.launch_with_backend(launcher)
            )

        self.assertEqual(attempts, ["patchright", "playwright"])
        self.assertTrue(patchright_runtime.stopped)
        self.assertIs(runtime, playwright_runtime)
        self.assertEqual(backend, "playwright")
        self.assertEqual(result, "browser-ready")
        self.assertEqual(fallback_reason, "OSError")

    def test_patchright_import_failure_falls_back_to_playwright(self):
        playwright_runtime = FakeRuntime("playwright")

        def fake_import(name):
            if name == "patchright.sync_api":
                raise ImportError("patchright missing")
            return SimpleNamespace(
                sync_playwright=lambda: FakeManager(playwright_runtime)
            )

        with patch.dict(os.environ, {}, clear=True), patch.object(
            browser_backend, "import_module", side_effect=fake_import
        ):
            runtime, backend, result, fallback_reason = (
                browser_backend.launch_with_backend(lambda _: "ready")
            )

        self.assertIs(runtime, playwright_runtime)
        self.assertEqual(backend, "playwright")
        self.assertEqual(result, "ready")
        self.assertEqual(fallback_reason, "ImportError")

    def test_explicit_playwright_does_not_try_patchright(self):
        playwright_runtime = FakeRuntime("playwright")
        calls = []

        def fake_import(name):
            calls.append(name)
            return SimpleNamespace(
                sync_playwright=lambda: FakeManager(playwright_runtime)
            )

        with patch.dict(
            os.environ, {"CYBERNOVA_BROWSER_BACKEND": "playwright"}
        ), patch.object(browser_backend, "import_module", side_effect=fake_import):
            runtime, backend, result, fallback_reason = (
                browser_backend.launch_with_backend(lambda _: "ready")
            )

        self.assertEqual(calls, ["playwright.sync_api"])
        self.assertEqual(backend, "playwright")
        self.assertIsNone(fallback_reason)


if __name__ == "__main__":
    unittest.main()
