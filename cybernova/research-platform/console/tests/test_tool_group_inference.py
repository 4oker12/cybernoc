"""Unit tests for intent → tool group inference (no network, no MCP)."""
from __future__ import annotations

import unittest

from gpt_tool_runtime import (
    infer_relevant_tool_groups, resolve_tool_groups, tool_group_for_name,
)


class InferToolGroupsTests(unittest.TestCase):
    def test_browser_registration(self):
        groups = infer_relevant_tool_groups(
            "Открой сайт example.com и зарегистрируй аккаунт"
        )
        self.assertIn("browser", groups)

    def test_web_search(self):
        groups = infer_relevant_tool_groups("Найди в Google информацию о CVE-2024")
        self.assertIn("web", groups)

    def test_computer(self):
        groups = infer_relevant_tool_groups("Покажи процессы и загрузку CPU")
        self.assertIn("computer", groups)

    def test_terminal(self):
        groups = infer_relevant_tool_groups("Выполни в PowerShell Get-Process")
        self.assertIn("terminal", groups)

    def test_developer_github(self):
        groups = infer_relevant_tool_groups("Сделай commit и открой pull request")
        self.assertIn("developer", groups)
        self.assertIn("github", groups)

    def test_security(self):
        groups = infer_relevant_tool_groups("Просканируй с nuclei")
        self.assertIn("security", groups)

    def test_traffic(self):
        groups = infer_relevant_tool_groups("Проанализируй HAR файл")
        self.assertIn("traffic", groups)

    def test_no_signal(self):
        self.assertEqual(infer_relevant_tool_groups("Привет, как дела?"), [])

    def test_group_mapping_terminal_aliases(self):
        self.assertEqual(tool_group_for_name("terminal_run"), "terminal")
        self.assertEqual(tool_group_for_name("safe_terminal"), "terminal")
        self.assertEqual(tool_group_for_name("browser_navigate"), "browser")
        self.assertEqual(tool_group_for_name("browser_open"), "browser")


class ResolveToolGroupsTests(unittest.TestCase):
    def test_explicit_wins(self):
        self.assertEqual(
            resolve_tool_groups("register account", ["terminal"]),
            ["terminal"],
        )

    def test_infer_augments_browser_with_web(self):
        groups = resolve_tool_groups("зарегистрируй аккаунт на сайте", [])
        self.assertIn("browser", groups)
        self.assertIn("web", groups)

    def test_empty_on_no_signal(self):
        self.assertEqual(resolve_tool_groups("Привет", None), [])


if __name__ == "__main__":
    unittest.main()
