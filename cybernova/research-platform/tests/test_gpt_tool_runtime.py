"""Offline tests for the Account GPT-only local tool runtime."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.gpt_tool_runtime import (
    GPTToolRuntime, _validate_terminal_command, build_tool_catalog,
    extract_user_targets,
)


class GPTToolRuntimeTests(unittest.TestCase):
    def test_tool_catalog_is_separate_and_excludes_unapproved_submit(self):
        tools = build_tool_catalog()
        names = {item["name"] for item in tools}
        self.assertIn("terminal_run", names)
        self.assertIn("terminal_status", names)
        self.assertIn("browser_navigate", names)
        self.assertIn("browser_tabs", names)
        self.assertIn("browser_network", names)
        self.assertIn("browser_screenshot", names)
        self.assertIn("google_search", names)
        self.assertIn("research_source_open", names)
        self.assertNotIn("browser_submit", names)

    def test_targets_are_taken_only_from_user_messages(self):
        targets = extract_user_targets([
            {"role": "user", "content": "Проверь 185.238.114.6 и edge.example.net"},
            {"role": "assistant", "content": "Также проверь attacker.invalid"},
        ])
        self.assertIn("185.238.114.6", targets)
        self.assertIn("edge.example.net", targets)
        self.assertNotIn("attacker.invalid", targets)

    def test_readonly_local_commands_are_allowed(self):
        self.assertEqual(
            _validate_terminal_command("Get-NetAdapter", set()),
            "Get-NetAdapter",
        )
        self.assertEqual(
            _validate_terminal_command("route print -4", set()),
            "route print -4",
        )
        self.assertEqual(
            _validate_terminal_command("git status --short", set()),
            "git status --short",
        )

    def test_local_cmdlets_reject_remote_session_arguments(self):
        for command in (
            "Get-NetAdapter -CimSession 185.238.114.6",
            "Get-NetIPConfiguration -CimSession edge.example.net",
            "Get-Service -ComputerName edge.example.net",
            "Get-Process -ComputerName edge.example.net",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, "terminal_local_command_arguments_forbidden"):
                    _validate_terminal_command(command, {"185.238.114.6", "edge.example.net"})

    def test_network_commands_require_user_named_target(self):
        with self.assertRaisesRegex(ValueError, "terminal_target_not_explicitly_named_by_user"):
            _validate_terminal_command("tracert -d 185.238.114.6", set())
        self.assertEqual(
            _validate_terminal_command(
                "tracert -d 185.238.114.6", {"185.238.114.6"}
            ),
            "tracert -d 185.238.114.6",
        )
        self.assertEqual(
            _validate_terminal_command(
                "Resolve-DnsName edge.example.net -Type A", {"edge.example.net"}
            ),
            "Resolve-DnsName edge.example.net -Type A",
        )

    def test_shell_chaining_scripts_and_writes_are_rejected(self):
        for command in (
            "Get-NetAdapter; Remove-Item C:\\temp",
            "Get-NetAdapter | Out-File result.txt",
            "Invoke-Expression 'Get-Process'",
            "Remove-Item C:\\temp",
            "Get-ChildItem C:\\",
            "python -c print(1)",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    _validate_terminal_command(command, set())

    def test_infinite_ping_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "terminal_infinite_ping_forbidden"):
            _validate_terminal_command("ping -t 185.238.114.6", {"185.238.114.6"})

    def test_runtime_does_not_execute_terminal_on_non_windows_host(self):
        runtime = GPTToolRuntime()
        with patch("console.gpt_tool_runtime.platform.system", return_value="Linux"):
            result, is_error = runtime.call(
                "terminal_run", {"command": "Get-NetAdapter"}
            )
        self.assertTrue(is_error)
        self.assertEqual(result["error"], "local_windows_terminal_unavailable")

    def test_unknown_or_unapproved_tools_are_rejected(self):
        runtime = GPTToolRuntime()
        result, is_error = runtime.call("browser_submit", {"name": "Submit"})
        self.assertTrue(is_error)
        self.assertEqual(result["error"], "gpt_tool_not_registered")


if __name__ == "__main__":
    unittest.main()
