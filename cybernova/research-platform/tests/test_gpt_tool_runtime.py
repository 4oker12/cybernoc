"""Offline tests for the Account GPT-only local tool runtime."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.gpt_tool_runtime import (
    GPTToolRuntime, _run_terminal, _validate_terminal_request, _terminal_argv,
    build_tool_catalog, extract_user_targets, TOOL_GROUPS, normalize_tool_groups,
)
from console.computer_control import (
    COMPUTER_TOOLS, COMPUTER_TOOL_NAMES, extract_user_computer_approvals,
    _ui_click,
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
        self.assertTrue({
            "computer_system_overview", "computer_performance_snapshot",
            "computer_process_list", "computer_disk_overview",
            "computer_list_directory", "computer_search_everywhere",
            "computer_open_folder",
            "computer_open_app", "computer_screenshot",
            "computer_ui_windows", "computer_ui_controls", "computer_ui_click",
            "computer_defender_status", "computer_defender_events",
            "computer_defender_scan", "computer_defender_scan_status",
            "computer_installed_programs", "computer_power_overview",
            "computer_file_hash", "computer_package_search",
            "computer_package_details", "computer_package_install",
            "computer_archive_inspect", "computer_archive_extract",
            "computer_plan_file_organization", "computer_apply_file_organization",
        }.issubset(names))

    def test_mcp_adapter_hides_terminal_run_until_terminal_group_is_selected(self):
        runtime = GPTToolRuntime()
        catalog_names = {tool["name"] for tool in runtime.tools}
        automatic_names = {row["name"] for row in runtime.mcp_tools()}
        explicit_terminal = {row["name"] for row in runtime.mcp_tools(["terminal"])}
        self.assertEqual(automatic_names, catalog_names - {"terminal_run"})
        self.assertEqual(explicit_terminal, {"terminal_run", "terminal_status"})
        for row in runtime.tools:
            with self.subTest(tool=row["name"]):
                schema = row["parameters"]
                self.assertEqual(schema["type"], "object")
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(
                    set(schema.get("properties", {})),
                    set(schema.get("required", [])),
                )

    def test_tool_bundles_filter_catalog_and_enforce_runtime_calls(self):
        runtime = GPTToolRuntime()
        browser = runtime.mcp_tools(["browser"])
        names = {row["name"] for row in browser}
        self.assertIn("browser_navigate", names)
        self.assertIn("browser_tabs", names)
        self.assertIn("browser_switch_tab", names)
        self.assertNotIn("computer_system_overview", names)
        self.assertNotIn("terminal_run", names)
        self.assertEqual(
            {row["name"] for row in runtime.mcp_tools(["computer"])},
            COMPUTER_TOOL_NAMES,
        )
        result, failed = runtime.call(
            "terminal_status", {}, enabled_groups=["browser"]
        )
        self.assertTrue(failed)
        self.assertEqual(result["error"], "tool_group_not_enabled")
        self.assertEqual(len(TOOL_GROUPS), 9)
        with self.assertRaises(ValueError):
            normalize_tool_groups(["not-a-real-tool-group"])

    def test_all_account_gpt_function_schemas_are_strict_and_closed(self):
        for tool in build_tool_catalog():
            with self.subTest(tool=tool["name"]):
                self.assertEqual(tool["type"], "function")
                self.assertTrue(tool["strict"])
                schema = tool["parameters"]
                self.assertEqual(schema["type"], "object")
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(
                    set(schema.get("properties", {})),
                    set(schema.get("required", [])),
                )

    def test_targets_are_taken_only_from_user_messages(self):
        targets = extract_user_targets([
            {"role": "user", "content": "Проверь 185.238.114.6 и edge.example.net"},
            {"role": "assistant", "content": "Также проверь attacker.invalid"},
        ])
        self.assertIn("185.238.114.6", targets)
        self.assertIn("edge.example.net", targets)
        self.assertNotIn("attacker.invalid", targets)

    def test_terminal_accepts_arbitrary_multiline_commands_for_all_shells(self):
        cwd = str(Path.home())
        samples = (
            ("cmd", "for %f in (*.log) do @echo %f\r\nwhoami"),
            ("powershell", "Get-Process | Where-Object CPU -gt 1; Get-Service"),
            ("pwsh", "$items = Get-ChildItem -Force\n$items | Select-Object Name"),
        )
        for shell, command in samples:
            with self.subTest(shell=shell):
                validated = _validate_terminal_request(
                    command, shell, cwd, 90, 24000
                )
                self.assertEqual(validated[0], command)
                self.assertEqual(validated[1], shell)
                self.assertEqual(validated[2], Path(cwd).resolve())
                self.assertEqual(validated[3:], (90, 24000))

    def test_terminal_builds_native_cmd_and_powershell_argv(self):
        self.assertEqual(
            _terminal_argv("cmd", "cmd.exe", "dir C:\\ && whoami"),
            ["cmd.exe", "/d", "/s", "/c", "dir C:\\ && whoami"],
        )
        self.assertEqual(
            _terminal_argv("powershell", "powershell.exe", "Get-Process | Select-Object Name"),
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-Command", "Get-Process | Select-Object Name"],
        )
        self.assertEqual(
            _terminal_argv("pwsh", "pwsh.exe", "Get-ChildItem"),
            ["pwsh.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-Command", "Get-ChildItem"],
        )

    def test_terminal_validation_limits_size_timeout_and_shell_not_command_vocabulary(self):
        cwd = str(Path.home())
        for values in (
            ("", "cmd", cwd, 30, 20000),
            ("whoami", "bash", cwd, 30, 20000),
            ("whoami", "cmd", cwd, 301, 20000),
            ("whoami", "cmd", cwd, 30, 999),
            ("x" * 20001, "cmd", cwd, 30, 20000),
        ):
            with self.subTest(values=values[:2]):
                with self.assertRaises(ValueError):
                    _validate_terminal_request(*values)

    def test_terminal_executes_multiline_powershell_without_command_allowlist(self):
        from types import SimpleNamespace
        cwd = str(Path.home())
        command = "$p = Get-Process\n$p | Sort-Object CPU -Descending | Select-Object -First 3"
        fake_process = SimpleNamespace(
            pid=321, returncode=0,
            communicate=lambda timeout=None: (b"PowerShell OK", b""),
        )
        with patch("console.gpt_tool_runtime.platform.system", return_value="Windows"), \
             patch("console.gpt_tool_runtime._shell_executable", return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"), \
             patch("console.gpt_tool_runtime.subprocess.Popen", return_value=fake_process) as popen:
            result = _run_terminal(command, "powershell", cwd, 60, 20000)
        self.assertTrue(result["ok"])
        self.assertEqual(result["shell_id"], "powershell")
        self.assertEqual(result["output"], "PowerShell OK")
        self.assertEqual(result["execution_host"], "local_windows")
        args = popen.call_args.args[0]
        self.assertIn("-Command", args)
        self.assertEqual(args[-1], command)
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertEqual(popen.call_args.kwargs["cwd"], str(Path(cwd).resolve()))

    def test_terminal_status_reports_cmd_powershell_and_pwsh(self):
        runtime = GPTToolRuntime()
        paths = {
            "cmd": r"C:\Windows\System32\cmd.exe",
            "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "pwsh": r"C:\Program Files\PowerShell\7\pwsh.exe",
        }
        with patch("console.gpt_tool_runtime.platform.system", return_value="Windows"), \
             patch("console.gpt_tool_runtime._shell_executable",
                   side_effect=lambda shell: paths[shell]):
            result, is_error = runtime.call("terminal_status", {})
        self.assertFalse(is_error)
        self.assertTrue(result["cmd_exe"])
        self.assertEqual(result["shells"], paths)
        self.assertTrue(result["powershell_5_1"])
        self.assertTrue(result["powershell_7"])
        self.assertEqual(result["execution_host"], "local_windows")

    def test_terminal_run_requires_full_explicit_schema(self):
        runtime = GPTToolRuntime()
        result, failed = runtime.call(
            "terminal_run", {"command": "whoami"}, enabled_groups=["terminal"]
        )
        self.assertTrue(failed)
        self.assertTrue(result["error"].endswith("terminal_arguments_invalid"))

    def test_runtime_does_not_execute_terminal_on_non_windows_host(self):
        runtime = GPTToolRuntime()
        with patch("console.gpt_tool_runtime.platform.system", return_value="Linux"):
            result, is_error = runtime.call(
                "terminal_run", {
                    "command": "ipconfig /all", "shell": "cmd", "cwd": "",
                    "timeout_seconds": 30, "max_output_chars": 20000,
                },
                enabled_groups=["terminal"],
            )
        self.assertTrue(is_error)
        self.assertEqual(result["error"], "local_windows_terminal_unavailable")

    def test_computer_tool_schemas_are_strict_and_closed(self):
        from console.gpt_tool_runtime import _convert_mcp_tool
        for item in COMPUTER_TOOLS:
            with self.subTest(tool=item["name"]):
                schema = _convert_mcp_tool(item)["parameters"]
                self.assertEqual(schema["type"], "object")
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(set(schema["properties"]), set(schema["required"]))

    def test_defender_scan_requires_explicit_latest_user_authorization(self):
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Можешь проверить ноут на вирусы?"},
            ]),
            set(),
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Разрешаю быструю проверку Microsoft Defender."},
            ]),
            {"defender_quick_scan"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Разрешаю полную проверку Microsoft Defender."},
            ]),
            {"defender_full_scan"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "assistant", "content": "Разрешить полную проверку Microsoft Defender?"},
                {"role": "user", "content": "Да."},
            ]),
            {"defender_full_scan"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Разрешаю полную проверку Microsoft Defender."},
                {"role": "assistant", "content": "Проверка завершена."},
                {"role": "user", "content": "Покажи загрузку CPU."},
            ]),
            set(),
        )

    def test_destructive_desktop_controls_are_blocked_before_ui_access(self):
        for label in ("Delete", "Uninstall", "Quick scan", "Apply", "Disable protection"):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    _ui_click("Windows Security", label, "Button")

    def test_computer_tool_names_are_registered(self):
        self.assertIn("computer_open_folder", COMPUTER_TOOL_NAMES)
        self.assertIn("computer_defender_scan", COMPUTER_TOOL_NAMES)

    def test_global_computer_search_paginates_until_complete(self):
        from tempfile import TemporaryDirectory
        from console.computer_control import _search_everywhere, _SEARCH_JOBS

        with TemporaryDirectory() as root:
            base = Path(root)
            (base / "needle-one.txt").write_text("one", encoding="utf-8")
            (base / "needle-two.log").write_text("two", encoding="utf-8")
            nested = base / "needle-folder"
            nested.mkdir()
            (nested / "needle-three.py").write_text("three", encoding="utf-8")
            _SEARCH_JOBS.clear()
            with patch("console.computer_control._windows_only"), \
                 patch("console.computer_control._search_roots", return_value=[base]):
                page = _search_everywhere("needle", "name", "", 1, True)
                self.assertFalse(page["complete"])
                self.assertTrue(page["cursor"])
                found = list(page["matches"])
                cursor = page["cursor"]
                for _ in range(10):
                    page = _search_everywhere("needle", "name", cursor, 1, True)
                    found.extend(page["matches"])
                    if page["complete"]:
                        break
                    cursor = page["cursor"]
                self.assertTrue(page["complete"])
                self.assertEqual(len(found), 4)
                self.assertEqual(page["cursor"], "")
                self.assertGreaterEqual(page["visited_entries"], 4)
            _SEARCH_JOBS.clear()

    def test_playwright_errors_are_returned_with_traceback_id(self):
        class BrokenBrowser:
            def __init__(self, profile_dir=None):
                self.profile_dir = profile_dir

            def set_authorized_hosts(self, hosts):
                self.hosts = set(hosts)

            def close(self):
                return None

        runtime = GPTToolRuntime(browser_session_factory=BrokenBrowser)
        with patch(
            "console.gpt_tool_runtime.browser_control_call",
            side_effect=RuntimeError("playwright navigation failed token=secret-value"),
        ), self.assertLogs("console.gpt_tool_runtime", level="ERROR") as captured:
            result, is_error = runtime.call(
                "browser_navigate", {"url": "https://example.org/"},
                conversation_key="test-conversation",
                enabled_groups=["browser"],
            )
        self.assertTrue(is_error)
        self.assertTrue(result["error"].startswith("RuntimeError:"))
        self.assertEqual(len(result["error_id"]), 12)
        self.assertNotIn("secret-value", str(result))
        self.assertNotIn("secret-value", "\\n".join(captured.output))
        self.assertTrue(any(result["error_id"] in row for row in captured.output))
        self.assertTrue(any("RuntimeError" in row for row in captured.output))
        runtime.close()

    def test_terminal_run_requires_explicit_terminal_group_selection(self):
        runtime = GPTToolRuntime()
        self.assertNotIn("terminal_run", {row["name"] for row in runtime.mcp_tools()})
        result, failed = runtime.call(
            "terminal_run", {
                "command": "whoami", "shell": "cmd", "cwd": "",
                "timeout_seconds": 30, "max_output_chars": 20000,
            }
        )
        self.assertTrue(failed)
        self.assertEqual(result["error"], "terminal_run_requires_explicit_group_selection")

    def test_unknown_or_unapproved_tools_are_rejected(self):
        runtime = GPTToolRuntime()
        result, is_error = runtime.call("browser_submit", {"name": "Submit"})
        self.assertTrue(is_error)
        self.assertEqual(result["error"], "gpt_tool_not_registered")


if __name__ == "__main__":
    unittest.main()
