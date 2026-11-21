"""Offline tests for the Account GPT-only local tool runtime."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.gpt_tool_runtime import (
    GPTToolRuntime, _run_terminal, _validate_terminal_command, build_tool_catalog,
    extract_user_targets, TOOL_GROUPS, normalize_tool_groups,
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
            "computer_list_directory", "computer_open_folder",
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

    def test_mcp_adapter_exports_the_identical_local_tool_names_and_schemas(self):
        runtime = GPTToolRuntime()
        rows = runtime.mcp_tools()
        self.assertEqual(
            {row["name"] for row in rows},
            {tool["name"] for tool in runtime.tools},
        )
        for row in rows:
            with self.subTest(tool=row["name"]):
                self.assertEqual(row["inputSchema"]["type"], "object")
                self.assertFalse(row["inputSchema"]["additionalProperties"])
                self.assertEqual(
                    set(row["inputSchema"].get("properties", {})),
                    set(row["inputSchema"].get("required", [])),
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

    def test_readonly_cmd_commands_are_allowed(self):
        for command in (
            "hostname",
            "whoami",
            "whoami /groups",
            "whoami /priv",
            "ver",
            "systeminfo",
            "ipconfig /all",
            "ipconfig /displaydns",
            "tasklist /fo csv",
            "tasklist /fo table",
            "driverquery /fo csv",
            "sc query",
            "sc query WinDefend",
            "powercfg /getactivescheme",
            "where.exe winget",
            "route print -4",
            "route print -6",
            "netstat -ano",
            "netstat -e",
            "arp -a",
            "getmac /v",
            "netsh interface show interface",
            "netsh interface ipv4 show config",
            "netsh advfirewall show allprofiles",
            "netsh wlan show interfaces",
            "git status --short",
            "python --version",
        ):
            with self.subTest(command=command):
                self.assertEqual(_validate_terminal_command(command, set()), command)

    def test_powershell_specific_commands_are_not_used_by_cmd_backend(self):
        for command in (
            "Get-NetAdapter",
            "Get-NetIPConfiguration",
            "Get-NetRoute",
            "Test-NetConnection -ComputerName edge.example.net -Port 443",
            "Resolve-DnsName edge.example.net",
            "pwsh --version",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    _validate_terminal_command(command, {"edge.example.net"})

    def test_cmd_diagnostic_allowlist_rejects_mutating_process_and_service_commands(self):
        for command in (
            "taskkill /im chrome.exe /f",
            "sc config WinDefend start= disabled",
            "sc stop WinDefend",
            "powercfg /setactive SCHEME_MAX",
            "where.exe powershell",
            "driverquery /v /fo list",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    _validate_terminal_command(command, set())

    def test_cmd_backend_rejects_mutating_network_commands(self):
        for command in (
            "route add 10.0.0.0 mask 255.0.0.0 192.168.1.1",
            "arp -s 192.168.1.1 00-11-22-33-44-55",
            "ipconfig /release",
            "netsh advfirewall set allprofiles state off",
            "netsh interface ip set address",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    _validate_terminal_command(command, set())

    def test_network_commands_require_user_named_target(self):
        with self.assertRaisesRegex(ValueError, "terminal_target_not_explicitly_named_by_user"):
            _validate_terminal_command("tracert -d 185.238.114.6", set())
        self.assertEqual(
            _validate_terminal_command(
                "tracert -d -h 12 -w 700 185.238.114.6", {"185.238.114.6"}
            ),
            "tracert -d -h 12 -w 700 185.238.114.6",
        )
        self.assertEqual(
            _validate_terminal_command(
                "ping -n 5 1.1.1.1", {"1.1.1.1"}
            ),
            "ping -n 5 1.1.1.1",
        )
        self.assertEqual(
            _validate_terminal_command(
                "nslookup edge.example.net", {"edge.example.net"}
            ),
            "nslookup edge.example.net",
        )

    def test_https_probe_is_bounded_to_head_request(self):
        self.assertEqual(
            _validate_terminal_command(
                "curl.exe -I --connect-timeout 5 --max-time 10 https://edge.example.net/",
                {"edge.example.net"},
            ),
            "curl.exe -I --connect-timeout 5 --max-time 10 https://edge.example.net/",
        )
        for command in (
            "curl.exe -X POST https://edge.example.net/",
            "curl.exe -I -L https://edge.example.net/",
            "curl.exe -I --connect-timeout 50 --max-time 10 https://edge.example.net/",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    _validate_terminal_command(command, {"edge.example.net"})

    def test_dns_tools_cannot_choose_unscoped_resolvers(self):
        with self.assertRaisesRegex(ValueError, "terminal_nslookup_custom_server_or_options_forbidden"):
            _validate_terminal_command(
                "nslookup edge.example.net 8.8.8.8",
                {"edge.example.net", "8.8.8.8"},
            )

    def test_shell_chaining_scripts_and_writes_are_rejected(self):
        for command in (
            "Get-NetAdapter; Remove-Item C:\\temp",
            "Get-NetAdapter | Out-File result.txt",
            "Invoke-Expression 'Get-Process'",
            "Remove-Item C:\\temp",
            "Get-ChildItem C:\\",
            "python -c print(1)",
            "git diff --stat --output=leak.txt",
            "git log --output=leak.txt",
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    _validate_terminal_command(command, set())

    def test_ping_count_is_bounded_and_infinite_ping_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "terminal_ping_options_not_allowlisted"):
            _validate_terminal_command("ping -t 185.238.114.6", {"185.238.114.6"})
        with self.assertRaisesRegex(ValueError, "terminal_ping_count_out_of_range"):
            _validate_terminal_command("ping -n 99 185.238.114.6", {"185.238.114.6"})

    def test_terminal_executes_through_local_cmd_exe(self):
        from types import SimpleNamespace
        cmd_path = r"C:\Windows\System32\cmd.exe"
        with patch("console.gpt_tool_runtime.platform.system", return_value="Windows"), \
             patch("console.gpt_tool_runtime.shutil.which", return_value=cmd_path), \
             patch("console.gpt_tool_runtime.Path.is_file", return_value=True), \
             patch("console.gpt_tool_runtime.subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout=b"CMD OK", stderr=b"")) as run:
            result = _run_terminal("ipconfig /all", set())
        self.assertTrue(result["ok"])
        self.assertEqual(result["shell"], "Windows CMD")
        self.assertEqual(result["execution_host"], "local_windows")
        args = run.call_args.args[0]
        self.assertEqual(args, [cmd_path, "/d", "/s", "/c", "ipconfig /all"])
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_terminal_status_reports_cmd_as_the_execution_shell(self):
        runtime = GPTToolRuntime()
        cmd_path = r"C:\Windows\System32\cmd.exe"
        with patch("console.gpt_tool_runtime.platform.system", return_value="Windows"), \
             patch("console.gpt_tool_runtime.shutil.which", return_value=cmd_path), \
             patch("console.gpt_tool_runtime.Path.is_file", return_value=True):
            result, is_error = runtime.call("terminal_status", {})
        self.assertFalse(is_error)
        self.assertTrue(result["cmd_exe"])
        self.assertEqual(result["terminal"], "Windows CMD")
        self.assertEqual(result["execution_host"], "local_windows")
        self.assertIn("computer_tool_dependencies", result)
        self.assertTrue({
            "psutil", "pyautogui", "pywinauto", "win32com", "playwright",
        }.issubset(result["computer_tool_dependencies"]))
        self.assertIsInstance(result["computer_tool_dependencies_ready"], bool)
        self.assertNotIn("powershell_7", result)

    def test_runtime_does_not_execute_terminal_on_non_windows_host(self):
        runtime = GPTToolRuntime()
        with patch("console.gpt_tool_runtime.platform.system", return_value="Linux"):
            result, is_error = runtime.call(
                "terminal_run", {"command": "ipconfig /all"}
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

    def test_unknown_or_unapproved_tools_are_rejected(self):
        runtime = GPTToolRuntime()
        result, is_error = runtime.call("browser_submit", {"name": "Submit"})
        self.assertTrue(is_error)
        self.assertEqual(result["error"], "gpt_tool_not_registered")


if __name__ == "__main__":
    unittest.main()
