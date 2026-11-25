"""Offline tests for the Account GPT-only local tool runtime."""
from pathlib import Path
import sys
import threading
import time
import unittest
from threading import RLock
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.gpt_tool_runtime import (
    GPTToolRuntime, _run_terminal, _validate_terminal_request, _terminal_argv,
    build_tool_catalog, extract_user_targets, TOOL_GROUPS, normalize_tool_groups,
)
from console.github_tools import GITHUB_NAMES
from console.computer_control import (
    COMPUTER_TOOLS, COMPUTER_TOOL_NAMES, extract_user_computer_approvals,
    _ui_click,
)


class GPTToolRuntimeTests(unittest.TestCase):
    def test_tool_catalog_is_separate_and_includes_intent_gated_submit(self):
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
        self.assertTrue(GITHUB_NAMES.issubset(names))
        from console.github_write_tools import GITHUB_WRITE_NAMES
        self.assertTrue(GITHUB_WRITE_NAMES.issubset(names))
        self.assertIn("browser_submit", names)
        self.assertIn("browser_submit_payment", names)
        self.assertIn("browser_request_and_fill_payment_card", names)
        self.assertTrue({
            "account_mission_create", "account_mission_checkpoint",
            "account_mission_get", "account_mission_list", "account_mission_resume",
            "browser_generate_and_fill_password", "browser_fill_saved_credential",
            "browser_request_and_fill_payment_card", "browser_submit_payment",
            "account_vault_list", "account_vault_mark_verified",
        }.issubset(names))
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

    def test_mcp_adapter_exposes_full_tool_pool_in_automatic_mode(self):
        runtime = GPTToolRuntime()
        catalog_names = {tool["name"] for tool in runtime.tools}
        automatic_names = {row["name"] for row in runtime.mcp_tools()}
        explicit_terminal = {row["name"] for row in runtime.mcp_tools(["terminal"])}
        self.assertEqual(automatic_names, catalog_names)
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
        self.assertIn("account_mission_create", names)
        self.assertIn("account_mission_checkpoint", names)
        self.assertIn("browser_generate_and_fill_password", names)
        self.assertIn("browser_fill_saved_credential", names)
        self.assertIn("browser_request_and_fill_payment_card", names)
        self.assertIn("browser_submit_payment", names)
        self.assertIn("account_vault_list", names)
        self.assertNotIn("computer_system_overview", names)
        self.assertNotIn("terminal_run", names)
        self.assertEqual(
            {row["name"] for row in runtime.mcp_tools(["computer"])},
            COMPUTER_TOOL_NAMES,
        )
        from console.github_write_tools import GITHUB_WRITE_NAMES
        self.assertEqual({row["name"] for row in runtime.mcp_tools(["github"])},
                         GITHUB_NAMES | GITHUB_WRITE_NAMES)
        result, failed = runtime.call(
            "terminal_status", {}, enabled_groups=["browser"]
        )
        self.assertTrue(failed)
        self.assertEqual(result["error"], "tool_group_not_enabled")
        self.assertEqual(len(TOOL_GROUPS), 10)
        with self.assertRaises(ValueError):
            normalize_tool_groups(["not-a-real-tool-group"])

    def test_github_tools_are_read_write_and_enforce_group_selection(self):
        from console.gpt_tool_runtime import tool_group_for_name
        runtime = GPTToolRuntime()
        self.assertEqual(tool_group_for_name("github_list_issues"), "github")
        self.assertEqual(tool_group_for_name("github_api_request"), "github")
        self.assertEqual(tool_group_for_name("github_commit_files"), "github")
        result, failed = runtime.call("github_repo_info", {"repo": "owner/repo"}, enabled_groups=["browser"])
        self.assertTrue(failed)
        self.assertEqual(result["error"], "tool_group_not_enabled")

    def test_account_mission_tools_persist_checkpoints_and_resume_without_replay(self):
        from tempfile import TemporaryDirectory
        from console.account_missions import AccountMissionStore
        from console.gpt_tool_runtime import tool_group_for_name

        with TemporaryDirectory() as root:
            store = AccountMissionStore(Path(root) / "missions.sqlite3")
            runtime = GPTToolRuntime()
            with patch("console.gpt_tool_runtime.account_mission_store", return_value=store):
                created, failed = runtime.call(
                    "account_mission_create",
                    {"service": "AWS", "goal": "Create and verify account",
                     "success_criteria": "Account dashboard is reachable"},
                    enabled_groups=["browser"],
                )
                self.assertFalse(failed)
                mission_id = created["mission"]["mission_id"]
                checkpoint, failed = runtime.call(
                    "account_mission_checkpoint",
                    {"mission_id": mission_id, "step_key": "email",
                     "step_name": "Confirm email", "step_status": "waiting_owner",
                     "summary": "Provider sent a one-time code",
                     "next_action": "Wait for owner code", "page_url": "",
                     "mission_status": ""},
                    enabled_groups=["browser"],
                )
                self.assertFalse(failed)
                self.assertEqual(checkpoint["mission"]["status"], "waiting_owner")
                resumed, failed = runtime.call(
                    "account_mission_resume", {"mission_id": mission_id},
                    enabled_groups=["browser"],
                )
                self.assertFalse(failed)
                self.assertEqual(resumed["mission"]["status"], "running")
                self.assertEqual(resumed["mission"]["steps"][0]["status"], "waiting_owner")
                self.assertEqual(tool_group_for_name("account_mission_get"), "browser")

    def test_generated_and_saved_passwords_never_return_to_the_model(self):
        from threading import RLock

        class FakeSession:
            def __init__(self):
                self.filled = []
            def set_authorized_hosts(self, hosts):
                pass
            def current_origin(self):
                return "https://signin.aws.amazon.com"
            def fill_owner_input(self, label, value, kind, expected_origin=""):
                self.filled.append((label, value, kind, expected_origin))
                return {"ok": True, "visible_text": "Password saved"}

        class FakeVault:
            def __init__(self):
                self.password = None
            def store_password(self, service, username, password, origin, label):
                self.password = password
                return {"record_id": "av_" + "z" * 20, "service": service,
                        "username": username, "origin": origin, "status": "pending"}
            def _secret_for_browser_fill(self, record_id, origin):
                return ({"record_id": record_id, "service": "AWS",
                         "username": "owner@example.net", "origin": origin,
                         "status": "active"}, "ExistingSavedPassword!456")
            def list_entries(self, limit, service):
                return [{"record_id": "av_" + "z" * 20, "service": "AWS"}]
            def mark_verified(self, record_id):
                return {"record_id": record_id, "status": "active"}

        runtime = GPTToolRuntime()
        session = FakeSession()
        vault = FakeVault()
        entry = {"session": session, "call_lock": RLock()}
        with patch.object(runtime._browser_pool, "acquire", return_value=("fake", entry)), \
             patch.object(runtime._browser_pool, "release"), \
             patch("console.gpt_tool_runtime.account_vault", return_value=vault):
            generated, failed = runtime.call(
                "browser_generate_and_fill_password",
                {"service": "AWS", "username": "owner@example.net",
                 "account_label": "personal", "field_label": "Password"},
                conversation_key="deepseek:" + "a" * 32, enabled_groups=["browser"],
                user_messages=[{"role": "user", "content": "Create an AWS account"}],
            )
            self.assertFalse(failed)
            self.assertTrue(generated["password_generated_locally"])
            self.assertEqual(generated["credential_record"]["status"], "pending")
            self.assertNotIn(vault.password, str(generated))
            self.assertEqual(session.filled[-1][1], vault.password)

            saved, failed = runtime.call(
                "browser_fill_saved_credential",
                {"record_id": "av_" + "z" * 20, "field_label": "Password"},
                conversation_key="deepseek:" + "a" * 32, enabled_groups=["browser"],
            )
            self.assertFalse(failed)
            self.assertTrue(saved["saved_credential_filled"])
            self.assertNotIn("ExistingSavedPassword!456", str(saved))
            self.assertEqual(session.filled[-1][1], "ExistingSavedPassword!456")
            self.assertEqual(session.filled[-1][3], "https://signin.aws.amazon.com")

    def test_protected_fill_errors_never_echo_password_values(self):
        from threading import RLock

        captured = {}
        class FakeSession:
            def set_authorized_hosts(self, hosts):
                pass
            def current_origin(self):
                return "https://signin.aws.amazon.com"
            def fill_owner_input(self, label, value, kind, expected_origin=""):
                captured["value"] = value
                raise RuntimeError("Playwright fill failed value=" + value)

        class FakeVault:
            def store_password(self, service, username, password, origin, label):
                return {"record_id": "av_" + "p" * 20, "service": service}

        runtime = GPTToolRuntime()
        entry = {"session": FakeSession(), "call_lock": RLock()}
        with patch.object(runtime._browser_pool, "acquire", return_value=("fake", entry)), \
             patch.object(runtime._browser_pool, "release"), \
             patch("console.gpt_tool_runtime.account_vault", return_value=FakeVault()), \
             patch("console.gpt_tool_runtime.secrets.choice", side_effect=lambda alphabet: alphabet[0]):
            result, failed = runtime.call(
                "browser_generate_and_fill_password",
                {"service": "AWS", "username": "owner@example.net",
                 "account_label": "personal", "field_label": "Password"},
                conversation_key="deepseek:" + "c" * 32, enabled_groups=["browser"],
                user_messages=[{"role": "user", "content": "Create an AWS account"}],
            )
        self.assertTrue(failed)
        self.assertTrue(captured["value"])
        self.assertNotIn(captured["value"], str(result))
        self.assertIn("protected_browser_fill_failed", result["error"])

    def test_payment_card_flow_keeps_card_data_out_of_tool_result(self):
        from console.owner_input import OwnerInputBroker

        runtime = GPTToolRuntime()
        broker = OwnerInputBroker()
        captured = {}
        class FakeSession:
            def set_authorized_hosts(self, hosts):
                pass
            def inspect_payment_form(self):
                return {
                    "ok": True, "origin": "https://signin.aws.amazon.com",
                    "fields": ["card_number", "expiry", "cvv", "cardholder_name"],
                    "field_hosts": {
                        "card_number": "signin.aws.amazon.com",
                        "expiry": "js.stripe.com",
                        "cvv": "js.stripe.com",
                        "cardholder_name": "signin.aws.amazon.com",
                    },
                    "payment_frame_hosts": ["js.stripe.com"],
                }
            def fill_owner_payment_card(self, card, origin, field_hosts, approved_hosts):
                captured.update(card)
                captured["approved_hosts"] = list(approved_hosts)
                return {"ok": True, "payment_card_filled": True,
                        "filled_fields": sorted(field_hosts), "card_data_saved": False}

        entry = {"session": FakeSession(), "call_lock": RLock()}
        session_id = "deepseek:" + "j" * 32
        outcome = {}
        with patch.object(runtime._browser_pool, "acquire", return_value=("fake", entry)), \
             patch.object(runtime._browser_pool, "release"), \
             patch("console.gpt_tool_runtime.owner_input_broker", broker):
            worker = threading.Thread(target=lambda: outcome.update(
                value=runtime.call(
                    "browser_request_and_fill_payment_card",
                    {"purpose": "AWS requires a card to verify the account"},
                    conversation_key=session_id, enabled_groups=["browser"],
                    user_messages=[{"role": "user", "content": "Create an AWS account"}],
                )
            ))
            worker.start()
            deadline = time.monotonic() + 2
            pending = None
            while time.monotonic() < deadline and pending is None:
                pending = broker.pending(session_id)
                time.sleep(0.01)
            self.assertIsNotNone(pending)
            self.assertEqual(pending["input_type"], "payment_card")
            self.assertNotIn("value", pending)
            broker.submit(
                session_id, pending["request_id"],
                payment_card={
                    "card_number": "4242 4242 4242 4242",
                    "expiry_month": "12", "expiry_year": "30",
                    "cvv": "123", "cardholder_name": "Test Owner",
                },
                approved_frame_hosts=["js.stripe.com"],
            )
            worker.join(3)
        self.assertFalse(worker.is_alive())
        result, failed = outcome["value"]
        self.assertFalse(failed)
        self.assertTrue(result["payment_card_filled"])
        self.assertNotIn("4242424242424242", str(result))
        self.assertNotIn("123", str(result))
        self.assertEqual(captured["card_number"], "4242424242424242")
        self.assertEqual(captured["cvv"], "123")
        self.assertEqual(captured["approved_hosts"], ["js.stripe.com"])

    def test_payment_submit_requires_and_consumes_in_chat_confirmation(self):
        from console.owner_input import OwnerInputBroker

        runtime = GPTToolRuntime()
        broker = OwnerInputBroker()
        actions = []
        class FakeSession:
            def set_authorized_hosts(self, hosts):
                pass
            def inspect_submit_target(self, button):
                return {
                    "ok": True, "button": button,
                    "merchant_origin": "https://signin.aws.amazon.com",
                    "action_origin": "https://payments.aws.amazon.com",
                    "payment_target": True,
                }
            def submit_payment_after_owner_approval(self, button, origin, action_origin):
                actions.append((button, origin, action_origin))
                return {"ok": True, "payment_action_submitted": True}

        entry = {"session": FakeSession(), "call_lock": RLock()}
        session_id = "deepseek:" + "k" * 32
        outcome = {}
        with patch.object(runtime._browser_pool, "acquire", return_value=("fake", entry)), \
             patch.object(runtime._browser_pool, "release"), \
             patch("console.gpt_tool_runtime.owner_input_broker", broker):
            worker = threading.Thread(target=lambda: outcome.update(
                value=runtime.call(
                    "browser_submit_payment",
                    {"name": "Verify payment method",
                     "purpose": "AWS may place a temporary authorization; no recurring plan shown"},
                    conversation_key=session_id, enabled_groups=["browser"],
                )
            ))
            worker.start()
            deadline = time.monotonic() + 2
            pending = None
            while time.monotonic() < deadline and pending is None:
                pending = broker.pending(session_id)
                time.sleep(0.01)
            self.assertEqual(pending["input_type"], "payment_confirmation")
            broker.submit(session_id, pending["request_id"], decision=True)
            worker.join(3)
        self.assertFalse(worker.is_alive())
        result, failed = outcome["value"]
        self.assertFalse(failed)
        self.assertTrue(result["payment_action_submitted"])
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0][0], "Verify payment method")

    def test_payment_submit_decline_never_invokes_browser_action(self):
        from console.owner_input import OwnerInputBroker

        runtime = GPTToolRuntime()
        broker = OwnerInputBroker()
        actions = []
        class FakeSession:
            def set_authorized_hosts(self, hosts):
                pass
            def inspect_submit_target(self, button):
                return {"payment_target": True,
                        "merchant_origin": "https://signin.aws.amazon.com",
                        "action_origin": "https://payments.aws.amazon.com"}
            def submit_payment_after_owner_approval(self, *args):
                actions.append(args)
                return {"ok": True}

        entry = {"session": FakeSession(), "call_lock": RLock()}
        session_id = "deepseek:" + "l" * 32
        outcome = {}
        with patch.object(runtime._browser_pool, "acquire", return_value=("fake", entry)), \
             patch.object(runtime._browser_pool, "release"), \
             patch("console.gpt_tool_runtime.owner_input_broker", broker):
            worker = threading.Thread(target=lambda: outcome.update(
                value=runtime.call(
                    "browser_submit_payment",
                    {"name": "Verify payment method", "purpose": "Temporary card authorization"},
                    conversation_key=session_id, enabled_groups=["browser"],
                )
            ))
            worker.start()
            deadline = time.monotonic() + 2
            pending = None
            while time.monotonic() < deadline and pending is None:
                pending = broker.pending(session_id)
                time.sleep(0.01)
            broker.submit(session_id, pending["request_id"], decision=False)
            worker.join(3)
        self.assertFalse(worker.is_alive())
        result, failed = outcome["value"]
        self.assertTrue(failed)
        self.assertEqual(result["status"], "owner_declined_payment_action")
        self.assertEqual(actions, [])

    def test_generated_password_requires_explicit_account_creation_intent(self):
        runtime = GPTToolRuntime()
        result, failed = runtime.call(
            "browser_generate_and_fill_password",
            {"service": "AWS", "username": "owner@example.net",
             "account_label": "personal", "field_label": "Password"},
            conversation_key="deepseek:" + "b" * 32,
            enabled_groups=["browser"],
            user_messages=[{"role": "user", "content": "Inspect this login page"}],
        )
        self.assertTrue(failed)
        self.assertEqual(result["error"], "account_creation_intent_required")

    def test_account_vault_metadata_tools_do_not_expose_passwords(self):
        class FakeVault:
            def list_entries(self, limit, service):
                return [{"record_id": "av_" + "q" * 20, "service": service}]
            def mark_verified(self, record_id):
                return {"record_id": record_id, "status": "active"}

        runtime = GPTToolRuntime()
        with patch("console.gpt_tool_runtime.account_vault", return_value=FakeVault()):
            listed, failed = runtime.call(
                "account_vault_list", {"service": "AWS", "limit": 10},
                enabled_groups=["browser"],
            )
            self.assertFalse(failed)
            self.assertEqual(listed["entries"][0]["service"], "AWS")
            verified, failed = runtime.call(
                "account_vault_mark_verified", {"record_id": "av_" + "q" * 20},
                enabled_groups=["browser"],
            )
            self.assertFalse(failed)
            self.assertEqual(verified["entry"]["status"], "active")

    def test_browser_fill_mcp_accepts_optional_fields_without_changing_strict_gpt(self):
        from console.tool_policy import validate_dynamic_arguments
        runtime = GPTToolRuntime()
        try:
            schema = next(row["inputSchema"] for row in runtime.mcp_tools(["browser"])
                          if row["name"] == "browser_fill")
            supplied = {"target": "Display name", "value": "Synthetic"}
            self.assertEqual(validate_dynamic_arguments(supplied, schema), supplied)
            strict_schema = runtime.tool_map["browser_fill"]["parameters"]
            self.assertEqual(set(strict_schema["required"]), set(strict_schema["properties"]))
        finally:
            runtime.close()

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

    def test_defender_scan_uses_direct_user_task_intent_without_second_confirmation(self):
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Можешь проверить ноут на вирусы?"},
            ]),
            {"defender_quick_scan"},
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

    def test_terminal_run_is_available_in_automatic_mode(self):
        runtime = GPTToolRuntime()
        self.assertIn("terminal_run", {row["name"] for row in runtime.mcp_tools()})
        self.assertEqual(runtime.explicit_only_tools, ())
        result, failed = runtime.call(
            "terminal_run", {
                "command": "whoami", "shell": "cmd", "cwd": "",
                "timeout_seconds": 30, "max_output_chars": 20000,
            }, enabled_groups=["browser"]
        )
        self.assertTrue(failed)
        self.assertEqual(result["error"], "tool_group_not_enabled")

    def test_unknown_or_unapproved_tools_are_rejected(self):
        runtime = GPTToolRuntime()
        result, is_error = runtime.call("browser_submit", {"name": "Submit"})
        self.assertTrue(is_error)
        self.assertEqual(result["error"], "browser_submit_requires_explicit_user_intent")


if __name__ == "__main__":
    unittest.main()
