"""Offline tests for local Windows computer-use tools."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.computer_control import (
    APP_COMMANDS, COMPUTER_TOOLS, COMPUTER_TOOL_NAMES,
    HIGH_IMPACT_UI, SAFE_UI_CONTROL_TYPES,
    _archive_member_path, _explicit_action_approved,
    _sensitive_component, _ui_action_allowed, _validate_ui_target, _ui_click,
    extract_user_computer_approvals, computer_control_call, _service_overview,
)


class ComputerControlTests(unittest.TestCase):
    def test_process_list_accepts_required_limit_argument(self):
        with patch("console.computer_control._process_list",
                   return_value={"ok": True, "count_returned": 3, "processes": []}) as fake:
            result, failed = computer_control_call(
                "computer_process_list", {"limit": 3}
            )
        self.assertFalse(failed)
        self.assertEqual(result["count_returned"], 3)
        fake.assert_called_once_with(3)
        result, failed = computer_control_call("computer_process_list", {})
        self.assertTrue(failed)
        self.assertIn("requires_limit", result["error"])

    def test_service_overview_skips_missing_windows_services(self):
        class FakeService:
            def as_dict(self):
                return {
                    "name": "WinDefend", "display_name": "Microsoft Defender",
                    "status": "running", "start_type": "auto",
                }
        class FakePsutil:
            NoSuchProcess = LookupError
            AccessDenied = PermissionError
            @staticmethod
            def win_service_get(name):
                if name == "WinDefend":
                    return FakeService()
                raise FileNotFoundError("missing from test Windows")
        with (patch("console.computer_control.platform.system", return_value="Windows"),
              patch("console.computer_control.psutil", FakePsutil)):
            result = _service_overview()
        self.assertTrue(result["ok"])
        self.assertEqual(
            [row["name"] for row in result["services"]], ["WinDefend"]
        )
        self.assertGreater(len(result["unavailable"]), 0)

    def test_computer_tool_catalog_covers_local_management_domains(self):
        names = {item["name"] for item in COMPUTER_TOOLS}
        self.assertTrue({
            "computer_system_overview", "computer_performance_snapshot",
            "computer_process_list", "computer_disk_overview",
            "computer_service_overview", "computer_startup_items",
            "computer_list_directory", "computer_search_files",
            "computer_search_everywhere", "computer_read_text_file", "computer_open_folder",
            "computer_open_app", "computer_screenshot",
            "computer_ui_windows", "computer_ui_controls", "computer_ui_inputs",
            "computer_ui_click", "computer_mouse_click", "computer_mouse_scroll",
            "computer_keyboard_type", "computer_keyboard_keypress",
            "computer_defender_status", "computer_defender_events",
            "computer_defender_scan", "computer_defender_scan_status",
            "computer_installed_programs", "computer_power_overview",
            "computer_file_hash", "computer_package_search",
            "computer_package_details", "computer_package_install",
            "computer_archive_inspect", "computer_archive_extract",
            "computer_plan_file_organization", "computer_apply_file_organization",
        }.issubset(names))
        self.assertEqual(COMPUTER_TOOL_NAMES, names)

    def test_mouse_keyboard_actions_require_matching_user_intent(self):
        inspection = [{"role": "user", "content": (
            "Изучи интерфейс AdsPower, ничего не создавай и не изменяй настройки."
        )}]
        self.assertTrue(_ui_action_allowed(inspection, "click"))
        self.assertTrue(_ui_action_allowed(inspection, "scroll"))
        self.assertTrue(_ui_action_allowed(inspection, "key"))
        self.assertFalse(_ui_action_allowed(inspection, "type"))
        self.assertFalse(_ui_action_allowed(
            [{"role": "user", "content": "Не нажимай на вкладки."}], "click",
        ))
        self.assertTrue(_ui_action_allowed(
            [{"role": "user", "content": "Введи название профиля в поле Profile name."}],
            "type",
        ))

    def test_mouse_and_keyboard_targets_reject_sensitive_or_high_impact_controls(self):
        self.assertEqual(_validate_ui_target("Dashboard tab"), "Dashboard tab")
        for target in (
            "Save button", "Delete account", "Password field", "API key input",
            "Create profile", "Add account", "New profile",
        ):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    _validate_ui_target(target)

    def test_computer_schemas_are_strict(self):
        for tool in COMPUTER_TOOLS:
            with self.subTest(tool=tool["name"]):
                schema = tool["inputSchema"]
                self.assertEqual(schema["type"], "object")
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(set(schema["properties"]), set(schema["required"]))

    def test_app_launcher_is_an_allowlist_not_a_command_executor(self):
        self.assertIn("windows_security", APP_COMMANDS)
        self.assertIn("task_manager", APP_COMMANDS)
        self.assertIn("resource_monitor", APP_COMMANDS)
        self.assertNotIn("cmd", APP_COMMANDS)
        self.assertNotIn("powershell", APP_COMMANDS)

    def test_sensitive_directory_and_file_names_are_hidden(self):
        for name in (
            ".ssh", ".aws", "AppData", "gpt-chromium-profile",
            "model_api_key", "web_access.txt", "id_rsa",
            "client-secret.pem", "passwords.txt",
        ):
            with self.subTest(name=name):
                self.assertTrue(_sensitive_component(name))

    def test_destructive_or_security_changing_ui_labels_are_blocked(self):
        for label in (
            "Delete", "Uninstall", "Quick scan", "Full scan", "Apply",
            "Disable protection", "Quarantine", "Save", "Restart",
            "Create profile", "Add account", "New profile",
            "OK", "Yes", "Next", "Continue",
        ):
            with self.subTest(label=label):
                self.assertRegex(label, HIGH_IMPACT_UI)
                with self.assertRaises(ValueError):
                    _ui_click("Windows Security", label, "Button")

    def test_only_navigation_control_types_are_clickable(self):
        self.assertEqual(
            SAFE_UI_CONTROL_TYPES,
            {"Button", "TabItem", "TreeItem", "ListItem", "MenuItem", "Hyperlink"},
        )
        with self.assertRaises(ValueError):
            _ui_click("Settings", "Wi-Fi", "CheckBox")
        with self.assertRaises(ValueError):
            _ui_click("Settings", "Search", "Edit")

    def test_quick_scan_uses_direct_task_intent_without_second_confirmation(self):
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
                {"role": "user", "content": "Запусти проверку на вирусы."},
            ]),
            {"defender_quick_scan"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Не запускай быструю проверку Microsoft Defender."},
            ]),
            set(),
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Не разрешаю полную проверку Microsoft Defender."},
            ]),
            set(),
        )

    def test_package_install_uses_task_intent_without_exact_phrase(self):
        package_id = "VideoLAN.VLC"
        self.assertTrue(_explicit_action_approved(
            [{"role": "user", "content": "Установи VLC"}],
            r"(установ|install)", [package_id],
        ))
        self.assertTrue(_explicit_action_approved(
            [{"role": "user", "content": "Разрешаю установить пакет VideoLAN.VLC из winget."}],
            r"(установ|install)", [package_id],
        ))
        self.assertFalse(_explicit_action_approved(
            [
                {"role": "assistant", "content": "Разрешаешь установить пакет VideoLAN.VLC из winget?"},
                {"role": "user", "content": "Да."},
            ],
            r"(установ|install)", [package_id],
        ))
        self.assertFalse(_explicit_action_approved(
            [
                {"role": "assistant", "content": "Разрешаешь установить пакет VideoLAN.VLC из winget?"},
                {"role": "user", "content": "Да."},
            ],
            r"(установ|install)", ["Other.Publisher.App"],
        ))
        self.assertFalse(_explicit_action_approved(
            [{"role": "user", "content": "Не разрешаю установить пакет VideoLAN.VLC."}],
            r"(установ|install)", [package_id],
        ))
        self.assertFalse(_explicit_action_approved(
            [{"role": "user", "content": "Да, но не устанавливай пакет VideoLAN.VLC."}],
            r"(установ|install)", [package_id],
        ))

    def test_archive_and_file_move_use_direct_task_intent(self):
        source = r"C:\Users\Andrei\Downloads\sample.zip"
        destination = r"C:\Users\Andrei\Documents\Extracted"
        self.assertTrue(_explicit_action_approved(
            [{"role": "user", "content": f"Разрешаю распаковать {source} в {destination}."}],
            r"(распак|extract)", [source, destination],
        ))
        self.assertTrue(_explicit_action_approved(
            [{"role": "user", "content": f"Распакуй {source} в выбранную папку."}],
            r"(распак|extract)", [source, r"C:\Users\Andrei\Desktop\Other"],
        ))
        self.assertFalse(_explicit_action_approved(
            [{"role": "user", "content": f"Не разрешаю распаковать {source} в {destination}."}],
            r"(распак|extract)", [source, destination],
        ))
        self.assertTrue(_explicit_action_approved(
            [{"role": "user", "content":
              f"Разрешаю переместить файлы из {destination} в {source} с группировкой extension."}],
            r"(перемест|move)", [destination, source, "extension"],
        ))

    def test_archive_path_traversal_and_windows_ads_are_blocked(self):
        root = Path("/tmp/cybernova-archive-test")
        for name in ("../escape.txt", r"..\\escape.txt", r"C:\\Windows\\evil.dll",
                     r"\\\\server\\share\\evil.dll", "folder/secret.key"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    _archive_member_path(root, name)
        self.assertEqual(
            _archive_member_path(root, "folder/report.txt"),
            root / "folder" / "report.txt",
        )

    def test_full_scan_and_screenshot_use_direct_task_intent(self):
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Разрешаю полную проверку Microsoft Defender."},
            ]),
            {"defender_full_scan"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Разрешаю сделать снимок экрана и передать его ChatGPT для анализа."},
            ]),
            {"computer_screenshot"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Сделай снимок экрана."},
            ]),
            {"computer_screenshot"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Не разрешаю сделать снимок экрана и передать его ChatGPT для анализа."},
            ]),
            set(),
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Изучи интерфейс AdsPower, ничего не создавай и не изменяй настройки."},
            ]),
            {"computer_screenshot"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Сделай снимок экрана, но не изменяй настройки."},
            ]),
            {"computer_screenshot"},
        )
        self.assertEqual(
            extract_user_computer_approvals([
                {"role": "user", "content": "Не делай снимок экрана, просто прочитай UI Automation."},
            ]),
            set(),
        )
        with patch("console.computer_control._screenshot",
                   return_value={"ok": True, "image_data_url": "data:image/jpeg;base64,AA=="}) as screenshot:
            result, failed = computer_control_call(
                "computer_screenshot", {},
                user_messages=[{"role": "user", "content": "Сделай снимок экрана."}],
            )
        self.assertFalse(failed)
        self.assertTrue(result["ok"])
        screenshot.assert_called_once()
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


if __name__ == "__main__":
    unittest.main()
