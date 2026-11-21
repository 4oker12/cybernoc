"""Offline tests for local Windows computer-use tools."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.computer_control import (
    APP_COMMANDS, COMPUTER_TOOLS, COMPUTER_TOOL_NAMES,
    HIGH_IMPACT_UI, SAFE_UI_CONTROL_TYPES,
    _sensitive_component, _ui_click, extract_user_computer_approvals,
)


class ComputerControlTests(unittest.TestCase):
    def test_computer_tool_catalog_covers_local_management_domains(self):
        names = {item["name"] for item in COMPUTER_TOOLS}
        self.assertTrue({
            "computer_system_overview", "computer_performance_snapshot",
            "computer_process_list", "computer_disk_overview",
            "computer_service_overview", "computer_startup_items",
            "computer_list_directory", "computer_search_files",
            "computer_read_text_file", "computer_open_folder",
            "computer_open_app", "computer_screenshot",
            "computer_ui_windows", "computer_ui_controls", "computer_ui_click",
            "computer_defender_status", "computer_defender_events",
            "computer_defender_scan", "computer_defender_scan_status",
        }.issubset(names))
        self.assertEqual(COMPUTER_TOOL_NAMES, names)

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

    def test_quick_scan_requires_explicit_latest_user_authorization(self):
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
                {"role": "user", "content": "Запусти проверку на вирусы."},
            ]),
            {"defender_quick_scan"},
        )

    def test_full_scan_requires_explicit_full_scan_authorization(self):
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


if __name__ == "__main__":
    unittest.main()
