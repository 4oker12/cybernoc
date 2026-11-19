"""Regression tests for persistent shared and per-mode user profiles."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import server
from console.profile_settings import (
    ProfileSettingsError, ProfileSettingsStore, default_settings,
    mode_instructions_for, user_context_for,
)
from console.siwc_chat_store import GPTChatStore


class ProfileSettingsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.profile_store = ProfileSettingsStore(self.root / "profile_settings.json")
        self.chat_store = GPTChatStore(self.root / "communications.sqlite3")

    def test_defaults_and_atomic_persistence_round_trip(self):
        defaults = self.profile_store.load()
        self.assertEqual(defaults["ui"]["theme"], "light")
        self.assertTrue(defaults["privacy"]["share_with_researcher"])
        defaults["user"]["display_name"] = "Operator"
        saved = self.profile_store.save(defaults)
        reopened = ProfileSettingsStore(self.root / "profile_settings.json")
        self.assertEqual(reopened.load(), saved)
        if __import__("os").name != "nt":
            self.assertEqual((self.root / "profile_settings.json").stat().st_mode & 0o077, 0)

    def test_common_context_is_shared_but_can_be_disabled_per_mode(self):
        settings = default_settings()
        settings["user"].update({
            "display_name": "Operator",
            "role": "ISP NOC",
            "about": "Works with PON and IP networks",
        })
        self.assertIn("ISP NOC", user_context_for(settings, "researcher"))
        self.assertIn("ISP NOC", user_context_for(settings, "chatgpt"))
        settings["privacy"]["share_with_chatgpt"] = False
        self.assertEqual(user_context_for(settings, "chatgpt"), "")
        self.assertIn("ISP NOC", user_context_for(settings, "researcher"))

    def test_mode_instructions_are_separate_and_additive(self):
        settings = default_settings()
        settings["researcher"]["instructions"] = "Сначала изучай архитектуру."
        settings["chatgpt"]["instructions"] = "Отвечай кратко."
        researcher = mode_instructions_for(settings, "researcher")
        chatgpt = mode_instructions_for(settings, "chatgpt")
        self.assertIn("Сначала изучай архитектуру", researcher)
        self.assertNotIn("Отвечай кратко", researcher)
        self.assertIn("Отвечай кратко", chatgpt)
        self.assertNotIn("Сначала изучай архитектуру", chatgpt)
        self.assertIn("не расширяют scope", researcher)

    def test_invalid_settings_are_rejected(self):
        settings = default_settings()
        settings["ui"]["theme"] = "neon"
        with self.assertRaises(ProfileSettingsError):
            self.profile_store.save(settings)
        settings = default_settings()
        settings["user"]["about"] = "x" * 3001
        with self.assertRaises(ProfileSettingsError):
            self.profile_store.save(settings)

    def test_profile_settings_http_api_round_trip(self):
        with patch.object(server, "profile_settings_store", return_value=self.profile_store):
            client = TestClient(server.app, base_url="http://127.0.0.1:18794")
            response = client.get("/api/profile-settings")
            self.assertEqual(response.status_code, 200, response.text)
            settings = response.json()["settings"]
            settings["user"]["display_name"] = "Andrei"
            saved = client.post("/api/profile-settings", json={"settings": settings})
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(saved.json()["settings"]["user"]["display_name"], "Andrei")
            settings["ui"]["theme"] = "neon"
            invalid = client.post("/api/profile-settings", json={"settings": settings})
            self.assertEqual(invalid.status_code, 422)

    def test_chatgpt_receives_shared_profile_and_its_own_prompt(self):
        settings = default_settings()
        settings["user"]["role"] = "ISP NOC"
        settings["chatgpt"]["description"] = "Технический консультант"
        settings["chatgpt"]["instructions"] = "Сначала объясняй причину."
        self.profile_store.save(settings)
        calls = []

        def fake_chat(model, messages, **kwargs):
            calls.append(kwargs)
            return {"answer": "Ответ", "model": model, "source": "test"}

        with patch.object(server, "profile_settings_store", return_value=self.profile_store), \
             patch.object(server, "gpt_chat_store", return_value=self.chat_store), \
             patch.object(server, "chatgpt_chat", side_effect=fake_chat):
            result = server.siwc_chat_message(server.ChatGPTMessageRequest(
                model="gpt-6.2-sol", message="Проверь контекст",
            ))
        self.assertEqual(result["answer"], "Ответ")
        self.assertIn("ISP NOC", calls[0]["user_context"])
        self.assertIn("Технический консультант", calls[0]["profile_instructions"])
        self.assertIn("Сначала объясняй причину", calls[0]["profile_instructions"])


if __name__ == "__main__":
    unittest.main()
