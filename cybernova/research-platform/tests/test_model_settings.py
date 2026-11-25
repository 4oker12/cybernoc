"""Tests for local, secret-safe active model configuration."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from console.model_settings import (
    ModelSettingsError, apply_model_settings, get_model_settings,
    test_model_connection,
)


class ModelSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        (self.data / "communications.sqlite3").touch()
        (self.data / "runtime.env").write_text(
            "CYBERNOVA_LLM_PROVIDER=ollama\n"
            "CYBERNOVA_MODEL=cybernova-security:30b\n"
            "CYBERNOVA_LLM_BASE_URL=\n"
            "CYBERNOVA_LLM_API_KEY_FILE=\n"
            "CYBERNOVA_OLLAMA_URL=http://127.0.0.1:11434/api/chat\n"
            "CYBERNOVA_COMM_DB=" + str(self.data / "communications.sqlite3") + "\n",
            encoding="utf-8",
        )
        self.env = patch.dict(os.environ, {
            "CYBERNOVA_COMM_DB": str(self.data / "communications.sqlite3"),
            "CYBERNOVA_LLM_PROVIDER": "ollama",
            "CYBERNOVA_MODEL": "cybernova-security:30b",
            "CYBERNOVA_LLM_BASE_URL": "",
            "CYBERNOVA_LLM_API_KEY_FILE": "",
            "CYBERNOVA_OLLAMA_URL": "http://127.0.0.1:11434/api/chat",
            "CYBERNOVA_DEEPSEEK_THINKING": "enabled",
            "CYBERNOVA_DEEPSEEK_REASONING_EFFORT": "high",
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_deepseek_connection_is_verified_before_settings_are_applied(self):
        with patch("console.model_settings.OpenAICompatibleClient") as client_type:
            client_type.return_value.list_models.return_value = ["deepseek-flash"]
            result = test_model_connection({
                "provider": "openai_compatible",
                "model": "deepseek-flash",
                "base_url": "https://api.deepseek.com",
                "api_key": "sk-test-key-value",
            })
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["model"], "deepseek-flash")
        self.assertEqual(client_type.call_args.kwargs["api_key"], "sk-test-key-value")

    def test_deepseek_authentication_error_is_sanitized(self):
        from console.model_providers import ModelConfigError
        with patch("console.model_settings.OpenAICompatibleClient") as client_type:
            client_type.return_value.list_models.side_effect = ModelConfigError("llm_models_http_401")
            with self.assertRaises(ModelSettingsError) as raised:
                test_model_connection({
                    "provider": "openai_compatible",
                    "model": "deepseek-flash",
                    "base_url": "https://api.deepseek.com",
                    "api_key": "sk-secret-not-for-logs",
                })
        self.assertEqual(str(raised.exception), "deepseek_authentication_failed")
        self.assertNotIn("sk-secret-not-for-logs", str(raised.exception))

    def test_remote_key_is_saved_outside_repo_and_never_returned(self):
        client, public = apply_model_settings({
            "provider": "openai_compatible",
            "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com",
            "api_key": "sk-test-key-value",
        })
        self.assertEqual(client.model, "deepseek-chat")
        self.assertTrue(public["api_key_configured"])
        self.assertNotIn("api_key", public)
        self.assertEqual((self.data / "model_api_key").read_text().strip(), "sk-test-key-value")
        self.assertNotIn("sk-test-key-value", (self.data / "runtime.env").read_text())
        self.assertEqual(os.environ["CYBERNOVA_LLM_PROVIDER"], "openai_compatible")

    def test_blank_key_preserves_existing_key(self):
        (self.data / "model_api_key").write_text("sk-existing-secret\n")
        client, public = apply_model_settings({
            "provider": "openai_compatible",
            "model": "deepseek-chat",
            "base_url": "https://api.deepseek.com",
            "api_key": None,
        })
        self.assertEqual(client.model, "deepseek-chat")
        self.assertTrue(public["api_key_configured"])
        self.assertEqual((self.data / "model_api_key").read_text().strip(), "sk-existing-secret")

    def test_remote_provider_requires_key(self):
        with self.assertRaises(ModelSettingsError):
            apply_model_settings({
                "provider": "openai_compatible",
                "model": "deepseek-chat",
                "base_url": "https://api.deepseek.com",
                "api_key": None,
            })

    def test_switch_to_ollama_applies_without_deleting_saved_key(self):
        (self.data / "model_api_key").write_text("sk-existing-secret\n")
        client, public = apply_model_settings({
            "provider": "ollama",
            "model": "cybernova-security:30b",
            "base_url": "",
            "api_key": None,
        })
        self.assertEqual(client.model, "cybernova-security:30b")
        self.assertEqual(os.environ["CYBERNOVA_LLM_PROVIDER"], "ollama")
        self.assertEqual(os.environ["CYBERNOVA_LLM_API_KEY_FILE"], "")
        self.assertEqual((self.data / "model_api_key").read_text().strip(), "sk-existing-secret")

    def test_clear_key_is_explicit(self):
        (self.data / "model_api_key").write_text("sk-existing-secret\n")
        apply_model_settings({
            "provider": "ollama",
            "model": "cybernova-security:30b",
            "base_url": "",
            "api_key": None,
            "clear_api_key": True,
        })
        self.assertFalse((self.data / "model_api_key").exists())

    def test_switch_to_pro_and_max_persists_without_leaking_key(self):
        client, public = apply_model_settings({
            "provider": "openai_compatible",
            "model": "deepseek-v4-pro",
            "base_url": "https://api.deepseek.com",
            "api_key": "sk-test-key-value",
            "reasoning_effort": "max",
        })
        self.assertEqual(client.model, "deepseek-v4-pro")
        self.assertEqual(public["reasoning_effort"], "max")
        config = (self.data / "runtime.env").read_text()
        self.assertIn("CYBERNOVA_MODEL=deepseek-v4-pro", config)
        self.assertIn("CYBERNOVA_DEEPSEEK_THINKING=enabled", config)
        self.assertIn("CYBERNOVA_DEEPSEEK_REASONING_EFFORT=max", config)
        self.assertNotIn("sk-test-key-value", config)
        self.assertEqual(get_model_settings()["reasoning_effort"], "max")
        from portable.native import _load
        self.assertEqual(_load(self.data)["CYBERNOVA_DEEPSEEK_REASONING_EFFORT"], "max")

    def test_off_then_low_reuses_existing_key(self):
        (self.data / "model_api_key").write_text("sk-existing-secret\n")
        common = {"provider": "openai_compatible", "model": "deepseek-flash",
                  "base_url": "https://api.deepseek.com", "api_key": None}
        _, disabled = apply_model_settings({**common, "reasoning_effort": "none"})
        self.assertEqual(disabled["reasoning_effort"], "none")
        self.assertIn("CYBERNOVA_DEEPSEEK_THINKING=disabled",
                      (self.data / "runtime.env").read_text())
        _, low = apply_model_settings({**common, "reasoning_effort": "low"})
        self.assertEqual(low["reasoning_effort"], "low")
        self.assertEqual((self.data / "model_api_key").read_text().strip(),
                         "sk-existing-secret")

    def test_invalid_effort_cannot_change_model_configuration(self):
        before = (self.data / "runtime.env").read_text()
        with self.assertRaises(ModelSettingsError):
            apply_model_settings({
                "provider": "openai_compatible", "model": "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com", "api_key": "sk-test-key-value",
                "reasoning_effort": "ultra",
            })
        self.assertEqual((self.data / "runtime.env").read_text(), before)

    def test_invalid_host_cannot_enable_deepseek_effort(self):
        before = (self.data / "runtime.env").read_text()
        with self.assertRaises(ModelSettingsError):
            apply_model_settings({
                "provider": "openai_compatible", "model": "deepseek-v4-pro",
                "base_url": "https://api.example.com", "api_key": "sk-test-key-value",
                "reasoning_effort": "max",
            })
        self.assertEqual((self.data / "runtime.env").read_text(), before)

    def test_invalid_remote_http_url_is_rejected(self):
        with self.assertRaises(Exception):
            apply_model_settings({
                "provider": "openai_compatible",
                "model": "deepseek-chat",
                "base_url": "http://api.deepseek.com",
                "api_key": "sk-test-key-value",
            })


if __name__ == "__main__":
    unittest.main()
