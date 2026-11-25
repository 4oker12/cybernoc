"""Offline tests for per-conversation Chromium session isolation."""
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.gpt_tool_runtime import BrowserSessionPool, GPTToolRuntime


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class FakeBrowserSession:
    def __init__(self, profile_dir=None):
        self.profile_dir = Path(profile_dir) if profile_dir is not None else None
        self.closed = False
        self.authorized_hosts = set()

    def set_authorized_hosts(self, hosts):
        self.authorized_hosts = set(hosts or ())

    def close(self):
        self.closed = True


class BrowserSessionIsolationTests(unittest.TestCase):
    def make_pool(self, root, *, maximum=4, idle=900, clock=None):
        return BrowserSessionPool(
            root, session_factory=FakeBrowserSession,
            max_sessions=maximum, idle_seconds=idle, clock=clock,
        )

    def test_same_conversation_reuses_session_and_hashed_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            pool = self.make_pool(folder)
            key1, first = pool.acquire("siwc:private-thread-123")
            pool.release(key1, first)
            key2, second = pool.acquire("siwc:private-thread-123")
            self.assertEqual(key1, key2)
            self.assertIs(first, second)
            self.assertEqual(first["profile_dir"].parent.name, "conversations")
            self.assertRegex(first["profile_dir"].name, r"^[0-9a-f]{24}$")
            self.assertNotIn("private-thread-123", str(first["profile_dir"]))
            pool.release(key2, second)
            pool.close()
            self.assertTrue(first["session"].closed)

    def test_different_conversations_never_share_browser_or_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            pool = self.make_pool(folder)
            key_a, a = pool.acquire("deepseek:chat-a")
            key_b, b = pool.acquire("deepseek:chat-b")
            self.assertNotEqual(key_a, key_b)
            self.assertIsNot(a["session"], b["session"])
            self.assertNotEqual(a["profile_dir"], b["profile_dir"])
            pool.release(key_a, a)
            pool.release(key_b, b)
            pool.close()

    def test_idle_lru_eviction_closes_oldest_session_without_deleting_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            clock = FakeClock()
            pool = self.make_pool(folder, maximum=2, clock=clock)
            key_a, a = pool.acquire("thread-a")
            pool.release(key_a, a)
            clock.value = 1
            key_b, b = pool.acquire("thread-b")
            pool.release(key_b, b)
            clock.value = 2
            key_a2, a2 = pool.acquire("thread-a")
            pool.release(key_a2, a2)
            clock.value = 3
            key_c, c = pool.acquire("thread-c")
            self.assertTrue(b["session"].closed)
            self.assertFalse(a["session"].closed)
            self.assertFalse(c["session"].closed)
            self.assertEqual(pool.session_count, 2)
            self.assertEqual(b["profile_dir"], b["session"].profile_dir)
            pool.release(key_c, c)
            pool.close()

    def test_active_session_is_not_evicted_to_make_room(self):
        with tempfile.TemporaryDirectory() as folder:
            pool = self.make_pool(folder, maximum=2)
            key_a, a = pool.acquire("active-a")
            key_b, b = pool.acquire("idle-b")
            pool.release(key_b, b)
            key_c, c = pool.acquire("new-c")
            self.assertFalse(a["session"].closed)
            self.assertTrue(b["session"].closed)
            pool.release(key_a, a)
            pool.release(key_c, c)
            pool.close()

    def test_pool_refuses_new_session_when_all_slots_are_active(self):
        with tempfile.TemporaryDirectory() as folder:
            pool = self.make_pool(folder, maximum=1)
            key, active = pool.acquire("active")
            with self.assertRaisesRegex(ValueError, "browser_session_capacity_reached"):
                pool.acquire("second")
            pool.release(key, active)
            pool.close()

    def test_idle_timeout_expires_only_idle_sessions(self):
        with tempfile.TemporaryDirectory() as folder:
            clock = FakeClock()
            pool = self.make_pool(folder, maximum=2, idle=60, clock=clock)
            key, old = pool.acquire("old-thread")
            pool.release(key, old)
            clock.value = 61
            new_key, new = pool.acquire("new-thread")
            self.assertTrue(old["session"].closed)
            self.assertFalse(new["session"].closed)
            pool.release(new_key, new)
            pool.close()

    def test_missing_conversation_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            pool = self.make_pool(folder)
            with self.assertRaisesRegex(ValueError, "browser_conversation_required"):
                pool.acquire(None)
            pool.close()

    def test_runtime_browser_calls_use_distinct_conversation_sessions(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = GPTToolRuntime(
                browser_profile_dir=folder,
                browser_session_factory=FakeBrowserSession,
            )
            observed = []

            def fake_call(name, args, session):
                observed.append((session.profile_dir, set(session.authorized_hosts)))
                return {"ok": True}, False

            with patch("console.gpt_tool_runtime.browser_control_call", side_effect=fake_call):
                for conversation in ("thread-one", "thread-two"):
                    result, failed = runtime.call(
                        "browser_navigate", {"url": "https://example.org/"},
                        conversation_key=conversation,
                        authorized_targets={"example.org"},
                        enabled_groups=["browser"],
                    )
                    self.assertFalse(failed)
                    self.assertTrue(result["ok"])
            self.assertEqual(len(observed), 2)
            self.assertNotEqual(observed[0][0], observed[1][0])
            self.assertEqual(observed[0][1], {"example.org"})
            self.assertEqual(observed[1][1], {"example.org"})
            runtime.close()

    def test_runtime_browser_calls_fail_closed_without_server_conversation_key(self):
        runtime = GPTToolRuntime(browser_session_factory=FakeBrowserSession)
        result, failed = runtime.call(
            "browser_navigate", {"url": "https://example.org/"},
            enabled_groups=["browser"],
        )
        self.assertTrue(failed)
        self.assertTrue(result["error"].endswith("browser_conversation_required"))
        self.assertEqual(runtime._browser_pool.session_count, 0)
        runtime.close()


if __name__ == "__main__":
    unittest.main()
