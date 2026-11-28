"""Tests for observed vs model-declared research state."""
from __future__ import annotations

import sys
import unittest
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.research_progress import (
    ResearchProgress, ResearchProgressStore, MAX_NOTE_CHARS, RESEARCH_STATE_TOOLS,
)


class ResearchProgressTests(unittest.TestCase):
    def test_observation_does_not_set_phase_from_tools(self):
        progress = ResearchProgress(session_key="s1")
        progress.set_goal("Explore example.com login flow")
        progress.record_observation(tool="browser_navigate", ok=True, page_url="https://example.com/login")
        progress.record_observation(tool="browser_snapshot", ok=True, page_url="https://example.com/login")
        progress.record_observation(tool="browser_click_button", ok=False, error="browser_target_stale")
        # Phase remains unknown until the model declares it.
        self.assertEqual(progress.phase, "unknown")
        self.assertEqual(progress.pages_observed, 1)
        self.assertEqual(progress.tools_ok, 2)
        self.assertEqual(progress.tools_failed, 1)
        self.assertEqual(progress.last_tool, "browser_click_button")
        self.assertIn("browser_target_stale", progress.recent_errors)

    def test_model_update_sets_semantic_fields(self):
        progress = ResearchProgress(session_key="s2")
        card = progress.apply_model_update(
            phase="verify",
            summary="Login form requires CSRF token",
            open_items=["confirm token field"],
            findings=["form posts to /session"],
            hypotheses=["token is in hidden input"],
        )
        self.assertEqual(progress.phase, "verify")
        self.assertEqual(card["model"]["phase"], "verify")
        self.assertIn("form posts to /session", card["model"]["findings"])
        progress.apply_model_update(resolve_open=["confirm token field"])
        self.assertEqual(progress.open_items, [])

    def test_system_note_separates_model_and_observed(self):
        progress = ResearchProgress(session_key="s3")
        progress.set_goal("Check headers")
        progress.apply_model_update(phase="explore", summary="starting")
        progress.record_observation(tool="browser_snapshot", ok=True, page_url="https://example.com")
        progress.record_usage({"input_tokens": 100, "output_tokens": 20})
        note = progress.system_note()
        self.assertLessEqual(len(note), MAX_NOTE_CHARS)
        self.assertIn("model_phase=explore", note)
        self.assertIn("observed{", note)
        self.assertIn("last_tool=browser_snapshot", note)

    def test_open_goal_survives_followup_and_completed_goal_can_advance(self):
        p = ResearchProgress(session_key="s")
        p.set_goal("Find products")
        p.apply_model_update(phase="act", open_items=["check price"])
        p.set_goal("Only show available products")
        self.assertEqual(p.goal, "Find products")
        self.assertEqual(p.current_request, "Only show available products")
        p.apply_model_update(phase="done")
        self.assertEqual(p.completion_status(), "declared_done_with_open_items")
        p.apply_model_update(resolve_open=["check price"])
        p.set_goal("Find another category")
        self.assertEqual(p.goal_generation, 2)
        self.assertEqual(p.goal, "Find another category")
        self.assertEqual(p.phase, "unknown")

    def test_browser_check_is_evidence_not_completion_and_invalidates_on_action(self):
        p = ResearchProgress(session_key="s")
        p.set_goal("Find result")
        p.record_observation(tool="browser_verify", ok=True, browser_verified=True)
        self.assertEqual(p.completion_status(), "not_declared_done")
        p.apply_model_update(phase="done")
        self.assertEqual(p.completion_status(), "declared_done_with_observed_browser_check")
        p.record_observation(tool="browser_click_button", ok=True)
        self.assertEqual(p.completion_status(), "declared_done_without_browser_check")

    def test_browser_check_expires_per_turn_while_open_goal_remains(self):
        p = ResearchProgress(session_key="s")
        p.set_goal("Find products")
        p.apply_model_update(phase="verify", open_items=["check price"])
        p.record_observation(tool="browser_verify", ok=True, browser_verified=True)
        p.set_goal("Find products")
        self.assertIsNone(p.last_browser_check)
        p.record_observation(tool="browser_verify", ok=True, browser_verified=False)
        p.set_goal("Only show available products")
        self.assertEqual(p.goal, "Find products")
        self.assertEqual(p.open_items, ["check price"])
        self.assertEqual(p.current_request, "Only show available products")
        self.assertIsNone(p.last_browser_check)

    def test_observation_retains_origin_and_known_error_codes(self):
        p = ResearchProgress(session_key="s")
        p.record_observation(
            tool="browser_navigate", ok=True,
            page_url="https://username:credential@example.test:8443/private-path?token=query#fragment",
        )
        p.record_observation(
            tool="browser_snapshot", ok=True,
            page_url="https://example.test:8443/private-path?token=another-query",
        )
        self.assertEqual(p.pages_observed, 1)
        p.record_observation(
            tool="browser_navigate", ok=False, error="opaque_error_value",
            page_url="https://example.test:8443/next-path",
        )
        p.record_observation(tool="browser_snapshot", ok=False, page_url="javascript:private-payload")
        self.assertEqual(p.pages_observed, 2)
        card = p.ui_card()
        self.assertEqual(card["observed"]["last_page_url"], "https://example.test:8443")
        self.assertEqual(card["observed"]["last_error"], "tool_execution_failed")
        self.assertIn("url=https://example.test:8443", p.system_note())
        for private in (
            "username", "credential", "private-path", "query", "fragment",
            "next-path", "private-payload", "opaque_error_value",
        ):
            self.assertNotIn(private, repr(card))
            self.assertNotIn(private, repr(p))

    def test_invalid_phase_rejected(self):
        progress = ResearchProgress(session_key="s4")
        with self.assertRaises(ValueError):
            progress.apply_model_update(phase="hack")

    def test_tool_schema_present(self):
        self.assertEqual(RESEARCH_STATE_TOOLS[0]["name"], "research_state_update")
        props = RESEARCH_STATE_TOOLS[0]["inputSchema"]["properties"]
        self.assertIn("phase", props)
        self.assertIn("hypotheses", props)

    def test_store_lru(self):
        store = ResearchProgressStore(max_sessions=3)
        for index in range(5):
            store.get(f"session-{index}").set_goal(f"g{index}")
        self.assertIsNone(store.snapshot("session-0"))
        self.assertIsNotNone(store.snapshot("session-4"))


class ChatSessionProgressTests(unittest.TestCase):
    def test_expired_session_cannot_share_progress_with_reused_id(self):
        from console import server

        clock = SimpleNamespace(monotonic=lambda: 100)
        with patch.object(server, "sessions", OrderedDict()), patch.object(server, "time", clock):
            session_id, state = server._session("a" * 32)
            progress = state["research_progress"]
            progress.set_goal("Old goal")
            _, same_state = server._session(session_id)
            self.assertIs(same_state["research_progress"], progress)
            clock.monotonic = lambda: 101 + server.SESSION_TTL_SECONDS
            _, replacement = server._session(session_id)
            progress.set_goal("Late old request")
            self.assertEqual(replacement["research_progress"].goal, "")

    def test_capacity_eviction_and_reset_detach_progress(self):
        from console import server

        with patch.object(server, "sessions", OrderedDict()), patch.object(server, "MAX_SESSIONS", 1):
            session_id, state = server._session("b" * 32)
            state["research_progress"].set_goal("Evicted goal")
            server._session("c" * 32)
            _, replacement = server._session(session_id)
            self.assertEqual(replacement["research_progress"].goal, "")
            replacement["research_progress"].set_goal("Reset goal")
            with patch.object(server, "diagnostic_event"):
                server.reset(server.ResetRequest(session_id=session_id))
            _, reset_state = server._session(session_id)
            self.assertEqual(reset_state["research_progress"].goal, "")


if __name__ == "__main__":
    unittest.main()
