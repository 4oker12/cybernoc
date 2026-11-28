"""Tests for observed vs model-declared research state."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
