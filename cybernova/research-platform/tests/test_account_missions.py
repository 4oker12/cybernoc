"""Offline tests for durable account mission checkpoints."""
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.account_missions import AccountMissionError, AccountMissionStore


class AccountMissionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "communications.sqlite3"
        self.store = AccountMissionStore(self.db)

    def test_create_checkpoint_and_reopen_survive_process_restart(self):
        mission = self.store.create("AWS", "Create an account and verify access", "Account dashboard is reachable")
        self.store.checkpoint(
            mission["mission_id"], "profile", "Fill registration profile", "completed",
            "Registration profile submitted and dashboard not yet verified",
            "Inspect verification state",
            "https://signin.aws.amazon.com/signup",
        )
        self.store.checkpoint(
            mission["mission_id"], "email", "Confirm email", "waiting_owner",
            "Provider sent a one-time code",
            "Wait for owner code",
            "https://signin.aws.amazon.com/signup",
        )
        reopened = AccountMissionStore(self.db).get(mission["mission_id"])
        self.assertEqual(reopened["status"], "waiting_owner")
        self.assertEqual([x["step_key"] for x in reopened["steps"]], ["profile", "email"])
        self.assertEqual(reopened["steps"][0]["status"], "completed")

    def test_recovery_never_replays_in_flight_step(self):
        mission = self.store.create("AWS", "Create account")
        self.store.checkpoint(
            mission["mission_id"], "submit", "Submit registration", "started",
            "Registration form is ready", "Check result before retry",
        )
        self.assertEqual(self.store.recover_interrupted(), 1)
        recovered = self.store.get(mission["mission_id"])
        self.assertEqual(recovered["status"], "blocked")
        self.assertEqual(recovered["steps"][0]["status"], "needs_reconciliation")
        self.assertTrue(recovered["resume_requires_reconciliation"])
        self.assertEqual(self.store.recover_interrupted(), 0)

    def test_resume_is_explicit_and_does_not_change_checkpoint(self):
        mission = self.store.create("AWS", "Create account")
        self.store.checkpoint(
            mission["mission_id"], "verify", "Verify email", "waiting_owner",
            "Code requested", "Wait for owner",
        )
        resumed = self.store.resume(mission["mission_id"])
        self.assertEqual(resumed["status"], "running")
        self.assertEqual(resumed["steps"][0]["status"], "waiting_owner")

    def test_completed_step_cannot_be_downgraded_by_duplicate_started_event(self):
        mission = self.store.create("AWS", "Create account")
        args = (mission["mission_id"], "submit", "Submit form")
        self.store.checkpoint(*args, "completed", "Form submitted", "")
        duplicate = self.store.checkpoint(*args, "started", "Submit form", "Retry?")
        self.assertEqual(duplicate["steps"][0]["status"], "completed")

    def test_sensitive_values_and_url_query_tokens_are_not_persisted(self):
        mission = self.store.create("AWS", "Create account password=TopSecret123")
        self.store.checkpoint(
            mission["mission_id"], "email", "Confirm email", "waiting_owner",
            "OTP=123456; Authorization=Bearer abcdefghijklmnop",
            "Enter verification code",
            "https://example.com/verify/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?token=secret",
        )
        with closing(sqlite3.connect(self.db)) as db, db:
            rows = db.execute(
                "SELECT goal FROM account_missions UNION ALL "
                "SELECT summary FROM account_mission_steps"
            ).fetchall()
            url = db.execute("SELECT safe_url FROM account_mission_steps").fetchone()[0]
        text = " ".join(row[0] for row in rows)
        self.assertNotIn("TopSecret123", text)
        self.assertNotIn("123456", text)
        self.assertNotIn("abcdefghijklmnop", text)
        self.assertNotIn("token=secret", url)
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url)

    def test_waiting_owner_request_is_marked_lost_after_restart(self):
        mission = self.store.create("AWS", "Create account")
        self.store.checkpoint(
            mission["mission_id"], "otp", "Enter email code", "waiting_owner",
            "Provider requested a one-time code", "Request a fresh code if needed",
        )
        self.assertEqual(self.store.recover_interrupted(), 1)
        recovered = self.store.get(mission["mission_id"])
        self.assertEqual(recovered["status"], "blocked")
        self.assertIn("lost on restart", recovered["next_action"])
        resumed = self.store.resume(mission["mission_id"])
        self.assertEqual(resumed["status"], "running")

    def test_mission_cannot_be_completed_with_unfinished_steps(self):
        mission = self.store.create("AWS", "Create account")
        mission_id = mission["mission_id"]
        self.store.checkpoint(
            mission_id, "profile", "Fill profile", "completed", "Profile verified",
        )
        with self.assertRaisesRegex(AccountMissionError, "completion_requires_verified_step"):
            self.store.checkpoint(
                mission_id, "submit", "Submit registration", "started",
                "Submission about to happen", mission_status="completed",
            )
        self.store.checkpoint(
            mission_id, "submit", "Submit registration", "completed",
            "Dashboard verified", mission_status="completed",
        )
        self.assertEqual(self.store.get(mission_id)["status"], "completed")

    def test_invalid_url_and_status_are_rejected(self):
        mission = self.store.create("AWS", "Create account")
        with self.assertRaises(AccountMissionError):
            self.store.checkpoint(
                mission["mission_id"], "step", "Step", "started", "Summary",
                page_url="http://example.com",
            )
        with self.assertRaises(AccountMissionError):
            self.store.list(status="unknown")


if __name__ == "__main__":
    unittest.main()
