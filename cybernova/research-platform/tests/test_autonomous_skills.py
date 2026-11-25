import unittest
from console.autonomous_skills import select_skill_guidance, FailedCallGuard
from console.profile_settings import default_settings, normalize_settings, mode_instructions_for

class AutonomousSkillsTests(unittest.TestCase):
    def test_selective_guidance(self):
        self.assertEqual(select_skill_guidance("Привет"), "")
        guide = select_skill_guidance("Проверь DNS и VPN")
        self.assertIn("NOC Engineer", guide)
        self.assertNotIn("Software Developer", guide)

    def test_identical_failures_bounded(self):
        guard = FailedCallGuard()
        args = {"url": "https://example.org"}
        guard.record("browser_navigate", args, True)
        self.assertFalse(guard.blocked("browser_navigate", args))
        guard.record("browser_navigate", args, True)
        self.assertTrue(guard.blocked("browser_navigate", args))
        self.assertFalse(guard.blocked("browser_navigate", {"url": "https://example.net"}))
        guard.record("browser_navigate", args, False)
        self.assertFalse(guard.blocked("browser_navigate", args))

    def test_existing_profile_values_preserved(self):
        settings = normalize_settings({"researcher": {"behavior": {"autonomy": 55}}})
        self.assertEqual(settings["researcher"]["behavior"]["autonomy"], 55)
        self.assertEqual(settings["researcher"]["behavior"]["humor"], 25)
        self.assertIn("Неформальность и юмор 25/100", mode_instructions_for(settings, "researcher"))

if __name__ == "__main__":
    unittest.main()
