"""Unit tests for offline safety decisions. No network access."""
import unittest
from datetime import datetime, timezone
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.policy import evaluate_action, validate_catalog, validate_plan, validate_engagement

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "tools" / "catalog.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((ROOT / "profiles" / "simnet.example.json").read_text(encoding="utf-8"))


def approved():
    e = dict(EXAMPLE)
    e["status"] = "approved"
    e["authorization"] = {
        "reference": "LAB-APPROVAL-EXAMPLE-NOT-REAL",
        "approved_by": "Example test owner",
        "valid_until": "2099-01-01T00:00:00Z",
        "emergency_contact": "example internal test contact",
    }
    e["max_mode"] = "low_impact_active"
    e["assets"] = [{"hostname": "simnet.ua", "in_scope": True,
                    "schemes": ["https"], "paths": ["/"]}]
    return e


class PolicyTests(unittest.TestCase):
    def test_catalog_valid_unique(self):
        self.assertEqual(validate_catalog(CATALOG), [])
        self.assertGreaterEqual(len(CATALOG["tools"]), 60)

    def test_draft_blocks_live_get(self):
        self.assertEqual(
            evaluate_action(EXAMPLE, CATALOG, "http_get", "https://simnet.ua/")["reason"],
            "authorization_not_approved")

    def test_offline_is_allowed(self):
        self.assertTrue(evaluate_action(EXAMPLE, CATALOG, "python_static_review")["allowed"])

    def test_planned_tools_are_not_executable(self):
        self.assertEqual(evaluate_action(approved(), CATALOG, "injection_control_test",
                                         "https://simnet.ua/")["reason"], "not_implemented")

    def test_exact_hostname_not_suffix(self):
        self.assertEqual(evaluate_action(approved(), CATALOG, "http_get",
                                          "https://a.simnet.ua/")["reason"], "not_in_approved_scope")

    def test_cross_domain_redirect_would_need_separate_check(self):
        self.assertEqual(evaluate_action(approved(), CATALOG, "http_get",
                                          "https://thirdparty.example/")["reason"], "not_in_approved_scope")

    def test_userinfo_and_nonstandard_port_denied(self):
        for value in ["https://user:pass@simnet.ua/", "https://simnet.ua:8443/",
                      "https://simnet.ua/ok#frag"]:
            self.assertFalse(evaluate_action(approved(), CATALOG, "http_get", value)["allowed"])

    def test_expired_approval_denied(self):
        e = approved()
        e["authorization"]["valid_until"] = "2020-01-01T00:00:00Z"
        self.assertEqual(evaluate_action(e, CATALOG, "http_get",
                         "https://simnet.ua/")["reason"], "authorization_expired")

    def test_not_approved_assets_blocked(self):
        e = approved()
        e["assets"] = EXAMPLE["assets"]
        self.assertFalse(evaluate_action(e, CATALOG, "http_get", "https://simnet.ua/")["allowed"])

    def test_bad_authorization_blocked(self):
        e = approved()
        del e["authorization"]["emergency_contact"]
        self.assertIn("requires full authorization", str(validate_engagement(e)))

    def test_plan_dry_run_blocks_unimplemented(self):
        steps = [{"tool": "python_static_review"},
                 {"tool": "http_get", "url": "https://simnet.ua/"},
                 {"tool": "authorization_matrix_test", "url": "https://simnet.ua/"}]
        result = validate_plan(approved(), CATALOG, steps)
        self.assertFalse(result["ok"])
        self.assertEqual(result["steps"][0]["reason"], "offline_tool_only")
        self.assertEqual(result["steps"][2]["reason"], "not_implemented")


if __name__ == "__main__":
    unittest.main()
