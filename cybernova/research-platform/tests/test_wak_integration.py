"""WAK extension has zero network access. All examples are synthetic and unapproved."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.research import (
    asset_inventory, entity_disambiguation, threat_intelligence_review,
    attack_path_model, security_posture_summary
)
from core.workflow import load_phases, validate_workflow, plan_workflow

CATALOG = json.loads((ROOT / "tools" / "catalog.json").read_text(encoding="utf-8"))
DRAFT = json.loads((ROOT / "profiles" / "simnet.example.json").read_text(encoding="utf-8"))


class ResearchTests(unittest.TestCase):
    def test_candidate_assets_are_never_authorized(self):
        candidates = asset_inventory([
            {"hostname": "simnet.ua", "source": "example ct"},
            {"hostname": "SIMNET.UA.", "source": "example archive", "candidate_owner": "Entity A"},
        ])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["authorization"], "not_granted")
        self.assertEqual(len(candidates[0]["sources"]), 2)

    def test_disambiguation_keeps_homonyms_separate(self):
        result = entity_disambiguation("Simnet", [
            {"hostname": "simnet.ua", "source": "public registry", "candidate_owner": "Company A"},
            {"hostname": "simnet.if.ua", "source": "public registry", "candidate_owner": "Company B"},
        ])
        self.assertTrue(result["needs_owner_confirmation"])
        self.assertEqual(len(result["candidate_domains"]), 2)
        self.assertEqual(result["automatically_authorized_assets"], [])

    def test_asset_rejects_invalid_host_and_missing_source(self):
        for item in (
            {"hostname": "localhost", "source": "x"},
            {"hostname": "simnet.ua", "source": ""},
            {"hostname": "https://simnet.ua", "source": "x"},
        ):
            with self.assertRaises(ValueError):
                asset_inventory([item])

    def test_suspicious_does_not_mean_malicious(self):
        out = threat_intelligence_review([
            {"hostname": "example.org", "signal": "ct_change", "source": "offline sample"}
        ])
        self.assertEqual(out[0]["maliciousness"], "unknown")
        self.assertTrue(out[0]["requires_manual_review"])
        self.assertEqual(out[0]["classification"], "unverified_signal")

    def test_threat_rejects_unsourced_claims(self):
        with self.assertRaises(ValueError):
            threat_intelligence_review([
                {"hostname": "example.org", "signal": "typosquat_candidate"}
            ])

    def test_attack_path_remains_hypothesis_without_transition_proof(self):
        nodes = [{"id": "F1", "state": "verified", "evidence_ids": ["E1"]},
                 {"id": "F2", "state": "verified", "evidence_ids": ["E2"]}]
        result = attack_path_model(nodes, [{"from": "F1", "to": "F2"}])
        self.assertFalse(result["chain_verified"])
        self.assertFalse(result["execution_allowed"])

    def test_attack_path_can_be_evidence_backed_but_never_executed(self):
        nodes = [{"id": "F1", "state": "verified", "evidence_ids": ["E1"]},
                 {"id": "F2", "state": "verified", "evidence_ids": ["E2"]}]
        result = attack_path_model(nodes, [
            {"from": "F1", "to": "F2", "transition_evidence_ids": ["E3"]}])
        self.assertTrue(result["chain_verified"])
        self.assertFalse(result["execution_allowed"])

    def test_security_score_not_invented(self):
        result = security_posture_summary([
            {"state": "verified"}, {"state": "not_tested"}, {"state": "blocked_by_scope"}],
            [{"state": "verified", "evidence_ids": ["E1"], "severity": "medium"},
             {"state": "hypothesis", "severity": "critical"}])
        self.assertAlmostEqual(result["coverage"]["percent"], 33.3)
        self.assertEqual(result["verified_risk"]["maximum_severity"], "medium")
        self.assertIsNone(result["overall_security_score"])
        self.assertEqual(result["confidence"]["assessment"], "insufficient_coverage")

    def test_no_tests_yields_unknown_coverage(self):
        result = security_posture_summary([], [])
        self.assertIsNone(result["coverage"]["percent"])
        self.assertIsNone(result["verified_risk"]["maximum_severity"])

    def test_phase_graph_matches_catalog(self):
        phases = load_phases()
        self.assertEqual(len(phases), 12)
        self.assertEqual(validate_workflow(phases, CATALOG), [])

    def test_unknown_tool_is_rejected(self):
        phases = load_phases()
        phases[0]["tools"].append("simnet_only_special_tool")
        self.assertTrue(any("unknown_tool" in e for e in validate_workflow(phases, CATALOG)))

    def test_cycle_is_rejected(self):
        phases = load_phases()
        phases[0]["depends_on"] = ["retest"]
        self.assertTrue(any(e.startswith("cycle:") for e in validate_workflow(phases, CATALOG)))

    def test_draft_cannot_execute_active_workflow(self):
        result = plan_workflow(load_phases(), CATALOG, DRAFT)
        self.assertTrue(result["ok"])
        self.assertEqual(result["execution"], "disabled")
        self.assertTrue(result["authorized_scope_unchanged"])
        assert result["blocked_phases"] > 0
        for p in result["phases"]:
            self.assertFalse(p["automatically_executable"])
        ports = next(p for p in result["phases"] if p["phase"] == "ports")
        self.assertIn("authorization_required", ports["block_reasons"])

    def test_unimplemented_scanners_marked_missing(self):
        result = plan_workflow(load_phases(), CATALOG, DRAFT)
        stage = next(p for p in result["phases"] if p["phase"] == "vulnerability")
        self.assertIn("vulnerability_scan", stage["missing_adapters"])
        self.assertIn("missing_adapters", stage["block_reasons"])


if __name__ == "__main__":
    unittest.main()
