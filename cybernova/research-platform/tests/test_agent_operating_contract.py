"""Regression tests for project operating rules in both local model paths."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
CONSOLE = ROOT / "cybernova" / "research-platform" / "console"


class AgentOperatingContractTests(unittest.TestCase):
    def test_root_agents_file_exists(self):
        content = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("Mandatory preflight", content)
        self.assertIn("Windows CMD", content)
        self.assertIn("18883", content)
        self.assertIn("git reset --hard", content)

    def test_shared_contract_loader_is_bounded(self):
        source = CONSOLE / "operational_contract.py"
        spec = importlib.util.spec_from_file_location("cybernova_operating_contract_test", source)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        contract = module.load_operational_contract()
        self.assertIn("PORT", contract.upper())
        self.assertIn("CMD", contract)
        self.assertIn("Vast", contract)
        self.assertLessEqual(len(contract), 8500)

    def test_deepseek_and_gpt_both_load_contract(self):
        agent = (CONSOLE / "agent_profile.py").read_text(encoding="utf-8")
        gpt = (CONSOLE / "siwc_inference.py").read_text(encoding="utf-8")
        self.assertIn("from .operational_contract import OPERATIONAL_CONTRACT", agent)
        self.assertIn("from .operational_contract import OPERATIONAL_CONTRACT", gpt)
        self.assertIn("    OPERATIONAL_CONTRACT,", agent)
        self.assertIn(' + OPERATIONAL_CONTRACT', gpt)

    def test_safe_update_scripts_keep_no_auto_kill(self):
        cmd = ROOT / "tools" / "windows" / "Update_Cybernova_Safe.cmd"
        ps = ROOT / "tools" / "windows" / "Update_Cybernova_Safe.ps1"
        launcher = cmd.read_text(encoding="utf-8")
        script = ps.read_text(encoding="utf-8")
        self.assertIn("powershell.exe -NoProfile", launcher)
        self.assertIn("Get-NetTCPConnection", script)
        self.assertIn("git merge --ff-only", script)
        self.assertNotIn("Stop-Process", script)
        self.assertNotIn("taskkill", script)
        self.assertNotIn("git reset --hard", script)


if __name__ == "__main__":
    unittest.main()
