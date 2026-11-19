"""Safe command-construction and no-network regression tests for lab scanners."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console import lab_scanners
from console.lab_scanners import (
    SCANNER_TOOLS, SCANNER_NAMES, NETWORK_SCANNERS,
    ScannerError, inventory, run_scanner, _plan, _policy
)
from console.agent import Agent
from console.traffic_tools import TrafficToolClient


class FakeUpstream:
    def initialize(self):
        return [{"name": "gateway_status", "inputSchema": {"type": "object", "properties": {}}}]
    def call(self, name, args):
        return {"ok": True, "authorized_hosts": []}, False


class FakeQwen:
    model = "test-qwen"
    def __init__(self, responses):
        self.responses = list(responses)
    def chat(self, messages, tools=None, **kwargs):
        return self.responses.pop(0)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "projects" / "demo").mkdir(parents=True)
        (self.root / "rules" / "nuclei-reviewed").mkdir(parents=True)
        (self.root / "rules" / "semgrep-reviewed").mkdir(parents=True)
        (self.root / "wordlists").mkdir()
        (self.root / "wordlists" / "lab-small.txt").write_text("health\nstatus\n")
        self.policy = self.root / "lab_scope.json"
        self.config = {
            "version": 1, "enabled": True,
            "targets": {"demo": {"url": "http://127.0.0.1:8080/"}},
            "projects": {"code": "demo"},
            "nuclei_templates": "rules/nuclei-reviewed",
            "semgrep_rules": "rules/semgrep-reviewed",
            "ffuf_wordlist": "wordlists/lab-small.txt",
        }
        self.policy.write_text(json.dumps(self.config))
        self.root_patch = patch.object(lab_scanners, "LAB_ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_all_scanner_engines_are_advertised(self):
        names = [x["name"] for x in SCANNER_TOOLS]
        self.assertEqual(len(names), len(SCANNER_NAMES) + 1)  # scanners + inventory
        self.assertIn("lab_zap_active", names)
        self.assertIn("lab_gitleaks", names)
        self.assertIn("lab_bandit", names)
        for tool in SCANNER_NAMES:
            self.assertIn(tool, names)

    def test_default_disabled_no_targets_or_scans(self):
        config = dict(self.config, enabled=False)
        self.policy.write_text(json.dumps(config))
        with patch.dict(os.environ, {"CYBERNOVA_LAB_ISOLATED": "1"}):
            with self.assertRaisesRegex(ScannerError, "lab_scanners_disabled"):
                _policy(self.policy)
            result = inventory(self.policy)
            self.assertEqual(result["target_ids"], [])
            self.assertEqual(result["mode"], "lab_scanners_disabled")

    def test_isolation_flag_required(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ScannerError, "lab_network_isolation_not_attested"):
                _policy(self.policy)

    def test_public_target_always_denied_even_in_enabled_lab(self):
        self.config["targets"] = {"bad": {"url": "https://8.8.8.8:443/"}}
        self.policy.write_text(json.dumps(self.config))
        with patch.dict(os.environ, {"CYBERNOVA_LAB_ISOLATED": "1"}):
            with patch("console.lab_scanners.shutil.which", return_value="/usr/bin/nmap"):
                with self.assertRaisesRegex(ScannerError, "non_lab_ip_forbidden"):
                    with tempfile.TemporaryDirectory() as tmp:
                        _plan("lab_nmap", {"target_id": "bad"}, _policy(self.policy), Path(tmp))

    def test_arbitrary_cli_arguments_and_unlisted_ids_denied(self):
        with patch("console.lab_scanners.shutil.which", return_value="/usr/bin/nmap"):
            with tempfile.TemporaryDirectory() as tmp:
                for args in ({"target_id": "demo", "flags": "-sS"},
                             {"target_id": "not-listed"},
                             {"target_id": "demo;evil"}):
                    with self.assertRaises(ScannerError):
                        _plan("lab_nmap", args, self.config, Path(tmp))

    def test_all_profiles_build_fixed_argument_lists_no_shell(self):
        with patch("console.lab_scanners.shutil.which", side_effect=lambda name: "/usr/bin/" + name):
            with tempfile.TemporaryDirectory() as tmp:
                for name in SCANNER_NAMES:
                    args = {"target_id": "demo"} if name in NETWORK_SCANNERS else {"project_id": "code"}
                    if name == "lab_testssl":
                        # HTTPS requirement is intentional; check with HTTPS fixture.
                        self.config["targets"]["demo"]["url"] = "https://127.0.0.1:8443/"
                    try:
                        plan = _plan(name, args, self.config, Path(tmp))
                    finally:
                        self.config["targets"]["demo"]["url"] = "http://127.0.0.1:8080/"
                    self.assertIsInstance(plan["command"], list)
                    self.assertEqual(plan["target_id"], args.get("target_id", args.get("project_id")))
                    self.assertNotIn("sh", plan)
                    self.assertNotIn("-e", plan["command"])

    def test_zap_active_profile_is_explicit_and_bounded(self):
        with patch("console.lab_scanners.shutil.which", return_value="/usr/bin/zap-full-scan.py"):
            with tempfile.TemporaryDirectory() as tmp:
                plan = _plan("lab_zap_active", {"target_id": "demo"}, self.config, Path(tmp))
        self.assertEqual(plan["command"][0], "/usr/bin/zap-full-scan.py")
        self.assertIn("-m", plan["command"])
        self.assertIn("1", plan["command"])
        self.assertEqual(plan["network"], True)

    def test_gitleaks_summary_never_returns_secret_material(self):
        secret = "ghp_SUPER_SECRET_VALUE_123456"
        report = json.dumps([{
            "RuleID": "github-pat", "File": "/lab/project/config.env",
            "StartLine": 12, "Fingerprint": "abcdef0123456789",
            "Secret": secret, "Match": "TOKEN=" + secret,
        }]).encode()
        result = lab_scanners._summary("lab_gitleaks", "", report)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["rule_id"], "github-pat")
        self.assertNotIn(secret, json.dumps(result))

    def test_bandit_summary_returns_rule_metadata_not_source_lines(self):
        report = json.dumps({"results": [{
            "test_id": "B602", "issue_severity": "HIGH",
            "issue_confidence": "MEDIUM", "filename": "/lab/project/app.py",
            "line_number": 22, "issue_text": "dangerous source line",
            "code": "password = 'do-not-leak'",
        }]}).encode()
        result = lab_scanners._summary("lab_bandit", "", report)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["rule_id"], "B602")
        self.assertNotIn("do-not-leak", json.dumps(result))
        self.assertNotIn("dangerous source line", json.dumps(result))

    def test_mock_nmap_executes_fixed_command_summarizes_xml_without_raw(self):
        commands = []
        xml = ('<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" '
               'portid="8080"><state state="open"/><service name="http"/></port>'
               '</ports></host></nmaprun>')
        def mocked(command, **kwargs):
            commands.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout=xml, stderr="")
        with patch.dict(os.environ, {"CYBERNOVA_LAB_ISOLATED": "1"}):
            with patch("console.lab_scanners.shutil.which", return_value="/usr/bin/nmap"):
                result = run_scanner("lab_nmap", {"target_id": "demo"},
                                     policy_path=self.policy, run=mocked)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0][-1], "127.0.0.1")
        self.assertNotIn("shell", commands[0][1])
        self.assertEqual(result["result"]["finding_count"], 1)
        self.assertEqual(result["result"]["findings"][0]["service"], "http")
        self.assertNotIn(xml, str(result))

    def test_no_approval_no_scanner_invocation(self):
        remote = TrafficToolClient(FakeUpstream(), {})
        model = FakeQwen([
            {"role": "assistant", "content": "", "tool_calls": [
              {"function": {"name": "lab_nmap", "arguments": {"target_id": "demo"}}}]},
            {"role": "assistant", "content": "Нужно разрешение"}
        ])
        with patch("console.lab_scanners.run_scanner") as scanner:
            output = Agent(model, lambda: remote).run([], "Проверь лабораторию")
            scanner.assert_not_called()
        self.assertEqual(output["events"][0]["type"], "approval_required")
        self.assertEqual(output["tool_calls"], 0)
        self.assertEqual(output["approval_requests"][0]["tool"], "lab_nmap")


if __name__ == "__main__":
    unittest.main()
