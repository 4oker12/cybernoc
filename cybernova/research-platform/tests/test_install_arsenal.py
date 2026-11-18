"""The installer makes no changes or network requests by default."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install_arsenal

ROOT = Path(__file__).resolve().parents[1]
M = json.loads((ROOT / "engines" / "manifest.json").read_text())


class InstallerTests(unittest.TestCase):
    def test_baseline_contains_only_projectdiscovery(self):
        p = install_arsenal.build_plan("baseline", M)
        self.assertEqual(p["selected"], 5)
        self.assertTrue(all(e["installation"] == "pdtm" for e in p["engines"]))
        self.assertFalse(any(e["execution_enabled"] for e in p["engines"]))

    def test_inventory_complete_unique(self):
        inv = install_arsenal.validated_inventory(M)
        self.assertGreaterEqual(len(inv), 100)
        for name in ("reconFTW", "Burp Suite", "SecurityTrails",
                     "Metasploit auxiliary", "nuclei"):
            self.assertIn(name, inv)

    def test_unsupported_engine_is_never_auto_installed(self):
        p = install_arsenal.build_plan("all", M)
        row = next(x for x in p["engines"] if x["engine"] == "Metasploit auxiliary")
        self.assertFalse(row["automatic_install_supported"])

    def test_no_changes_without_explicit_acknowledgment(self):
        p = install_arsenal.build_plan("baseline", M)
        with self.assertRaises(ValueError):
            install_arsenal._execute_pdtm(p, bootstrap=False, version="latest",
                                          acknowledge=False)

    def test_inventory_does_not_call_subprocess(self):
        with patch.object(install_arsenal.subprocess, "run",
                          side_effect=AssertionError("no execution expected")):
            p = install_arsenal.build_plan("all", M)
            self.assertEqual(p["selected"], len(M["engines"]))

    def test_inventory_profile_includes_all_engines_without_execution(self):
        p=install_arsenal.build_plan("inventory",M)
        self.assertEqual(p["selected"],107)
        self.assertFalse(any(x["execution_enabled"] for x in p["engines"]))

    def test_inventory_detects_existing_non_pdtm_binary(self):
        def mock_which(name):
            return "/usr/bin/nmap" if name=="nmap" else None
        with patch.object(install_arsenal, "discover_binary",side_effect=mock_which):
            p=install_arsenal.build_plan("inventory",M)
        nmap=next(x for x in p["engines"] if x["engine"]=="nmap")
        shodan=next(x for x in p["engines"] if x["engine"]=="Shodan")
        self.assertEqual(nmap["detected_executable"],"/usr/bin/nmap")
        self.assertIsNone(shodan["detected_executable"])
        self.assertFalse(nmap["execution_enabled"])

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            install_arsenal.build_plan("attack-simnet", M)

    def test_missing_manager_fails_closed(self):
        with patch.object(install_arsenal, "discover_binary", return_value=None):
            p = install_arsenal.build_plan("baseline", M)
            result = install_arsenal._execute_pdtm(p, bootstrap=False,
                            version="latest", acknowledge=True)
            self.assertFalse(result["ok"])
            self.assertIn("pdtm not installed", result["error"])


if __name__ == "__main__":
    unittest.main()
