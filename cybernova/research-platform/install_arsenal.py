#!/usr/bin/env python3
"""Cybernova installation manager. Dry-run by default. No scans, targets, sudo or shell injection.

Automates only official ProjectDiscovery Tool Manager candidates.
Other packages must pass upstream, license, version and integrity review first.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "engines" / "manifest.json"
PROFILES = {
    "baseline": ("subfinder", "dnsx", "httpx", "tlsx", "katana"),
    "expanded": ("subfinder", "dnsx", "httpx", "tlsx", "katana",
                 "nuclei", "naabu", "uncover", "interactsh"),
    "inventory": tuple(),
}


def discover_binary(name: str | None) -> str | None:
    if not name:
        return None
    executable = shutil.which(name)
    if executable:
        return executable
    for path in (Path.home() / "go" / "bin" / name,
                 Path.home() / ".pdtm" / "go" / "bin" / name):
        if path.is_file() and path.stat().st_mode & 0o111:
            return str(path)
    return None


def validated_inventory(manifest: dict) -> dict:
    engines = manifest.get("engines")
    if not isinstance(engines, list):
        raise ValueError("Invalid engine manifest")
    names = [e.get("engine") for e in engines]
    if len(names) != len(set(names)) or not all(isinstance(n, str) and n for n in names):
        raise ValueError("Invalid or duplicated engine name")
    return {e["engine"]: e for e in engines}


def build_plan(profile: str, manifest: dict) -> dict:
    inventory = validated_inventory(manifest)
    if profile not in PROFILES and profile != "all":
        raise ValueError("Unknown profile")
    selected = PROFILES.get(profile, tuple(inventory))
    absent = [name for name in selected if name not in inventory]
    if absent:
        raise ValueError("Missing engine definitions: " + str(absent))
    items = []
    for name in selected:
        engine = inventory[name]
        binary = name if engine["installation"] == "pdtm" else None
        installed = discover_binary(binary)
        items.append({
            "engine": name,
            "capability": engine["capability"],
            "risk": engine["risk"],
            "installation": engine["installation"],
            "detected_executable": installed,
            "automatic_install_supported": engine["installation"] == "pdtm",
            "needs_upstream_review": engine["installation"] != "pdtm",
            "execution_enabled": False,
        })
    return {"profile": profile, "mode": "inventory_only_no_changes",
            "selected": len(items), "engines": items}


def _execute_pdtm(plan: dict, *, bootstrap: bool, version: str, acknowledge: bool) -> dict:
    if not acknowledge:
        raise ValueError("Explicit --i-understand-installation required")
    candidates = [e["engine"] for e in plan["engines"]
                  if e["automatic_install_supported"] and not e["detected_executable"]]
    manager = discover_binary("pdtm")
    changes = []
    if candidates and not manager and bootstrap:
        go = discover_binary("go")
        if not go:
            return {"ok": False, "error": "Go missing; install vetted Go toolchain first"}
        if not (version == "latest" or (
              version.lstrip("v").replace(".", "").isdigit() and len(version) < 25)):
            raise ValueError("Invalid pdtm version")
        cmd = [go, "install", "github.com/projectdiscovery/pdtm/cmd/pdtm@" + version]
        result = subprocess.run(cmd, timeout=900, check=False, capture_output=True, text=True)
        changes.append({"operation": "install_pdtm", "argv": cmd, "returncode": result.returncode,
                        "stderr_tail": result.stderr[-1200:]})
        if result.returncode:
            return {"ok": False, "changes": changes}
        manager = discover_binary("pdtm")
    if candidates and not manager:
        return {"ok": False, "error": "pdtm not installed; use --bootstrap-pdtm after Go preflight",
                "candidates": candidates}
    if candidates:
        cmd = [manager, "-i", ",".join(candidates), "-duc"]
        result = subprocess.run(cmd, timeout=1800, check=False, capture_output=True, text=True)
        changes.append({"operation": "install_pdtm_tools", "argv": cmd,
                        "returncode": result.returncode, "stderr_tail": result.stderr[-1200:]})
        if result.returncode:
            return {"ok": False, "changes": changes}
    verified = [{"engine": name, "executable": discover_binary(name)}
                for name in candidates]
    return {"ok": all(v["executable"] for v in verified), "mode": "install_only_no_scan",
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            "changes": changes, "verified_executables": verified,
            "skipped_other_engines": [e["engine"] for e in plan["engines"]
                                      if not e["automatic_install_supported"]]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Cybernova engine inventory / controlled software installation")
    parser.add_argument("--profile", choices=[*PROFILES, "all"], default="baseline")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--apply", action="store_true", help="Install PDTM candidates, never run scanners")
    parser.add_argument("--i-understand-installation", action="store_true")
    parser.add_argument("--bootstrap-pdtm", action="store_true")
    parser.add_argument("--pdtm-version", default="latest")
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    plan = build_plan(args.profile, manifest)
    if args.apply:
        try:
            result = _execute_pdtm(plan, bootstrap=args.bootstrap_pdtm,
                 version=args.pdtm_version, acknowledge=args.i_understand_installation)
        except ValueError as exc:
            result = {"ok": False, "error": str(exc)}
    else:
        result = plan
        result["instruction"] = ("Dry-run. For reviewed PDTM binaries only: "
          "python3 install_arsenal.py --profile baseline --apply "
          "--i-understand-installation --bootstrap-pdtm. "
          "No tool is activated against any target.")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not args.apply or result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
