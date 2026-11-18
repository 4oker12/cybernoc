"""Initialize an opt-in, isolated Cybernova scanner lab; no network or installs.

Usage:
  python -m console.lab_setup --init
  CYBERNOVA_LAB_SCOPE=/workspace/cybernova-lab/lab_scope.json \
    CYBERNOVA_LAB_ISOLATED=1 python -m console.lab_setup --check

Creating a config does NOT enable the scanners: enabled=false, no targets.
Operator must establish external egress isolation before setting enabled=true.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil

from .lab_scanners import inventory

SOURCE = Path(__file__).resolve().parents[1] / "lab_rules"
ROOT = Path(os.environ.get("CYBERNOVA_LAB_ROOT", "/workspace/cybernova-lab")).resolve()
FILE_MAP = {
    "nuclei-reviewed/header-hsts-check.yaml": "rules/nuclei-reviewed/header-hsts-check.yaml",
    "semgrep-reviewed/python-eval.yaml": "rules/semgrep-reviewed/python-eval.yaml",
    "wordlists/lab-small.txt": "wordlists/lab-small.txt",
}


def initialize(root: Path = ROOT) -> dict:
    root = Path(root).resolve()
    created = []
    (root / "projects").mkdir(parents=True, exist_ok=True)
    for source, destination in FILE_MAP.items():
        source_path = SOURCE / source
        target = root / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(source_path, target)
            created.append(str(target))
    policy = root / "lab_scope.json"
    if not policy.exists():
        policy.write_text(json.dumps({
            "version": 1,
            "enabled": False,
            "targets": {},
            "projects": {},
            "nuclei_templates": "rules/nuclei-reviewed",
            "semgrep_rules": "rules/semgrep-reviewed",
            "ffuf_wordlist": "wordlists/lab-small.txt",
        }, indent=2) + "\n", encoding="utf-8")
        created.append(str(policy))
    return {
        "lab_root": str(root),
        "policy": str(policy),
        "created": created,
        "execution_enabled": False,
        "next_step": "Establish an isolated network and review lab_scope.json, then explicitly enable",
    }


def main():
    parser = argparse.ArgumentParser(description="Cybernova scanner lab initializer/diagnostic")
    opts = parser.add_mutually_exclusive_group(required=True)
    opts.add_argument("--init", action="store_true")
    opts.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = initialize() if args.init else inventory(
        Path(os.environ.get("CYBERNOVA_LAB_SCOPE", str(ROOT / "lab_scope.json")))
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
