#!/usr/bin/env python3
"""Offline CLI for Cybernova architecture design (never executes scans)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from core.policy import read_json, validate_engagement, validate_catalog, validate_plan, evaluate_action

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description="Cybernova dry-run policy/catalog inspection")
    parser.add_argument("action", choices=("catalog", "engagement", "check", "plan"))
    parser.add_argument("--engagement", default=str(ROOT / "profiles" / "simnet.example.json"))
    parser.add_argument("--catalog", default=str(ROOT / "tools" / "catalog.json"))
    parser.add_argument("--tool")
    parser.add_argument("--url")
    parser.add_argument("--steps", help="JSON file containing a list of planned steps")
    args = parser.parse_args()
    catalog = read_json(args.catalog)
    if args.action == "catalog":
        output = {"valid": not validate_catalog(catalog),
                  "errors": validate_catalog(catalog),
                  "count": len(catalog.get("tools", [])),
                  "tools": [{"name": t["name"], "status": t["status"], "mode": t["mode"]}
                            for t in catalog["tools"]]}
    else:
        engagement = read_json(args.engagement)
        if args.action == "engagement":
            output = {"valid": not validate_engagement(engagement),
                      "errors": validate_engagement(engagement),
                      "status": engagement.get("status"),
                      "approved": engagement.get("status") == "approved"}
        elif args.action == "check":
            output = evaluate_action(engagement, catalog, args.tool or "", args.url)
        else:
            if not args.steps:
                parser.error("--steps required for plan")
            steps = json.loads(Path(args.steps).read_text(encoding="utf-8"))
            output = validate_plan(engagement, catalog, steps)
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output.get("ok", output.get("valid", output.get("allowed", False))) else 2


if __name__ == "__main__":
    raise SystemExit(main())
