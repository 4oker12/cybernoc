#!/usr/bin/env python3
"""Cybernova offline CLI. All commands are dry-run or local analysis; no scanner execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from core.policy import read_json, validate_engagement, validate_catalog, validate_plan, evaluate_action
from core.workflow import load_phases, plan_workflow, validate_workflow
from core.research import (
    asset_inventory, entity_disambiguation, threat_intelligence_review,
    attack_path_model, security_posture_summary,
)

ROOT = Path(__file__).resolve().parent


def _load_list(path: str | None) -> list:
    if not path:
        raise ValueError("Required --input JSON path missing")
    result = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(result, list):
        raise ValueError("--input JSON must be a list")
    return result


def main():
    parser = argparse.ArgumentParser(description="Cybernova offline audit control and WAK research dry-runs")
    parser.add_argument("action", choices=(
        "catalog", "engagement", "check", "plan", "workflow",
        "assets", "entity", "threats", "attack-path", "posture",
    ))
    parser.add_argument("--engagement", default=str(ROOT / "profiles" / "simnet.example.json"))
    parser.add_argument("--catalog", default=str(ROOT / "tools" / "catalog.json"))
    parser.add_argument("--tool")
    parser.add_argument("--url")
    parser.add_argument("--steps", help="JSON file containing a list of planned tool steps")
    parser.add_argument("--workflow", default=str(ROOT / "workflow" / "phases.json"))
    parser.add_argument("--input", help="JSON list with offline observations for assets/entity/threats")
    parser.add_argument("--name", help="Organization name to disambiguate")
    parser.add_argument("--nodes", help="JSON list of finding graph nodes")
    parser.add_argument("--edges", help="JSON list of hypothesis links")
    parser.add_argument("--tests", help="JSON list of scoped test case statuses")
    parser.add_argument("--findings", help="JSON list of evidence-tagged findings")
    args = parser.parse_args()
    catalog = read_json(args.catalog)
    engagement = read_json(args.engagement)

    try:
        if args.action == "catalog":
            errors = validate_catalog(catalog)
            output = {
                "valid": not errors, "errors": errors,
                "count": len(catalog.get("tools", [])),
                "tools": [{"name": t["name"], "status": t["status"], "mode": t["mode"]}
                          for t in catalog["tools"]],
            }
        elif args.action == "engagement":
            errors = validate_engagement(engagement)
            output = {
                "valid": not errors, "errors": errors,
                "status": engagement.get("status"),
                "approved": engagement.get("status") == "approved",
                "note": "Offline validation is not a signed authorization or actual production permission.",
            }
        elif args.action == "check":
            output = evaluate_action(engagement, catalog, args.tool or "", args.url)
        elif args.action == "plan":
            if not args.steps:
                parser.error("--steps is required for plan")
            steps = json.loads(Path(args.steps).read_text(encoding="utf-8"))
            output = validate_plan(engagement, catalog, steps)
        elif args.action == "workflow":
            output = plan_workflow(load_phases(args.workflow), catalog, engagement)
        elif args.action == "assets":
            output = {"ok": True, "execution": "offline", "assets": asset_inventory(_load_list(args.input))}
        elif args.action == "entity":
            output = {"ok": True, "execution": "offline", **entity_disambiguation(
                args.name or "", _load_list(args.input))}
        elif args.action == "threats":
            output = {"ok": True, "execution": "offline", "signals": threat_intelligence_review(
                _load_list(args.input))}
        elif args.action == "attack-path":
            if not args.nodes or not args.edges:
                parser.error("--nodes and --edges are required for attack-path")
            output = {"ok": True, **attack_path_model(
                _load_list(args.nodes), _load_list(args.edges))}
        else:
            if not args.tests or not args.findings:
                parser.error("--tests and --findings are required for posture")
            output = {"ok": True, **security_posture_summary(
                _load_list(args.tests), _load_list(args.findings))}
    except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
        output = {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:200]}

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output.get("ok", output.get("valid", output.get("allowed", False))) else 2


if __name__ == "__main__":
    raise SystemExit(main())
