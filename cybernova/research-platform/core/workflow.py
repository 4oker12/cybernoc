"""WAK-to-Cybernova workflow planner. No network, subprocess, or implicit authorization."""
from __future__ import annotations

from pathlib import Path
import json

MODE_RANK = {"offline": 0, "passive_public": 1, "low_impact_active": 2, "controlled_active": 3}
ROOT = Path(__file__).resolve().parents[1]
PHASES = ROOT / "workflow" / "phases.json"
IMPLEMENTED_STATES = {"deployed_mcp", "implemented_offline_not_deployed"}


def load_phases(path: str | Path = PHASES) -> list[dict]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("phases"), list):
        raise ValueError("workflow document has no phases")
    return value["phases"]


def validate_workflow(phases: list[dict], catalog: dict) -> list[str]:
    """Reject missing tools, cycles, duplicate IDs and malformed phase data."""
    errors = []
    if not isinstance(phases, list):
        return ["phases_not_list"]
    tools = {tool.get("name") for tool in catalog.get("tools", [])
             if isinstance(tool, dict)}
    graph = {}
    for phase in phases:
        if not isinstance(phase, dict):
            errors.append("invalid_phase")
            continue
        phase_id = phase.get("phase")
        if not isinstance(phase_id, str) or not phase_id:
            errors.append("missing_phase_id")
            continue
        if phase_id in graph:
            errors.append(f"duplicate_phase:{phase_id}")
        graph[phase_id] = phase.get("depends_on", [])
        if phase.get("default_mode") not in MODE_RANK:
            errors.append(f"invalid_mode:{phase_id}")
        steps = phase.get("tools")
        if not isinstance(steps, list) or not steps:
            errors.append(f"empty_tools:{phase_id}")
        else:
            for name in steps:
                if name not in tools:
                    errors.append(f"unknown_tool:{phase_id}:{name}")
    for name, dependencies in graph.items():
        if not isinstance(dependencies, list):
            errors.append(f"bad_dependencies:{name}")
        elif any(dep not in graph for dep in dependencies):
            errors.append(f"unknown_dependency:{name}")
    visiting, visited = set(), set()
    def visit(node):
        if node in visiting:
            errors.append(f"cycle:{node}")
            return
        if node in visited:
            return
        visiting.add(node)
        for dep in graph.get(node, []):
            if dep in graph:
                visit(dep)
        visiting.remove(node)
        visited.add(node)
    for name in graph:
        visit(name)
    return sorted(set(errors))


def plan_workflow(phases: list[dict], catalog: dict, engagement: dict) -> dict:
    """Return a useful dry-run, always marking non-ready live phases as blocked."""
    errors = validate_workflow(phases, catalog)
    if errors:
        return {"ok": False, "errors": errors, "execution": "disabled"}
    toolmap = {t["name"]: t for t in catalog["tools"]}
    status = engagement.get("status", "draft")
    max_mode = engagement.get("max_mode", "offline")
    result = []
    for phase in phases:
        mode = phase["default_mode"]
        tool_records = []
        for tool_name in phase["tools"]:
            tool = toolmap[tool_name]
            tool_records.append({"name": tool_name,
                                 "implementation": tool.get("status", "unknown"),
                                 "available_in_live_mcp": tool.get("status") == "deployed_mcp"})
        missing = [t["name"] for t in tool_records
                   if t["implementation"] not in IMPLEMENTED_STATES]
        network_phase = MODE_RANK[mode] > 0
        approval_missing = network_phase and (status != "approved" or
            MODE_RANK[mode] > MODE_RANK.get(max_mode, -1))
        reasons = []
        if missing:
            reasons.append("missing_adapters")
        if approval_missing:
            reasons.append("authorization_required")
        if network_phase:
            reasons.append("executor_scope_and_rate_guards_not_yet_integrated")
        result.append({
            "phase": phase["phase"], "mode": mode,
            "depends_on": phase["depends_on"], "tools": tool_records,
            "missing_adapters": missing, "blocked": bool(reasons),
            "block_reasons": reasons, "automatically_executable": False,
        })
    return {
        "ok": True, "type": "design_dry_run_only", "execution": "disabled",
        "authorized_scope_unchanged": True,
        "phases": result, "blocked_phases": sum(p["blocked"] for p in result),
        "unblocked_offline_design_phases": sum(not p["blocked"] for p in result),
    }
