"""Cybernova offline research helpers inspired by WAK. Never fetch URLs or run scanners.

All inputs are third-party observations: source evidence remains untrusted.
None of these functions expands an engagement's authorized scope.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
import re

DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
STATES = {"observed", "hypothesis", "verified", "rejected", "not_tested", "blocked_by_scope"}
TEST_STATES = {"verified", "rejected", "not_tested", "blocked_by_scope"}
RISK_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "unrated": 0}


def _domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("domain must be text")
    value = value.strip().lower().rstrip(".")
    if not DOMAIN.fullmatch(value):
        raise ValueError("invalid DNS name")
    return value


def asset_inventory(observations: list[dict]) -> list[dict]:
    """Deduplicate source-tagged candidates WITHOUT granting any test permission."""
    combined: dict[str, dict] = {}
    if not isinstance(observations, list):
        raise ValueError("observations must be a list")
    for row in observations:
        if not isinstance(row, dict):
            raise ValueError("bad observation")
        host = _domain(row.get("hostname", ""))
        source = row.get("source", "")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("every candidate requires a named source")
        key = host
        if key not in combined:
            combined[key] = {
                "asset_id": sha256(host.encode("ascii")).hexdigest()[:16],
                "hostname": host,
                "ownership": "unverified",
                "authorization": "not_granted",
                "sources": [],
                "candidate_owners": [],
            }
        item = combined[key]
        if source not in item["sources"]:
            item["sources"].append(source[:180])
        owner = str(row.get("candidate_owner") or "").strip()
        if owner and owner not in item["candidate_owners"]:
            item["candidate_owners"].append(owner[:180])
    return sorted(combined.values(), key=lambda x: x["hostname"])


def entity_disambiguation(organization_name: str, observations: list[dict]) -> dict:
    """Create a review queue for same-named organizations; NEVER infer ownership."""
    if not isinstance(organization_name, str) or not organization_name.strip():
        raise ValueError("organization name required")
    inventory = asset_inventory(observations)
    ownership_hints = sorted({o for asset in inventory for o in asset["candidate_owners"]})
    return {
        "query": organization_name.strip(),
        "candidate_domains": inventory,
        "possible_distinct_entities": ownership_hints,
        "needs_owner_confirmation": True,
        "automatically_authorized_assets": [],
        "result_state": "candidate_only",
    }


def threat_intelligence_review(indicators: list[dict]) -> list[dict]:
    """Normalize passive indicator claims; do not assert phishing/compromise."""
    if not isinstance(indicators, list):
        raise ValueError("indicators must be a list")
    out = []
    for row in indicators:
        if not isinstance(row, dict):
            raise ValueError("bad indicator")
        signal = row.get("signal", "")
        source = row.get("source", "")
        domain = _domain(row.get("hostname", ""))
        if signal not in {"ct_change", "typosquat_candidate", "historic_redirect",
                          "third_party_index", "public_leak_mention", "dns_change"}:
            raise ValueError("unsupported threat signal")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source is required")
        out.append({
            "hostname": domain, "signal": signal, "source": source[:180],
            "classification": "unverified_signal",
            "maliciousness": "unknown",
            "requires_manual_review": True,
        })
    return out


def attack_path_model(nodes: list[dict], edges: list[dict]) -> dict:
    """Construct a hypothesis graph, not an execution plan or proven exploit chain."""
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("nodes and edges must be lists")
    status = {}
    result_nodes = []
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise ValueError("node needs string id")
        name = node["id"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name) or name in status:
            raise ValueError("duplicate or unsafe node id")
        state = node.get("state", "hypothesis")
        if state not in STATES:
            raise ValueError("invalid finding state")
        verified = state == "verified" and bool(node.get("evidence_ids"))
        status[name] = verified
        result_nodes.append({"id": name, "state": state,
                             "evidence_backed": verified})
    result_edges = []
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("invalid edge")
        source, target = edge.get("from"), edge.get("to")
        if source not in status or target not in status or source == target:
            raise ValueError("edge refers to unknown or identical node")
        # Dependency between two verified findings does not prove a viable chain.
        result_edges.append({"from": source, "to": target,
                             "state": "hypothesis_until_transition_verified",
                             "transition_evidence_ids": edge.get("transition_evidence_ids", [])})
    return {
        "nodes": result_nodes,
        "edges": result_edges,
        "chain_verified": bool(result_edges) and all(status.values()) and
            all(bool(e["transition_evidence_ids"]) for e in result_edges),
        "execution_allowed": False,
        "note": "Graph representation only; no actual exploit execution.",
    }


def security_posture_summary(test_cases: list[dict], findings: list[dict]) -> dict:
    """Report three axes without a synthetic 0-100 security score."""
    if not isinstance(test_cases, list) or not isinstance(findings, list):
        raise ValueError("invalid inputs")
    counts = Counter()
    for test in test_cases:
        if not isinstance(test, dict):
            raise ValueError("invalid test case")
        state = test.get("state", "not_tested")
        if state not in TEST_STATES:
            raise ValueError("invalid test state")
        counts[state] += 1
    total = sum(counts.values())
    completed = counts["verified"] + counts["rejected"]
    severity_counts = Counter()
    evidence_count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("invalid finding")
        state = finding.get("state")
        if state == "verified" and finding.get("evidence_ids"):
            severity = str(finding.get("severity", "unrated")).lower()
            severity_counts[severity if severity in RISK_RANK else "unrated"] += 1
            evidence_count += 1
    return {
        "coverage": {
            "applicable_tests": total,
            "completed_tests": completed,
            "percent": round(100 * completed / total, 1) if total else None,
            "not_tested": counts["not_tested"],
            "blocked_by_scope": counts["blocked_by_scope"],
        },
        "verified_risk": {
            "findings_by_severity": dict(severity_counts),
            "maximum_severity": max(severity_counts, key=lambda s: RISK_RANK[s])
                if severity_counts else None,
        },
        "confidence": {
            "verified_findings_with_evidence": evidence_count,
            "assessment": "insufficient_coverage" if not total or completed < total
                else "coverage_complete_evidence_still_requires_review",
        },
        "overall_security_score": None,
        "note": "No A/B/C or 100-point rating: incomplete test coverage cannot prove safety.",
    }
