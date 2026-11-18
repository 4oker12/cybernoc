"""Cybernova dry-run authorization policy.

Standard-library only. This module **never** performs any network request or
runs scanners. An executor must recheck this policy and enforce DNS/IP pinning,
redirect boundaries, budgets, and cancellation at the actual connection layer.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

MODES = {"offline": 0, "passive_public": 1, "low_impact_active": 2, "controlled_active": 3}
VALID_STATUSES = {"draft", "approved", "paused", "revoked"}
HOST_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\Z")


def read_json(path: str | Path) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def _time(s: str) -> datetime:
    if not isinstance(s, str):
        raise ValueError("timestamp missing")
    result = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result.astimezone(timezone.utc)


def _hostname(host: str) -> bool:
    if not isinstance(host, str) or not HOST_RE.fullmatch(host.lower()):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        return host.lower() not in {"localhost", "local", "internal"}


def _normalized_url(url: str) -> tuple[dict | None, str]:
    if not isinstance(url, str) or len(url) > 2048 or not url:
        return None, "invalid_url"
    if re.search(r"[\x00-\x20\x7f\\]", url):
        return None, "invalid_url"
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        return None, "invalid_url"
    if u.scheme not in {"http", "https"} or not _hostname(host):
        return None, "unsupported_target"
    if u.username is not None or u.password is not None or u.fragment:
        return None, "unsafe_url"
    default_port = 443 if u.scheme == "https" else 80
    if port is not None and port != default_port:
        return None, "nonstandard_port_requires_separate_executor_policy"
    return {"scheme": u.scheme, "host": host, "path": u.path or "/", "port": default_port}, ""


def _scope_target(engagement: dict, url: str) -> tuple[dict | None, str]:
    parsed, error = _normalized_url(url)
    if error:
        return None, error
    for item in engagement.get("assets", []):
        if not isinstance(item, dict) or item.get("in_scope") is not True:
            continue
        if (item.get("hostname") or "").lower() != parsed["host"]:
            continue
        if parsed["scheme"] not in item.get("schemes", ["https"]):
            continue
        prefixes = item.get("paths", ["/"])
        if not isinstance(prefixes, list) or not prefixes:
            continue
        if any(isinstance(p, str) and p.startswith("/") and (
               p == "/" or parsed["path"] == p or
               parsed["path"].startswith(p.rstrip("/") + "/"))
               for p in prefixes):
            return parsed, ""
    return None, "not_in_approved_scope"


def validate_engagement(e: dict) -> list[str]:
    errors = []
    if e.get("status") not in VALID_STATUSES:
        errors.append("status must be draft, approved, paused, or revoked")
    if not isinstance(e.get("project"), str) or not e.get("project"):
        errors.append("project is required")
    if not isinstance(e.get("assets"), list):
        errors.append("assets must be a list")
    elif not all(isinstance(x, dict) and isinstance(x.get("hostname"), str) and
                 _hostname(x["hostname"]) for x in e["assets"]):
        errors.append("invalid asset hostname")
    if e.get("status") == "approved":
        auth = e.get("authorization", {})
        if not isinstance(auth, dict) or not all(auth.get(k) for k in
                ("reference", "approved_by", "valid_until", "emergency_contact")):
            errors.append("approved engagement requires full authorization")
        else:
            try:
                _time(auth["valid_until"])
            except (TypeError, ValueError):
                errors.append("authorization valid_until must be timezone-aware")
        if e.get("max_mode") not in MODES or e.get("max_mode") == "offline":
            errors.append("approved engagement requires valid max_mode")
    return errors


def evaluate_action(engagement: dict, catalog: dict, tool_name: str,
                    url: str | None = None, now: datetime | None = None) -> dict:
    """Authorization decision only; this is NEVER an executor."""
    names = {t["name"]: t for t in catalog.get("tools", []) if isinstance(t, dict)
             and isinstance(t.get("name"), str)}
    t = names.get(tool_name)
    if t is None:
        return {"allowed": False, "reason": "unknown_tool"}
    if t.get("status") != "deployed_mcp":
        return {"allowed": False, "reason": "not_implemented"}
    risk = t.get("mode")
    if risk not in MODES:
        return {"allowed": False, "reason": "unknown_risk_mode"}
    if risk == "offline":
        return {"allowed": True, "reason": "offline_tool_only"}
    errors = validate_engagement(engagement)
    if errors:
        return {"allowed": False, "reason": "invalid_engagement", "errors": errors}
    if engagement.get("status") != "approved":
        return {"allowed": False, "reason": "authorization_not_approved"}
    if MODES[risk] > MODES.get(engagement.get("max_mode"), -1):
        return {"allowed": False, "reason": "risk_mode_exceeds_approval"}
    when = now or datetime.now(timezone.utc)
    try:
        if when >= _time(engagement["authorization"]["valid_until"]):
            return {"allowed": False, "reason": "authorization_expired"}
    except (KeyError, ValueError, TypeError):
        return {"allowed": False, "reason": "invalid_authorization"}
    if not url:
        return {"allowed": False, "reason": "target_url_required"}
    target, error = _scope_target(engagement, url)
    if error:
        return {"allowed": False, "reason": error}
    if risk == "controlled_active" and engagement.get("enable_active") is not True:
        return {"allowed": False, "reason": "active_testing_not_enabled"}
    return {"allowed": True, "reason": "scope_and_authorization_passed",
            "target": target, "note": "executor must separately enforce DNS, redirects and budgets"}


def validate_plan(engagement: dict, catalog: dict, steps: list[dict]) -> dict:
    if not isinstance(steps, list):
        return {"ok": False, "error": "steps_not_list"}
    results = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            results.append({"index": index, "allowed": False, "reason": "invalid_step"})
            continue
        action = evaluate_action(engagement, catalog, step.get("tool", ""), step.get("url"))
        results.append({"index": index, "tool": step.get("tool"), **action})
    return {"ok": all(x["allowed"] for x in results), "steps": results, "mode": "DRY_RUN_NO_EXECUTION"}


def validate_catalog(catalog: dict) -> list[str]:
    errors, seen = [], set()
    for index, tool in enumerate(catalog.get("tools", [])):
        name = tool.get("name", "")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            errors.append(f"invalid tool name at index {index}")
        if name in seen:
            errors.append(f"duplicate: {name}")
        seen.add(name)
        if tool.get("mode") not in MODES:
            errors.append(f"unknown mode: {name}")
    return errors
