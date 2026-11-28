"""P1 Browser Intelligence: site-independent observation, verification and recovery.

Pure functions only (no Playwright objects), so every rule is unit-testable and
no page content, input value or credential can be introduced here. Everything
operates on the already-sanitized snapshot dictionaries produced by
``BrowserSession._snapshot``; it never re-reads the DOM.

Capabilities
------------
* ``page_digest``       - compact, comparable fingerprint of a snapshot.
* ``snapshot_delta``    - what actually changed between two digests.
* ``compact_action_result`` - replaces a full post-action snapshot by a delta
  (large token saving) and states whether any effect was observed.
* ``verify_expectations`` - read-only checks (text present/absent, URL, control)
  that return only booleans/counts, never page content.
* ``recovery_for`` / ``StrategyTracker`` - map stable error codes to concrete,
  ordered alternative strategies and escalate when the same action keeps failing.
"""
from __future__ import annotations

from collections import deque
import difflib
import hashlib
import json
import re

# Tools whose effect is an input value, which snapshots deliberately never echo.
INPUT_TOOLS = frozenset({"browser_fill", "browser_select", "browser_set_checked"})
ACTION_TOOLS = frozenset({
    "browser_click_button", "browser_fill", "browser_select", "browser_set_checked",
    "browser_press", "browser_scroll", "browser_wait",
})
# Tools whose full snapshot must always be returned (they establish a new baseline).
BASELINE_TOOLS = frozenset({
    "browser_navigate", "browser_snapshot", "browser_follow_link", "browser_back",
    "browser_forward", "browser_reload", "browser_new_tab", "browser_switch_tab",
})
MAX_DELTA_ITEMS = 8
MAX_LINE = 200
_CONTROL_LISTS = (("links", "link"), ("buttons", "button"), ("form_fields", "field"))
_WS = re.compile(r"\s+")


def _clip(value, limit=MAX_LINE) -> str:
    text = _WS.sub(" ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def response_mode(raw: str | None) -> str:
    """Return ``compact`` (default) or ``full``; unknown values fall back to compact."""
    return "full" if str(raw or "").strip().lower() == "full" else "compact"


def page_digest(snapshot: dict) -> dict:
    """Fingerprint of a snapshot: url/title, text lines and a keyed control map."""
    lines = [
        _clip(line) for line in str(snapshot.get("visible_text") or "").split("\n")
        if line.strip()
    ]
    controls: dict[tuple, dict] = {}
    for key, kind in _CONTROL_LISTS:
        for item in snapshot.get(key) or ():
            if not isinstance(item, dict):
                continue
            name = _clip(item.get("name") or item.get("label") or item.get("text")
                         or item.get("placeholder") or "", 120)
            ident = (kind, item.get("frame_index", 0), item.get("ref") or item.get("id") or name,
                     item.get("type") or "")
            state = {k: item[k] for k in ("expanded", "checked", "selected", "disabled",
                                            "readonly", "required", "in_viewport") if k in item}
            spatial = item.get("spatial")
            if isinstance(spatial, dict):
                for key in ("focused", "center_hit"):
                    if key in spatial:
                        state[key] = spatial[key]
            controls[ident] = {"kind": kind, "name": name, "id": item.get("id"),
                               "ref": item.get("ref"),
                               "frame_index": item.get("frame_index", 0), "state": state}
    frames = int(snapshot.get("frame_count") or 0)
    tab = snapshot.get("tab")
    coverage = {
        "text_complete": not snapshot.get("text_truncated") and
                         (snapshot.get("text_coverage") or {}).get("complete", True),
        "controls_complete": not snapshot.get("controls_truncated") and
                             snapshot.get("mode", "full") == "full",
    }
    material = json.dumps([lines, snapshot.get("url"), snapshot.get("title"),
                           list(controls.items()), frames, tab, coverage],
                          ensure_ascii=False, sort_keys=True)
    return {
        "url": snapshot.get("url") or "",
        "title": _clip(snapshot.get("title"), 160),
        "lines": lines,
        "controls": controls,
        "frame_count": frames,
        "tab": tab,
        "coverage": coverage,
        "state_id": hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:12],
    }


def _control_view(entry: dict) -> dict:
    view = {"kind": entry["kind"], "name": entry["name"]}
    if entry.get("id"):
        view["id"] = entry["id"]
    if entry.get("ref"):
        view["ref"] = entry["ref"]
    if entry.get("frame_index"):
        view["frame_index"] = entry["frame_index"]
    if entry.get("state"):
        view["state"] = entry["state"]
    return view


def snapshot_delta(before: dict | None, after: dict) -> dict:
    """Describe the observable difference between two digests (bounded size)."""
    if before is None:
        return {"baseline": False, "note": "no_previous_state", "changed": None}
    if before.get("tab") != after.get("tab"):
        return {"baseline": False, "note": "different_tab", "changed": None,
                "state_id": after["state_id"]}
    coverage = {k: bool(before.get("coverage", {}).get(k, True)
                        and after.get("coverage", {}).get(k, True))
                for k in ("text_complete", "controls_complete")}
    matcher = difflib.SequenceMatcher(a=before["lines"], b=after["lines"], autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag in {"replace", "delete"}:
            removed.extend(before["lines"][a0:a1])
        if tag in {"replace", "insert"}:
            added.extend(after["lines"][b0:b1])
    ctrl_added = [k for k in after["controls"] if k not in before["controls"]]
    ctrl_removed = [k for k in before["controls"] if k not in after["controls"]]
    ctrl_state = [
        k for k in after["controls"]
        if k in before["controls"] and before["controls"][k]["state"] != after["controls"][k]["state"]
    ]
    ctrl_renamed = [
        k for k in after["controls"]
        if k in before["controls"] and before["controls"][k]["name"] != after["controls"][k]["name"]
    ]
    url_changed = before["url"] != after["url"]
    title_changed = before["title"] != after["title"]
    frame_changed = before["frame_count"] != after["frame_count"]
    changed = bool(added or removed or ctrl_added or ctrl_removed or ctrl_state
                   or ctrl_renamed or url_changed or title_changed or frame_changed)
    delta: dict = {"changed": changed if changed or all(coverage.values()) else None,
                   "state_id": after["state_id"], "coverage": coverage}
    if not all(coverage.values()):
        delta["note"] = "partial_observation; additions/removals describe observed slices only"
    if frame_changed:
        delta["frame_count_changed"] = {"was": before["frame_count"], "now": after["frame_count"]}
    if url_changed:
        delta["url_changed"] = True
        delta["url"] = after["url"]
    if title_changed:
        delta["title"] = after["title"]
    if added:
        delta["text_added"] = added[:MAX_DELTA_ITEMS]
        delta["text_added_count"] = len(added)
    if removed:
        delta["text_removed"] = removed[:MAX_DELTA_ITEMS]
        delta["text_removed_count"] = len(removed)
    if ctrl_added:
        delta["controls_added"] = [_control_view(after["controls"][k]) for k in ctrl_added[:MAX_DELTA_ITEMS]]
        delta["controls_added_count"] = len(ctrl_added)
    if ctrl_removed:
        delta["controls_removed"] = [_control_view(before["controls"][k]) for k in ctrl_removed[:MAX_DELTA_ITEMS]]
        delta["controls_removed_count"] = len(ctrl_removed)
    if ctrl_renamed:
        # Covers content that is not part of the page text (e.g. Shadow DOM labels).
        delta["controls_renamed"] = [
            {"id": after["controls"][k].get("id"), "was": before["controls"][k]["name"],
             "now": after["controls"][k]["name"]} for k in ctrl_renamed[:MAX_DELTA_ITEMS]
        ]
    if ctrl_state:
        delta["control_state_changed"] = [
            {**_control_view(after["controls"][k]), "was": before["controls"][k]["state"]}
            for k in ctrl_state[:MAX_DELTA_ITEMS]
        ]
    return delta


# Keys that only describe the page bulk; they are dropped from compact results.
_BULK_KEYS = (
    "links", "buttons", "form_fields", "visible_text", "headings", "landmarks",
    "tables", "content_scopes", "content_stats", "focused_elements", "note",
    "browser", "browser_backend", "controls_truncated", "text_truncated", "page_type",
)


def compact_action_result(tool: str, result: dict, before: dict | None) -> tuple[dict, dict | None]:
    """Return ``(result_for_model, new_baseline_digest)``.

    Only successful action results that carry a full snapshot are compacted.
    Everything else (errors, approvals, blocked requests, verification fields set
    by the action such as ``tab_verified``) is passed through unchanged.
    """
    if (tool not in ACTION_TOOLS or not isinstance(result, dict)
            or result.get("ok") is not True or "visible_text" not in result):
        return result, page_digest(result) if isinstance(result, dict) and "visible_text" in result else before
    after = page_digest(result)
    delta = snapshot_delta(before, after)
    compact = {k: v for k, v in result.items() if k not in _BULK_KEYS}
    compact["snapshot_mode"] = "delta"
    compact["delta"] = delta
    if before is None or delta.get("baseline") is False:
        compact["effect"] = "unverified_no_baseline"
    elif delta.get("changed") is True:
        compact["effect"] = "observed"
    elif tool in INPUT_TOOLS:
        compact["effect"] = "input_applied_value_not_echoed"
    elif delta.get("changed") is None:
        compact["effect"] = "unverified_partial_observation"
    elif tool in {"browser_wait", "browser_scroll"}:
        compact["effect"] = "none_observed"
    else:
        compact["effect"] = "none_observed"
    compact["page_state"] = {
        "state_id": after["state_id"], "controls": len(after["controls"]),
        "text_lines": len(after["lines"]), "frames": after["frame_count"],
        "text_truncated": bool(result.get("text_truncated")),
        "controls_truncated": bool(result.get("controls_truncated"))
    }
    if delta.get("changed") is not True and tool in {"browser_click_button", "browser_press"}:
        compact["recovery"] = recovery_for("no_visible_change", tool)
    compact["hint"] = ("Compact delta: call browser_snapshot for the full page, "
                       "browser_find_controls to locate a control.")
    return compact, after


def verify_expectations(snapshot: dict, *, expect_text=None, absent_text=None,
                        url_contains=None, control=None) -> dict:
    """Evaluate read-only expectations. Returns booleans and counts, never page text."""
    haystack = str(snapshot.get("visible_text") or "").casefold()
    text_complete = not snapshot.get("text_truncated") and (
        snapshot.get("text_coverage") or {}
    ).get("complete", True)
    controls_complete = not snapshot.get("controls_truncated") and snapshot.get("mode", "full") == "full"
    checks: list[dict] = []

    def add(kind, passed, **extra):
        checks.append({"check": kind, "passed": passed,
                       "status": "unknown" if passed is None else ("pass" if passed else "fail"), **extra})

    for index, needle in enumerate(expect_text or ()):
        needle = str(needle).strip().casefold()
        found = bool(needle) and needle in haystack
        add("text_present", True if found else (False if not needle or text_complete else None), index=index)
    for index, needle in enumerate(absent_text or ()):
        needle = str(needle).strip().casefold()
        found = bool(needle) and needle in haystack
        add("text_absent", False if not needle or found else (True if text_complete else None), index=index)
    if url_contains:
        add("url_contains", str(url_contains).casefold() in str(snapshot.get("url") or "").casefold())
    if control:
        wanted = str(control).casefold()
        digest = page_digest(snapshot)
        if wanted.startswith("id:"):
            matches = [c for c in digest["controls"].values() if wanted[3:] == str(c.get("id") or "").casefold()]
        elif wanted.startswith("ref:"):
            matches = [c for c in digest["controls"].values() if wanted[4:] == str(c.get("ref") or "").casefold()]
        else:
            matches = [c for c in digest["controls"].values() if wanted in c["name"].casefold()
                       or wanted == str(c.get("id") or "").casefold()]
        add("control_present", True if matches else (False if controls_complete else None), matches=len(matches))
    if not checks:
        raise ValueError("browser_verify_no_expectations")
    passed = all(c["passed"] is True for c in checks)
    return {
        "ok": True, "verified": passed, "checks": checks,
        "failed": [c["check"] for c in checks if c["passed"] is False],
        "unknown": [c["check"] for c in checks if c["passed"] is None],
        "coverage": {"text_complete": bool(text_complete), "controls_complete": bool(controls_complete),
                     "text_scope": (snapshot.get("text_coverage") or {}).get("scope", "observed snapshot text")},
        "url": snapshot.get("url") or "", "title": _clip(snapshot.get("title"), 160),
        "note": "Checks describe observed scope only; unknown is not proof of absence. No page text or input values are echoed.",
    }


_RECOVERY = (
    ("not_unique", ["Narrow the target: use id:<id> from browser_find_controls.",
                    "Add frame/section context with browser_find_controls(query).",
                    "If ids are absent, use browser_find_text then a coordinate-free role+name."]),
    ("not_found", ["Call browser_find_controls with a shorter or alternative query.",
                   "Scroll with browser_scroll or browser_wait for dynamic content, then re-snapshot.",
                   "Check iframes/tabs: browser_tabs and the frame_index values in the snapshot."]),
    ("not_interactable", ["Dismiss overlays/cookie banners, then retry.",
                          "Scroll the element into view (browser_scroll) and re-check enabled state.",
                          "Use the keyboard path (browser_press Tab/Enter) if a custom control swallows clicks."]),
    ("stale", ["The reference is outdated; re-run browser_find_controls and use the new id."]),
    ("no_visible_change", ["Verify with browser_verify instead of repeating the same click.",
                           "Wait 500-1500 ms (browser_wait) in case the update is asynchronous.",
                           "Check browser_network_session for a pending/failed request, then change strategy."]),
    ("timeout", ["Page may still be loading: browser_wait, then browser_snapshot.",
                 "Check browser_network_session for pending or failed requests."]),
    ("access_limited", ["Do not retry the same URL unchanged; report the status code.",
                        "Use an alternative source and label it as separate evidence."]),
    ("approval", ["The action needs owner approval in the chat; do not retry until it is granted."]),
)


def recovery_for(error: str, tool: str = "") -> list[str]:
    code = str(error or "").lower()
    if re.search(r"not_unique:0\b", code):
        return list(dict(_RECOVERY)["not_found"])
    if "no_visible_change" in code:
        return list(dict(_RECOVERY)["no_visible_change"])
    if "not_unique" in code or "ambiguous" in code or "multiple" in code:
        return list(dict(_RECOVERY)["not_unique"])
    if "not_interactable" in code or "not_visible" in code or "disabled" in code or "intercept" in code:
        return list(dict(_RECOVERY)["not_interactable"])
    if "stale" in code or "detached" in code or "widget_target" in code:
        return list(dict(_RECOVERY)["stale"])
    if "not_found" in code or "no_match" in code or "missing" in code or "no_such" in code:
        return list(dict(_RECOVERY)["not_found"])
    if "timeout" in code:
        return list(dict(_RECOVERY)["timeout"])
    if "access_limited" in code:
        return list(dict(_RECOVERY)["access_limited"])
    if "approval" in code or "confirmation" in code or "policy_blocked" in code:
        return list(dict(_RECOVERY)["approval"])
    return ["Re-run browser_snapshot to refresh the page state, then choose a different locator or tool."]


class StrategyTracker:
    """Detects repeated identical failures and escalates the advice.

    Keys contain only the tool name and a short hash of the target, never the
    raw value, so typed secrets cannot be retained here.
    """

    def __init__(self, window: int = 12):
        self._recent: deque[tuple[str, str, str]] = deque(maxlen=window)

    @staticmethod
    def _target_hash(args: dict) -> str:
        target = ""
        if isinstance(args, dict):
            target = str(args.get("name") or args.get("target") or args.get("label") or args.get("query") or "")
        return hashlib.sha256(target.encode("utf-8", "replace")).hexdigest()[:8]

    def record_success(self, tool: str, args: dict) -> None:
        key = (tool, self._target_hash(args))
        self._recent = deque((e for e in self._recent if e[:2] != key), maxlen=self._recent.maxlen)

    def record_failure(self, tool: str, args: dict, error: str) -> dict:
        match = re.search(r"browser_[a-z0-9_]+(?::\d+)?", str(error or ""))
        code = match.group(0)[:80] if match else "browser_execution_failed"
        entry = (tool, self._target_hash(args), code)
        self._recent.append(entry)
        repeats = sum(1 for e in self._recent if e[:2] == entry[:2])
        advice = {"attempts_on_target": repeats, "recovery": recovery_for(error, tool)}
        if repeats >= 3:
            advice["change_strategy"] = True
            advice["escalation"] = ("The same action failed repeatedly. Stop retrying it: refresh with "
                                    "browser_snapshot, try another locator type or tool, and if still blocked "
                                    "report the concrete blocker instead of looping.")
        elif repeats == 2:
            advice["escalation"] = "Second failure on this target: change the locator before retrying."
        return advice
