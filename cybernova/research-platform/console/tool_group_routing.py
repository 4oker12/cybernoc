"""Tool-group inference helpers (shared by agent and server)."""
from __future__ import annotations

import re

# Wired from gpt_tool_runtime after TOOL_GROUP_IDS / normalize_tool_groups exist.
TOOL_GROUP_IDS: frozenset[str] = frozenset()
normalize_tool_groups = None  # type: ignore

_INTENT_GROUP_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        r"(?i)(\u0431\u0440\u0430\u0443\u0437\u0435\u0440|browser|\u0441\u0430\u0439\u0442|site|\u0441\u0442\u0440\u0430\u043d\u0438\u0446|page|\u0440\u0435\u0433\u0438\u0441\u0442\u0440|register|sign.?up|"
        r"\u0441\u043e\u0437\u0434\u0430\u0439.{0,30}\u0430\u043a\u043a\u0430\u0443\u043d\u0442|\u0437\u0430\u0432\u0435\u0434\u0438.{0,30}\u0430\u043a\u043a\u0430\u0443\u043d\u0442|\u0437\u0430\u043f\u043e\u043b\u043d\u0438.{0,20}\u0444\u043e\u0440\u043c|"
        r"form|dom|\u043a\u043d\u043e\u043f\u043a|button|\u043f\u043e\u043b\u0435|input|password|\u043f\u0430\u0440\u043e\u043b|\u043b\u043e\u0433\u0438\u043d|login|"
        r"\u043f\u0435\u0440\u0435\u0439\u0434|navigate|\u043e\u0442\u043a\u0440\u043e\u0439.{0,15}http|\u0441\u043a\u0440\u0438\u043d\u0448\u043e\u0442|screenshot|"
        r"\u0432\u043a\u043b\u0430\u0434\u043a|tab|cookie|\u0441\u0435\u0441\u0441)",
        ("browser",),
    ),
    (
        r"(?i)(\u043a\u043e\u043c\u043f\u044c\u044e\u0442\u0435\u0440|computer|desktop|window|process|service|cpu|ram|disk|defender)",
        ("computer",),
    ),
    (
        r"(?i)(\u0442\u0435\u0440\u043c\u0438\u043d\u0430\u043b|terminal|\bpowershell\b|\bcmd\b|\bshell\b|run\s+command|pwsh\b)",
        ("terminal",),
    ),
    (
        r"(?i)(\u043f\u043e\u0438\u0441\u043a|search|google|research|serp)",
        ("web",),
    ),
    (
        r"(?i)(dns|tls|ssl|network|\bip\b|gateway)",
        ("network",),
    ),
    (
        r"(?i)(\u0441\u043a\u0430\u043d|scan|nuclei|nmap|zap|nikto|trivy|semgrep|gitleaks|bandit|vuln)",
        ("security",),
    ),
    (
        r"(?i)(\bhar\b|traffic|pcap|devtools.?network)",
        ("traffic",),
    ),
    (
        r"(?i)(\u043a\u043e\u0434\b|source\s*code|\bedit\b|unittest|pytest|workspace|dev_|\brepo\b|\bcommit\b|pull\s*request|linter)",
        ("developer", "github"),
    ),
    (
        r"(?i)(github|issue|pull\s*request|\bpr\b|release|actions|collaborator)",
        ("github",),
    ),
)


def bind_routing(*, tool_group_ids, normalize):
    global TOOL_GROUP_IDS, normalize_tool_groups
    TOOL_GROUP_IDS = frozenset(tool_group_ids)
    normalize_tool_groups = normalize


def infer_relevant_tool_groups(user_text: str, *, max_groups: int = 4) -> list[str]:
    text_value = (user_text or "").strip()
    if not text_value or len(text_value) > 8000:
        return []
    matched: list[str] = []
    seen: set[str] = set()
    for pattern, groups in _INTENT_GROUP_PATTERNS:
        if re.search(pattern, text_value):
            for g in groups:
                if g in TOOL_GROUP_IDS and g not in seen:
                    matched.append(g)
                    seen.add(g)
                    if len(matched) >= max_groups:
                        return matched
    return matched


def resolve_tool_groups(user_text: str, explicit_groups=None, *, max_groups: int = 4) -> list[str]:
    if normalize_tool_groups is None:
        raise RuntimeError("tool_group_routing.bind_routing was not called")
    explicit = normalize_tool_groups(explicit_groups or [])
    if explicit:
        return explicit
    inferred = list(infer_relevant_tool_groups(user_text, max_groups=max_groups))
    if not inferred:
        return []
    if "browser" in inferred and "web" not in inferred:
        inferred.append("web")
    if "developer" in inferred and "github" not in inferred:
        inferred.append("github")
    return normalize_tool_groups(inferred)
