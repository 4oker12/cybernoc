"""Policy for autonomous tool selection and task-intent gating.

All tools registered by the owner-configured local MCP gateway are executable
without per-call approval after strict schema validation. Only high-impact
operations need matching intent in the current user task.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib import parse

MAX_ADVERTISED = 128
MAX_ARGUMENT_BYTES = 8192
MAX_VALUE_LENGTH = 4096
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,79}$")
SECRET_RE = re.compile(r"(?i)(?:password|passwd|secret|token|api.?key|cookie|authorization|credential|private.?key)")
REVIEWED_OFFLINE = frozenset({
    "gateway_status", "python_static_review", "http_header_review",
    "ip_network_summary", "local_webui_health",
    # Per-chat Traffic Intelligence (offline, sanitized, no network).
    "traffic_inventory", "traffic_api_map", "traffic_js_review",
    "traffic_session_review", "traffic_graph", "traffic_hypotheses",
    "traffic_report", "traffic_compare",
    "research_capabilities", "research_artifacts", "research_openapi_routes",
    "research_authorization_matrix", "research_network_packets",
    "research_network_logs", "research_server_config", "research_code_review",
    "research_dependencies", "research_tls_review", "research_findings",
    "research_next_steps", "research_full_report",
    "lab_scanner_inventory",
    "safe_terminal",
    "comm_request_review", "comm_post_progress", "comm_read_dialog",
    "comm_record_evidence",
    # Coding agent: edits and commits only in a separate Qwen task worktree.
    "dev_workspace", "dev_list", "dev_read", "dev_search",
    "dev_edit", "dev_delete", "dev_move", "dev_diff", "dev_test", "dev_commit",
    "dev_command", "dev_push", "dev_open_pr",
})
REVIEWED_SCOPED = frozenset({
    "http_get", "scoped_dns_resolve", "scoped_tls_inspect",
    "browser_open", "browser_network",
    # Public read-only web research: Google SERP and one public HTTPS source page.
    "google_search", "research_source_open",
})
try:
    from .computer_control import COMPUTER_TOOL_NAMES
    from .browser_control import BROWSER_CONTROL_TOOLS
    from .github_tools import GITHUB_NAMES
    from .github_write_tools import GITHUB_WRITE_NAMES
except ImportError:
    from computer_control import COMPUTER_TOOL_NAMES
    from browser_control import BROWSER_CONTROL_TOOLS
    from github_tools import GITHUB_NAMES
    from github_write_tools import GITHUB_WRITE_NAMES

# Shared local tools are safe-by-default or enforce their own exact-action
# authorization inside the controller (Defender scan, package install,
# archive extraction and file moves). They therefore do not need a second,
# model-specific generic approval layer.
SHARED_LOCAL_TOOLS = (
    COMPUTER_TOOL_NAMES
    | frozenset(item["name"] for item in BROWSER_CONTROL_TOOLS)
    | frozenset({"terminal_run", "terminal_status"})
    | GITHUB_NAMES | GITHUB_WRITE_NAMES
)
REVIEWED_TOOLS = REVIEWED_OFFLINE | REVIEWED_SCOPED | SHARED_LOCAL_TOOLS


class ToolPolicyError(ValueError):
    pass


def discovered_tools(rows: object) -> list[dict]:
    if not isinstance(rows, list):
        raise ToolPolicyError("tools/list must be a list")
    found: list[dict] = []
    seen = set()
    for raw in rows[:MAX_ADVERTISED]:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        schema = raw.get("inputSchema")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name in seen:
            continue
        # A callable unreviewed tool must advertise argument shape to enable
        # even *approved* dispatch. It can still be shown with a fallback.
        if not isinstance(schema, dict) or schema.get("type") != "object":
            schema = {"type": "object", "properties": {}, "additionalProperties": False}
        found.append({
            "name": name,
            "description": str(raw.get("description") or "")[:400],
            "inputSchema": schema,
        })
        seen.add(name)
    return found


def model_tools(rows: object) -> list[dict]:
    """Return all actual MCP functions, not a six-name allowlist."""
    return [{
        "type": "function",
        "function": {
            "name": item["name"],
            "description": item["description"] + (
                " [Autonomous when relevant. High-impact actions require matching intent in the current user task.]"
                if item["name"] not in REVIEWED_TOOLS else ""
            ),
            "parameters": item["inputSchema"],
        },
    } for item in discovered_tools(rows)]


def _json_depth(item, depth=0, max_value_length=MAX_VALUE_LENGTH) -> None:
    if depth > 8:
        raise ToolPolicyError("tool_arguments_too_deep")
    if isinstance(item, dict):
        if len(item) > 60:
            raise ToolPolicyError("tool_arguments_too_many_keys")
        for key, value in item.items():
            if not isinstance(key, str) or len(key) > 90:
                raise ToolPolicyError("tool_argument_key_invalid")
            _json_depth(value, depth + 1, max_value_length)
    elif isinstance(item, list):
        if len(item) > 80:
            raise ToolPolicyError("tool_arguments_too_many_items")
        for value in item:
            _json_depth(value, depth + 1, max_value_length)
    elif not (item is None or isinstance(item, (str, int, float, bool))):
        raise ToolPolicyError("tool_arguments_non_json_value")
    elif isinstance(item, str) and len(item) > max_value_length:
        raise ToolPolicyError("tool_argument_value_too_large")


def validate_dynamic_arguments(raw: object, schema: dict, *,
                               max_argument_bytes: int = MAX_ARGUMENT_BYTES,
                               max_value_length: int = MAX_VALUE_LENGTH) -> dict:
    """Validate argument shape and types before autonomous MCP execution.

    Schema validation is mandatory. Execution policy is evaluated separately:
    routine connected tools run automatically; high-impact tools require direct
    intent in the current user task. Only declared keys are accepted.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise ToolPolicyError("tool_arguments_not_json") from exc
    if not isinstance(raw, dict):
        raise ToolPolicyError("tool_arguments_not_object")
    _json_depth(raw, max_value_length=max_value_length)
    if len(json.dumps(raw, ensure_ascii=False).encode()) > max_argument_bytes:
        raise ToolPolicyError("tool_arguments_too_large")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ToolPolicyError("tool_schema_not_supported")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ToolPolicyError("tool_schema_not_supported")
    unexpected = set(raw) - set(properties)
    if unexpected:
        raise ToolPolicyError("unexpected_tool_arguments")
    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(k, str) for k in required):
        raise ToolPolicyError("tool_schema_not_supported")
    if set(required) - set(raw):
        raise ToolPolicyError("missing_required_tool_arguments")
    expected_types = {
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "null": lambda v: v is None,
    }
    for key, value in raw.items():
        prop = properties.get(key)
        if not isinstance(prop, dict):
            raise ToolPolicyError("invalid_tool_parameter_schema")
        defined = prop.get("type")
        if isinstance(defined, str):
            expected = [defined]
        elif isinstance(defined, list):
            expected = defined
        else:
            raise ToolPolicyError("untyped_tool_parameter")
        if not all(isinstance(t, str) and t in expected_types for t in expected):
            raise ToolPolicyError("unsupported_tool_parameter_type")
        if not any(expected_types[t](value) for t in expected):
            raise ToolPolicyError("invalid_argument_" + key)
        if "enum" in prop and value not in prop["enum"]:
            raise ToolPolicyError("invalid_enum_" + key)
    return raw



HIGH_IMPACT_TOOL_RE = re.compile(
    r"(?i)(?:delete|remove|destroy|drop|purge|format|uninstall|"
    r"shell|terminal|command|exec|install|scan|defender|"
    r"send|submit|publish|deploy|release|merge|dispatch|"
    r"permission|collaborator|invite|revoke|secret|credential|"
    r"webhook|branch.?protection|shutdown|restart|kill|terminate|"
    r"archive.?extract|file.?move|organize)"
)


def tool_requires_task_intent(name: str, description: str = "") -> bool:
    """Return true only for tool definitions whose names/descriptions signal a side effect."""
    return bool(HIGH_IMPACT_TOOL_RE.search(str(name) + " " + str(description)))


def task_intent_matches(name: str, description: str, user_text: str) -> bool:
    """Check that the current user task directly asks for the high-impact action."""
    text = str(user_text or "")
    if re.search(
        r"(?i)(?:\bне\b|\bнет\b|\bнельзя\b|\bзапрещаю\b|\bотмена\b|"
        r"\bdo\s+not\b|\bdon't\b|\bnever\b|\bdeny\b|\brefuse\b)",
        text,
    ):
        return False
    definition = (str(name) + " " + str(description)).casefold()
    groups = (
        (r"(?:delete|remove|destroy|drop|purge|format)", r"(?:удал|delete|remove|destroy|drop|purge|форматир)"),
        (r"(?:uninstall|install|package)", r"(?:установ|install|uninstall|поставь|upgrade|обнови)"),
        (r"(?:shell|terminal|command|exec)", r"(?:вызов|вызови|выполн|запусти|run|execute|command|shell|терминал|команд|скрипт)"),
        (r"(?:scan|defender)", r"(?:скан|проверь|провер|scan|check|антивирус|defender|malware)"),
        (r"(?:send|submit|publish|comment|email)", r"(?:отправ|send|submit|publish|опубликуй|коммент|email|письмо)"),
        (r"(?:deploy|release|merge|dispatch)", r"(?:deploy|развер|релиз|release|merge|мерж|объедин|слий|dispatch|workflow)"),
        (r"(?:permission|collaborator|invite|revoke|secret|credential|webhook|branch.?protection)", r"(?:доступ|прав|permission|collaborator|участник|приглас|revoke|секрет|secret|credential|webhook|защит|protection)"),
        (r"(?:archive.?extract|extract|unpack)", r"(?:распак|извлеч|extract|unpack)"),
        (r"(?:file.?move|organize)", r"(?:перемест|move|организ|сортир)"),
        (r"(?:shutdown|restart|kill|terminate)", r"(?:выключ|заверш|останов|перезапуск|restart|shutdown|kill|terminate)"),
    )
    for definition_pattern, intent_pattern in groups:
        if re.search(definition_pattern, definition) and re.search(intent_pattern, text, re.IGNORECASE):
            return True
    return False


def schema_digest(tool: dict) -> str:
    canonical = json.dumps(
        {"name": tool["name"], "inputSchema": tool.get("inputSchema")},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def safe_preview(args: dict) -> dict:
    """Show enough detail for human consent, redacting likely credentials."""
    def scrub(key, value, depth=0):
        if SECRET_RE.search(str(key)):
            return "[REDACTED SECRET]"
        if depth > 5:
            return "[nested]"
        if isinstance(value, str):
            if key.lower() in {"url", "uri", "endpoint"}:
                u = parse.urlsplit(value)
                if u.scheme and u.hostname:
                    return (u.scheme + "://" + u.hostname + (u.path or "/"))[:360]
            return value[:360] + ("…" if len(value) > 360 else "")
        if isinstance(value, dict):
            return {k: scrub(k, v, depth + 1) for k, v in list(value.items())[:20]}
        if isinstance(value, list):
            return [scrub(key, x, depth + 1) for x in value[:20]]
        return value
    return scrub("", args)


def action_description(
    name: str, reason: str, args: dict,
    *, objective: str = "", description: str = "",
) -> dict:
    """Human-readable tool request; all fields are observations, not consent."""
    return {
        "tool": name,
        "purpose": ("Задача пользователя: " + objective[:280])
                   if objective else "Qwen запрашивает инструмент для текущей задачи",
        "reason": reason,
        "tool_description": description[:240],
        "arguments": safe_preview(args),
        "execution": "not_started",
        "approval": "required",
    }
