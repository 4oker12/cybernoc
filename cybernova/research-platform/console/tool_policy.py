"""Policy for autonomous MCP choice and bounded, human-approved execution.

All advertised tools are visible to the model. Mere visibility is NOT execution
permission: six current reviewed methods run automatically; newly connected MCP
methods can be requested and approved once, with exact arguments.
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
})
REVIEWED_SCOPED = frozenset({"http_get"})
REVIEWED_TOOLS = REVIEWED_OFFLINE | REVIEWED_SCOPED


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
                " [Requires user approval before execution.]"
                if item["name"] not in REVIEWED_TOOLS else ""
            ),
            "parameters": item["inputSchema"],
        },
    } for item in discovered_tools(rows)]


def _json_depth(item, depth=0) -> None:
    if depth > 8:
        raise ToolPolicyError("tool_arguments_too_deep")
    if isinstance(item, dict):
        if len(item) > 60:
            raise ToolPolicyError("tool_arguments_too_many_keys")
        for key, value in item.items():
            if not isinstance(key, str) or len(key) > 90:
                raise ToolPolicyError("tool_argument_key_invalid")
            _json_depth(value, depth + 1)
    elif isinstance(item, list):
        if len(item) > 80:
            raise ToolPolicyError("tool_arguments_too_many_items")
        for value in item:
            _json_depth(value, depth + 1)
    elif not (item is None or isinstance(item, (str, int, float, bool))):
        raise ToolPolicyError("tool_arguments_non_json_value")
    elif isinstance(item, str) and len(item) > MAX_VALUE_LENGTH:
        raise ToolPolicyError("tool_argument_value_too_large")


def validate_dynamic_arguments(raw: object, schema: dict) -> dict:
    """Validate shape and types from MCP schema without executing tool code.

    Unknown tool schemas are not trusted as security classification; approval
    is still mandatory. Only keys explicitly declared by the tool are allowed.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise ToolPolicyError("tool_arguments_not_json") from exc
    if not isinstance(raw, dict):
        raise ToolPolicyError("tool_arguments_not_object")
    _json_depth(raw)
    if len(json.dumps(raw, ensure_ascii=False).encode()) > MAX_ARGUMENT_BYTES:
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
