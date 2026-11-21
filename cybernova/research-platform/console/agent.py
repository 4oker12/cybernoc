"""Provider-neutral Cybernova LLM ↔ MCP agent: autonomous tool choice, guarded execution."""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from urllib import request, parse, error

try:
    from .tool_policy import (
        REVIEWED_TOOLS, discovered_tools, model_tools, schema_digest,
        validate_dynamic_arguments, safe_preview, action_description,
        ToolPolicyError,
    )
except ImportError:
    from tool_policy import (
        REVIEWED_TOOLS, discovered_tools, model_tools, schema_digest,
        validate_dynamic_arguments, safe_preview, action_description,
        ToolPolicyError,
    )
try:
    from .gpt_tool_runtime import extract_user_targets
except ImportError:
    from gpt_tool_runtime import extract_user_targets

try:
    from .agent_profile import AGENT_PROFILE
except ImportError:
    from agent_profile import AGENT_PROFILE

OLLAMA_URL = os.environ.get("CYBERNOVA_OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
MCP_URL = os.environ.get("CYBERNOVA_MCP_URL", "http://127.0.0.1:18792/mcp")
MODEL = os.environ.get("CYBERNOVA_MODEL", "cybernova-security:30b")
MAX_ROUNDS = 16
MAX_CALLS = 32
MAX_HTTP_GETS = 3
MAX_PROMPT = 10000
MAX_RESULT = 12000
APPROVAL_TTL_SECONDS = 3600
OFFLINE_TOOLS = frozenset({
    "gateway_status", "python_static_review", "http_header_review",
    "ip_network_summary", "local_webui_health",
})
ACTIVE_TOOLS = frozenset({"http_get"})
BASE_SYSTEM = AGENT_PROFILE


class BackendError(RuntimeError):
    pass


def post_json(url: str, data: dict, timeout: int) -> dict:
    # Fixed loopback endpoints only. Environment overrides still must be localhost.
    u = parse.urlsplit(url)
    if u.scheme != "http" or u.hostname not in {"127.0.0.1", "localhost", "ollama"} or \
       u.username or u.password or u.fragment:
        raise BackendError("backend_must_be_localhost")
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    req = request.Request(url, data=raw, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-06-18",
    })
    try:
        opener = request.build_opener(request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise BackendError("backend_http_" + str(resp.status))
            return json.load(resp)
    except (error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise BackendError(type(exc).__name__ + ": " + str(exc)[:140]) from exc


class MCPClient:
    def __init__(self, endpoint: str = MCP_URL, transport=None):
        self.endpoint = endpoint
        self.transport = transport or post_json
        self.sequence = 0

    def rpc(self, method: str, params=None) -> dict:
        self.sequence += 1
        body = {"jsonrpc": "2.0", "method": method, "id": self.sequence}
        if params is not None:
            body["params"] = params
        value = self.transport(self.endpoint, body, 14)
        if not isinstance(value, dict):
            raise BackendError("invalid_mcp_response")
        if "error" in value:
            raise BackendError("mcp_rpc_error: " + str(value["error"])[:180])
        if not isinstance(value.get("result"), dict):
            raise BackendError("mcp_result_missing")
        return value["result"]

    def initialize(self) -> list[dict]:
        self.rpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "cybernova-console", "version": "0.1"},
        })
        found = self.rpc("tools/list").get("tools", [])
        if not isinstance(found, list):
            raise BackendError("invalid_tool_list")
        return [t for t in found if isinstance(t, dict) and isinstance(t.get("name"), str)]

    def call(self, name: str, args: dict) -> tuple[dict, bool]:
        response = self.rpc("tools/call", {"name": name, "arguments": args})
        items = response.get("content", [])
        if not isinstance(items, list):
            raise BackendError("invalid_tool_content")
        texts = [x.get("text", "") for x in items if isinstance(x, dict) and x.get("type") == "text"]
        if not texts:
            return {"error": "empty_tool_result"}, True
        try:
            parsed = json.loads(texts[0])
            if not isinstance(parsed, dict):
                parsed = {"value": parsed}
        except (ValueError, TypeError):
            parsed = {"message": str(texts[0])[:MAX_RESULT]}
        return parsed, bool(response.get("isError"))


class OllamaClient:
    def __init__(self, endpoint: str = OLLAMA_URL, model: str = MODEL, transport=None):
        self.endpoint = endpoint
        self.model = model
        self.transport = transport or post_json

    def chat(self, messages: list[dict], tools: list[dict] | None = None, *, json_mode=False) -> dict:
        payload = {
            "model": self.model, "messages": messages, "stream": False,
            "options": {"temperature": 0.15, "num_ctx": 8192, "num_predict": 1100},
        }
        if tools:
            payload["tools"] = tools
        if json_mode:
            payload["format"] = "json"
        response = self.transport(self.endpoint, payload, 240)
        msg = response.get("message")
        if not isinstance(msg, dict):
            raise BackendError("ollama_message_missing")
        return msg


def _tool_schema(found: list[dict], active_enabled: bool = True) -> list[dict]:
    """Expose every real MCP-advertised tool. active_enabled is legacy-only."""
    return model_tools(found)


def _arguments(name: str, value) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise BackendError("tool_arguments_not_json")
    if not isinstance(value, dict):
        raise BackendError("tool_arguments_not_object")
    expected = {
        "gateway_status": {},
        "local_webui_health": {},
        "ip_network_summary": {"cidr": str},
        "python_static_review": {"source": str},
        "http_header_review": {"raw_headers": str, "scheme": str},
        "http_get": {"url": str},
    }.get(name)
    if expected is None:
        raise BackendError("unreviewed_tool")
    if set(value) - set(expected):
        raise BackendError("unexpected_tool_arguments")
    for key, cls in expected.items():
        if key == "scheme" and key not in value:
            continue
        if key not in value or not isinstance(value[key], cls):
            raise BackendError("invalid_argument_" + key)
        if len(value[key]) > (64000 if key == "source" else 16000):
            raise BackendError("argument_too_large")
    return value


def _safe_args(name: str, args: dict) -> dict:
    if name == "google_search":
        # Actual sanitized query is returned by the search adapter; never
        # persist model-supplied free text in the event's argument preview.
        return {"query": "[privacy-filtered query]"}
    if name == "research_source_open":
        u = parse.urlsplit(args.get("url", ""))
        path = re.sub(r"(?i)(?:[0-9a-f]{16,}|[A-Za-z0-9_-]{32,}|\d{5,})", "{id}", u.path or "/")
        return {"url": (u.scheme + "://" + (u.hostname or "") + path)[:360]}
    if name == "http_get":
        u = parse.urlsplit(args.get("url", ""))
        return {"url": (u.scheme + "://" + (u.hostname or "") + (u.path or "/"))[:240]}
    if name == "ip_network_summary":
        return args
    return {key: "[provided: %d characters]" % len(str(val)) for key, val in args.items()}


def _allowed_http(url: str, hosts: set[str]) -> bool:
    try:
        u = parse.urlsplit(url)
        return (u.scheme == "https" and u.hostname in hosts and
                u.port in (None, 443) and not u.username and not u.password and
                not u.fragment and not re.search(r"[\x00-\x20\\]", url))
    except ValueError:
        return False


class Agent:
    def __init__(self, ollama=None, mcp_factory=None, local_tool_runtime=None):
        if ollama is None:
            try:
                from .model_providers import build_model_client
            except ImportError:
                from model_providers import build_model_client
            ollama = build_model_client()
        self.ollama = ollama
        self.mcp_factory = mcp_factory or (lambda: MCPClient())
        self.local_tool_runtime = local_tool_runtime

    def _call_registered_tool(self, name: str, args: dict, *, mcp=None,
                              authorized_targets=None, user_messages=None):
        if self.local_tool_runtime is not None and name in self.local_tool_runtime.tool_map:
            result, is_error = self.local_tool_runtime.call(
                name, args, authorized_targets=authorized_targets,
                user_messages=user_messages,
            )
            if isinstance(result, dict) and isinstance(result.get("image_data_url"), str):
                # The current DeepSeek/Ollama chat adapter is text-only. Do not
                # serialize megabytes of base64 into its prompt; use DOM/UIA data.
                result = dict(result)
                result.pop("image_data_url", None)
                result["visual_input"] = {
                    "captured": True, "forwarded_to_model": False,
                    "reason": "current_agent_model_adapter_is_text_only",
                    "alternative": "Use browser_snapshot/browser_network or computer_ui_windows/computer_ui_controls.",
                }
            return result, is_error
        if mcp is None:
            return {"ok": False, "error": "mcp_backend_unavailable"}, True
        return mcp.call(name, args)

    def run(self, history: list[dict], text: str, *, public_get=True, force_tools=True, scope: dict | None = None, user_context: str = "", profile_instructions: str = "") -> dict:
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_PROMPT:
            raise ValueError("message_length_invalid")
        # Only client-visible role/content history enters the model; never forward
        # hidden arguments or previous tool outputs as executable instructions.
        context = [{"role": "system", "content": BASE_SYSTEM}]
        if user_context:
            context.append({"role": "system", "content": user_context[:8500]})
        if profile_instructions:
            context.append({"role": "system", "content": profile_instructions[:12500]})
        # Owner-selected scope is trusted policy metadata, not model output.
        # It describes targets and evidence mode; it is not a blanket
        # authorization for changing production systems.
        scope_hosts = list((scope or {}).get("hosts") or [])
        if scope_hosts:
            context.append({"role": "system", "content":
                "Владелец выбрал объект(ы) этой задачи: " +
                ", ".join(scope_hosts[:20]) +
                ". Это применимо к пассивной навигации browser_navigate, browser_snapshot, " +
                "browser_follow_link и browser_network. " +
                "Если пользователь упомянул сайт без URL, можно читать " +
                "https://" + scope_hosts[0] + "/. " +
                "Уровень доказательств Network: " +
                str((scope or {}).get("capture_detail", "evidence")) +
                ". Для активных тестов сохраняется отдельное согласование."}
            )

        for msg in history[-16:]:
            if msg.get("role") in ("user", "assistant") and isinstance(msg.get("content"), str):
                context.append({"role": msg["role"], "content": msg["content"][:MAX_PROMPT]})
        context.append({"role": "user", "content": text})
        events = []
        pending_requests = []
        task_messages = [
            {"role": item["role"], "content": item["content"]}
            for item in history[-16:]
            if isinstance(item, dict) and item.get("role") in {"user", "assistant"}
            and isinstance(item.get("content"), str)
        ] + [{"role": "user", "content": text}]
        authorized_targets = extract_user_targets(task_messages)
        authorized_targets.update(
            str(host).lower().rstrip(".") for host in scope_hosts
            if isinstance(host, str) and host.strip()
        )
        mcp = None
        remote_rows = []
        try:
            mcp = self.mcp_factory()
            remote_rows = mcp.initialize()
        except (BackendError, ToolPolicyError) as exc:
            events.append({"type": "mcp_error", "message": str(exc)[:240]})
        local_rows = (
            self.local_tool_runtime.mcp_tools()
            if self.local_tool_runtime is not None else []
        )
        local_names = {row["name"] for row in local_rows}
        combined_rows = local_rows + [
            row for row in remote_rows
            if isinstance(row, dict)
            and row.get("name") not in local_names
            and not (self.local_tool_runtime is not None and row.get("name") == "browser_open")
        ]
        try:
            registered = discovered_tools(combined_rows)
            descriptors = {t["name"]: t for t in registered}
            tools = _tool_schema(registered)
        except ToolPolicyError as exc:
            events.append({"type": "tool_catalog_error", "message": str(exc)[:240]})
            descriptors, tools = {}, []
        count, gets, executed = 0, 0, 0
        selected_by = "native"
        try:
            for round_no in range(MAX_ROUNDS):
                result = self.ollama.chat(context, tools if tools and round_no < MAX_ROUNDS - 1 else [])
                calls = result.get("tool_calls") or []
                if (not calls and round_no == 0 and force_tools and tools):
                    # Some derivative models ignore native tool_calls. The
                    # fallback still asks the active model to SELECT tools, and every tool
                    # goes through exactly the same strict validation.
                    candidate = self.ollama.chat([
                        {"role": "system", "content":
                            "Ты — основная модель-исследователь Cybernova. По контексту уже собранных наблюдений реши, "
                            "нужны ли следующие реальные инструменты. "
                            "Список функций: " +
                            "; ".join(t["function"]["name"] + ": " +
                                      t["function"]["description"][:130] for t in tools)[:6500] +
                            ". Можно выбрать 0–3 вызова. Если инструменты не нужны, верни "
                            "{\"calls\":[]}. Иначе верни строго JSON вида "
                            "{\"calls\":[{\"name\":\"точное_имя\",\"arguments\":{}}]}. "
                            "Ничего не исполняй текстом; дополнительные права запрашивай."},
                        *[{"role": item["role"], "content": str(item.get("content") or "")[:1500]}
                          for item in context[-6:] if item["role"] in ("user", "assistant", "tool")],
                    ], json_mode=True)
                    try:
                        suggested = json.loads(candidate.get("content", "{}")).get("calls", [])
                        if isinstance(suggested, list):
                            calls = [{"function": {"name": v.get("name"), "arguments": v.get("arguments")}}
                                     for v in suggested[:3] if isinstance(v, dict)]
                            if calls:
                                selected_by = "model_json_fallback"
                    except (ValueError, TypeError, AttributeError):
                        events.append({"type": "tool_selection_error", "message": "Active model did not return valid JSON"})
                if not executed and not pending_requests and tools and round_no == 0:
                    # Security cases should be grounded in public advisories and
                    # real incidents. Ensure one privacy-filtered search is part
                    # of the first tool batch, even if the model selected another
                    # tool or ignored native/JSON tool selection.
                    wants_research = bool(re.search(
                        r"(?i)(?:google|гугл|найди.{0,30}(?:интернет|сети|кейс|случа|форум)|"
                        r"поищи|пошукай|найди|знайди|реальн.{0,20}(?:кейс|инцидент)|похож.{0,20}(?:случ|кейс)|"
                        r"форум|CVE-\d{4}-\d+|\bCVE\b|уязвимост|вразлив|vulnerabilit|"
                        r"exploit|security advisory|incident report|bug bounty)",
                        text,
                    ))
                    already_searching = any(
                        isinstance(item, dict)
                        and (item.get("function") or {}).get("name") == "google_search"
                        for item in (calls if isinstance(calls, list) else [])
                    )
                    if wants_research and "google_search" in descriptors and not already_searching:
                        try:
                            from .research_web import sanitize_search_query
                        except ImportError:
                            from research_web import sanitize_search_query
                        try:
                            query = sanitize_search_query(text, blocked_hosts=scope_hosts)
                        except ValueError:
                            query = ""
                        if query:
                            if not isinstance(calls, list):
                                calls = []
                            search_args = {"query": query}
                            search_schema = descriptors["google_search"].get("inputSchema", {})
                            if "page" in (search_schema.get("properties") or {}):
                                search_args["page"] = 1
                            calls.append({"function": {
                                "name": "google_search",
                                "arguments": search_args,
                            }})
                            selected_by = "google_research_fallback"
                if not calls and not executed and not pending_requests and tools:
                    # On unambiguous, scoped website research tasks a weak local
                    # model may ignore native tool calls AND JSON fallback.
                    # Try exactly one browser evidence call instead of claiming
                    # there is no access. Scope/policy enforcement is in tool.
                    requested_url = re.search(r"https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9_./?=&%+~-]*)?", text)
                    selected_url = requested_url.group(0) if requested_url else (
                        "https://" + scope_hosts[0] + "/" if scope_hosts else None)
                    browser_intent = bool(re.search(
                        r"(?i)(?:открой|исследуй|изучи|проверь|проанализируй|собери|network|devtools|браузер|сайт)",
                        text))
                    if selected_url and browser_intent and round_no == 0:
                        # Prefer the shared Playwright navigator when present.
                        # Legacy MCP-only agents retain their browser_network/open
                        # fallback and its existing URL argument contract.
                        if self.local_tool_runtime is not None and "browser_navigate" in descriptors:
                            chosen, chosen_args = "browser_navigate", {"url": selected_url}
                        elif "browser_network" in descriptors:
                            chosen, chosen_args = "browser_network", {"url": selected_url}
                        else:
                            chosen, chosen_args = "browser_open", {"url": selected_url}
                        if chosen in descriptors:
                            observed, error_flag = self._call_registered_tool(
                                chosen, chosen_args, mcp=mcp,
                                authorized_targets=authorized_targets,
                                user_messages=task_messages,
                            )
                            executed += 1
                            selected_by = "evidence_first_fallback"
                            serialized = json.dumps(observed, ensure_ascii=False)[:MAX_RESULT]
                            events.append({
                                "type": "tool_result", "name": chosen,
                                "arguments": {"url": selected_url},
                                "is_error": bool(error_flag),
                                "result": observed,
                            })
                            context.append({"role": "system", "content":
                                "Реальный инструмент " + chosen +
                                " уже вызван контроллером. Отдели полученные факты "
                                "от ошибок и гипотез. Не утверждай, что инструментов нет."})
                            context.append({"role": "tool", "tool_name": chosen,
                                            "content": serialized})
                            continue
                if not calls and not executed and not pending_requests and mcp and tools and round_no == 0:
                    # A derivative model sometimes lists coding advice without
                    # calling any real tools. Ground the FIRST coding response in
                    # the actual repository tree; subsequent choices stay with the active model.
                    wants_dev = bool(re.search(
                        r"(?i)(?:проект|репозитори|исходник|код|cybernova|разработ)",
                        text
                    )) and bool(re.search(
                        r"(?i)(?:изучи|изучить|проанализируй|исправ|проверь|найди|"
                        r"улучш|создай|напиши|доработ|рефактор|разбер)",
                        text))
                    if wants_dev and "dev_list" in descriptors:
                        observed, error_flag = mcp.call("dev_list", {"limit": 100})
                        executed += 1
                        selected_by = "developer_evidence_fallback"
                        events.append({
                            "type": "tool_result", "name": "dev_list",
                            "arguments": {"limit": 100},
                            "is_error": bool(error_flag), "result": observed,
                        })
                        context.append({"role": "system", "content":
                            "Получена реальная структура Git-проекта dev_list. "
                            "Если нужен конкретный исходный файл, вызывай dev_read; "
                            "если нужно менять код, используй dev_edit/dev_test. "
                            "Не утверждай, что у тебя нет доступа к репозиторию."})
                        context.append({"role": "tool", "tool_name": "dev_list",
                                        "content": json.dumps(observed, ensure_ascii=False)[:MAX_RESULT]})
                        continue
                if not calls:
                    answer = str(result.get("content") or "").strip()
                    if pending_requests:
                        answer += "\n\nДля продолжения нужны отдельные разрешения. "
                        answer += "Я подготовила запросы; до подтверждения действия не выполнены."
                    return {
                        "answer": answer or "Модель не сформировала текстовый ответ.",
                        "events": events, "tool_calls": executed,
                        "approval_requests": pending_requests,
                        "selected_by": selected_by if count or executed else "none",
                        "model": self.ollama.model,
                    }
                if not isinstance(calls, list):
                    raise BackendError("invalid_tool_calls")
                assistant_turn = {
                    "role": "assistant", "content": result.get("content") or "",
                    "tool_calls": calls,
                }
                # DeepSeek thinking mode requires reasoning_content to be
                # echoed unchanged on the next request when tools are enabled.
                if isinstance(result.get("reasoning_content"), str):
                    assistant_turn["reasoning_content"] = result["reasoning_content"]
                context.append(assistant_turn)
                for raw in calls[:MAX_CALLS-count]:
                    function = raw.get("function", {}) if isinstance(raw, dict) else {}
                    name = function.get("name")
                    allowed_names = set(descriptors)
                    safe_result, failed = {}, False
                    args, kind, event = {}, "tool_result", {}
                    try:
                        if name not in allowed_names:
                            raise BackendError("tool_not_registered")
                        if name in {"gateway_status", "python_static_review",
                                    "http_header_review", "ip_network_summary",
                                    "local_webui_health", "http_get"}:
                            args = _arguments(name, function.get("arguments"))
                        else:
                            # The 8 offline traffic tools use exact MCP-declared
                            # JSON argument schemas, like unknown tools.
                            args = validate_dynamic_arguments(
                                function.get("arguments"),
                                descriptors[name].get("inputSchema", {}),
                            )
                        if name == "http_get":
                            if not public_get:
                                raise BackendError("public_http_not_enabled")
                            if gets >= MAX_HTTP_GETS:
                                raise BackendError("public_http_budget_exhausted")
                            gateway, error_flag = mcp.call("gateway_status", {})
                            if error_flag:
                                raise BackendError("gateway_status_failed")
                            allowed_hosts = set(gateway.get("authorized_hosts", []))
                            if not _allowed_http(args["url"], allowed_hosts):
                                kind = "scope_change_required"
                                failed = True
                                safe_result = {
                                    "ok": False, "status": "not_executed",
                                    "reason": "http_target_outside_gateway_scope",
                                    "message": "Нужен согласованный допуск домена в MCP scope.json. "
                                               "Одного подтверждения действия в чате недостаточно.",
                                }
                            else:
                                gets += 1
                                safe_result, failed = mcp.call(name, args)
                                executed += 1
                        elif name in local_names:
                            safe_result, failed = self._call_registered_tool(
                                name, args, mcp=mcp,
                                authorized_targets=authorized_targets,
                                user_messages=task_messages,
                            )
                            executed += 1
                        elif name in REVIEWED_TOOLS:
                            if mcp is None:
                                raise BackendError("mcp_backend_unavailable")
                            safe_result, failed = mcp.call(name, args)
                            executed += 1
                        else:
                            # New/unreviewed MCP functions are visible to the active model,
                            # but execution needs one-time user consent.
                            kind = "approval_required"
                            failed = True
                            request_id = secrets.token_urlsafe(18)
                            desc = action_description(
                                name, "Вызов ещё не проверенной функции требует согласования", args,
                                objective=text,
                                description=descriptors[name].get("description", ""),
                            )
                            event = {"request_id": request_id, **desc}
                            pending_requests.append({
                                "request_id": request_id, "tool": name,
                                "args": args, "schema_hash": schema_digest(descriptors[name]),
                                "created_at": time.time(),
                            })
                            safe_result = {
                                "ok": False, "status": "approval_required",
                                "request_id": request_id,
                                "message": "Нужна отдельная санкция пользователя. Вызов не исполнен.",
                            }
                    except (BackendError, ToolPolicyError, ValueError, TypeError) as exc:
                        failed = True
                        safe_result = {"ok": False, "error": str(exc)[:200]}
                    serialized = json.dumps(safe_result, ensure_ascii=False)[:MAX_RESULT]
                    safe_event = {
                        "type": kind, "name": str(name)[:80],
                        "arguments": _safe_args(name, args) if name in REVIEWED_TOOLS
                                     else safe_preview(args),
                        "is_error": failed or safe_result.get("ok") is False,
                        "result": safe_result if len(serialized) < MAX_RESULT
                                  else {"truncated": serialized},
                    }
                    safe_event.update(event)
                    events.append(safe_event)
                    context.append({"role": "tool", "tool_name": str(name),
                                    "content": serialized})
                    count += 1
                if count >= MAX_CALLS:
                    context.append({"role": "system",
                                    "content": "Лимит инструментов достигнут. Сформируй итог только из наблюдений."})
                    final = self.ollama.chat(context, [])
                    answer = str(final.get("content") or "")
                    if pending_requests:
                        answer += "\n\nДля продолжения нужны отдельные разрешения. "
                        answer += "Запрошенные действия ещё не выполнены."
                    return {"answer": answer, "events": events, "tool_calls": executed,
                            "approval_requests": pending_requests,
                            "selected_by": selected_by, "model": self.ollama.model}
            raise BackendError("agent_round_limit")
        except (BackendError, ValueError, TypeError) as exc:
            events.append({"type": "agent_error", "message": str(exc)[:200]})
            return {
                "answer": "Ошибка исполнения: " + str(exc)[:180],
                "events": events, "tool_calls": executed,
                "approval_requests": pending_requests,
                "selected_by": selected_by if count or executed else "none", "model": self.ollama.model,
            }

    def execute_approved(self, approval: dict, history: list[dict]) -> dict:
        """Run exactly the previously proposed MCP call after user opt-in.

        Fresh MCP tools/list and schema hash prevent a different command from
        being swapped underneath the approval. No model-selected additional
        tools are allowed in this continuation turn.
        """
        if not isinstance(approval, dict) or time.time() - approval.get("created_at", 0) > APPROVAL_TTL_SECONDS:
            raise BackendError("approval_expired")
        name, args = approval.get("tool"), approval.get("args")
        if not isinstance(name, str) or name in REVIEWED_TOOLS:
            raise BackendError("approval_not_applicable")
        mcp = self.mcp_factory()
        available = {t["name"]: t for t in discovered_tools(mcp.initialize())}
        if name not in available or schema_digest(available[name]) != approval.get("schema_hash"):
            raise BackendError("tool_definition_changed")
        args = validate_dynamic_arguments(args, available[name]["inputSchema"])
        result, is_error = mcp.call(name, args)
        # No tool definitions here: a second tool requires another full user turn.
        prompt = [
            {"role": "system", "content":
             "Ты CYBERNOVA. Пользователь явно разрешил ОДИН запрос к MCP. "
             "Ниже фактический результат. Сделай вывод без вымышленных фактов. "
             "Не утверждай, что выполнялись другие действия."},
            *[{"role": row["role"], "content": row["content"][:4500]}
              for row in history[-8:] if row.get("role") in {"assistant", "user"}
              and isinstance(row.get("content"), str)],
            {"role": "user", "content":
             "Разрешённый MCP-вызов " + name + " завершён. "
             "Результат: " + json.dumps(result, ensure_ascii=False)[:MAX_RESULT]},
        ]
        message = self.ollama.chat(prompt, [])
        return {
            "answer": str(message.get("content") or "Результат получен, пояснение отсутствует."),
            "tool_calls": 1,
            "selected_by": "user_approved",
            "model": self.ollama.model,
            "events": [{
                "type": "approved_tool_result", "name": name,
                "arguments": safe_preview(args),
                "is_error": bool(is_error or result.get("ok") is False),
                "result": result,
            }],
        }
