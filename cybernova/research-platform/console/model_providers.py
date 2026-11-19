"""Portable LLM provider adapter: Ollama native or OpenAI-compatible chat.

This module does not change the Cybernova agent's tool/scope/approval policy.
Remote models are explicitly opt-in, HTTPS-only, and receive conversation
content. Do not enable cloud inference for secret or private research material.
"""
from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
from urllib import error, parse, request

LOCAL_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "ollama"})
MAX_RESPONSE_BYTES = 2_000_000


class ModelConfigError(ValueError):
    pass


def provider_name() -> str:
    name = os.environ.get("CYBERNOVA_LLM_PROVIDER", "ollama").strip().lower()
    if name not in {"ollama", "openai_compatible"}:
        raise ModelConfigError("unsupported_model_provider")
    return name


def _endpoint(base_url: str) -> str:
    """Validate a manually configured API endpoint; never take it from Qwen."""
    if not isinstance(base_url, str) or not base_url or len(base_url) > 500:
        raise ModelConfigError("llm_base_url_required")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in base_url):
        raise ModelConfigError("invalid_llm_url")
    parsed = parse.urlsplit(base_url)
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.scheme not in {"http", "https"}):
        raise ModelConfigError("invalid_llm_url")
    if parsed.scheme == "http" and parsed.hostname not in LOCAL_NAMES:
        raise ModelConfigError("remote_model_requires_https")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ModelConfigError("invalid_llm_port")
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def _key() -> str:
    inline = os.environ.get("CYBERNOVA_LLM_API_KEY", "")
    filename = os.environ.get("CYBERNOVA_LLM_API_KEY_FILE", "")
    if inline and filename:
        raise ModelConfigError("choose_one_api_key_source")
    if filename:
        path = Path(filename)
        if not path.is_file() or path.is_symlink():
            raise ModelConfigError("invalid_api_key_file")
        return path.read_text(encoding="utf-8").strip()
    return inline.strip()


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ModelConfigError("llm_redirect_forbidden")


def _normalize_context(messages: list[dict]) -> list[dict]:
    """Convert Qwen's Ollama-style tool turns into Chat Completions messages."""
    output = []
    pending = deque()
    for message in messages:
        role = message.get("role")
        if role in {"system", "user", "assistant"}:
            item = {"role": role, "content": str(message.get("content") or "")}
            if role == "assistant" and message.get("tool_calls"):
                calls = []
                for i, call in enumerate(message["tool_calls"][:16]):
                    function = call.get("function", {}) if isinstance(call, dict) else {}
                    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                        continue
                    args = function.get("arguments", {})
                    args_text = args if isinstance(args, str) else json.dumps(
                        args, ensure_ascii=False, separators=(",", ":"))
                    call_id = (call.get("id") if isinstance(call, dict) else None)
                    if not isinstance(call_id, str) or not call_id:
                        call_id = "cybernova_call_" + str(len(output)) + "_" + str(i)
                    calls.append({
                        "id": call_id, "type": "function",
                        "function": {"name": function["name"], "arguments": args_text},
                    })
                    pending.append(call_id)
                if calls:
                    item["tool_calls"] = calls
            output.append(item)
        elif role == "tool":
            # The controller's tool messages are consumed in the same order
            # as preceding assistant tool calls, preserving remote API linkage.
            if not pending:
                raise ModelConfigError("orphan_tool_response")
            output.append({"role": "tool", "tool_call_id": pending.popleft(),
                           "content": str(message.get("content") or "")})
    return output


class OpenAICompatibleClient:
    """Provider-neutral chat completion wrapper matching OllamaClient.chat()."""

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, transport=None):
        base = base_url or os.environ.get("CYBERNOVA_LLM_BASE_URL", "")
        self.endpoint = _endpoint(base)
        self.model = model or os.environ.get("CYBERNOVA_MODEL", "")
        if not self.model:
            raise ModelConfigError("llm_model_required")
        self.api_key = api_key if api_key is not None else _key()
        hostname = parse.urlsplit(self.endpoint).hostname
        if hostname not in LOCAL_NAMES and not self.api_key:
            raise ModelConfigError("remote_api_key_required")
        self.transport = transport or self._request

    def _request(self, payload: dict) -> dict:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        req = request.Request(self.endpoint, data=raw, method="POST", headers=headers)
        opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(req, timeout=240) as resp:
                if resp.status != 200:
                    raise ModelConfigError("llm_http_" + str(resp.status))
                content = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ModelConfigError("llm_response_too_large")
                result = json.loads(content)
        except error.HTTPError as exc:
            # Never dump remote response bodies: they can contain API keys.
            raise ModelConfigError("llm_http_" + str(exc.code)) from None
        except (error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ModelConfigError("llm_transport_" + type(exc).__name__) from None
        return result

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             *, json_mode: bool = False) -> dict:
        token_field = os.environ.get("CYBERNOVA_LLM_TOKEN_PARAMETER", "").strip()
        if not token_field:
            token_field = ("max_completion_tokens"
                           if self.model.startswith(("gpt-5", "gpt-6", "o1", "o3", "o4"))
                           else "max_tokens")
        if token_field not in {"max_tokens", "max_completion_tokens"}:
            raise ModelConfigError("invalid_token_parameter")
        payload = {
            "model": self.model, "stream": False,
            "messages": _normalize_context(messages),
            token_field: 1100,
        }
        custom_temp = os.environ.get("CYBERNOVA_LLM_TEMPERATURE", "").strip()
        if custom_temp:
            try:
                temperature = float(custom_temp)
                if not 0 <= temperature <= 2:
                    raise ValueError("outside_range")
            except ValueError:
                raise ModelConfigError("invalid_llm_temperature") from None
            payload["temperature"] = temperature
        if tools:
            payload["tools"] = tools
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        result = self.transport(payload)
        if not isinstance(result, dict) or not isinstance(result.get("choices"), list) or not result["choices"]:
            raise ModelConfigError("llm_choices_missing")
        message = result["choices"][0].get("message")
        if not isinstance(message, dict):
            raise ModelConfigError("llm_message_missing")
        calls = []
        for call in (message.get("tool_calls") or [])[:16]:
            if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
                continue
            function = call["function"]
            if not isinstance(function.get("name"), str):
                continue
            args = function.get("arguments")
            if not isinstance(args, (str, dict)):
                continue
            calls.append({
                "id": str(call.get("id") or ""),
                "function": {"name": function["name"], "arguments": args},
            })
        content = message.get("content")
        if isinstance(content, list):
            content = "\n".join(
                part.get("text", "") for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            )
        return {"content": content if isinstance(content, str) else "",
                "tool_calls": calls}


def build_model_client():
    """Leave Ollama behavior unchanged unless explicitly configured otherwise."""
    if provider_name() == "openai_compatible":
        return OpenAICompatibleClient()
    try:
        from .agent import OllamaClient
    except ImportError:
        from agent import OllamaClient
    return OllamaClient()
