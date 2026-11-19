"""ChatGPT-plan inference: documented public Models and Responses API only.

Every invocation is triggered by a deliberate Cybernova UI action.
No automatic export of local evidence or Qwen chat to OpenAI.
"""
from __future__ import annotations
import json
import re
from urllib import error, request

try:
    from .siwc import RESOURCE, MODEL_NAME, SIWCError, connection
except ImportError:
    from siwc import RESOURCE, MODEL_NAME, SIWCError, connection


def models() -> list[dict]:
    token = connection.access()
    req = request.Request(RESOURCE + "/models",
                          headers={"Authorization": "Bearer " + token,
                                   "Accept": "application/json"})
    try:
        with request.build_opener(request.ProxyHandler({})).open(req, timeout=18) as resp:
            raw = resp.read(1_000_001)
    except error.HTTPError as exc:
        raise SIWCError("models_http_" + str(exc.code)) from None
    except (OSError, TimeoutError):
        raise SIWCError("models_unavailable") from None
    if len(raw) > 1_000_000:
        raise SIWCError("model_catalog_too_large")
    try:
        data = json.loads(raw)
    except ValueError:
        raise SIWCError("models_invalid") from None
    rows = data.get("models", []) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise SIWCError("models_invalid")
    return [{"slug": row["slug"],
             "display_name": row.get("display_name") or row["slug"]}
            for row in rows if isinstance(row, dict)
            and row.get("visibility") == "list"
            and isinstance(row.get("slug"), str)
            and MODEL_NAME.fullmatch(row["slug"])]


def review(model: str, prompt: str) -> dict:
    if not isinstance(prompt, str) or not 1 <= len(prompt.strip()) <= 12000:
        raise SIWCError("review_prompt_invalid")
    if not isinstance(model, str) or not MODEL_NAME.fullmatch(model):
        raise SIWCError("model_invalid")
    allowed = {row["slug"] for row in models()}
    if model not in allowed:
        raise SIWCError("model_not_available")
    token = connection.access()
    payload = {
        "model": model, "store": False, "stream": True,
        "instructions": (
            "Ты — независимый рецензент Cybernova. Разделяй наблюдения, "
            "гипотезы и подтверждённые факты. Найди пробелы и альтернативы. "
            "Не утверждай, что запускал инструменты или сканировал объект. "
            "Сформулируй следующие разрешённые проверки и исправления."
        ),
        "input": [{"role": "user", "content": prompt.strip()}],
    }
    req = request.Request(
        RESOURCE + "/responses", method="POST",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                 "Accept": "text/event-stream"},
    )
    chunks = []
    completed = False
    total_bytes = 0
    total_chars = 0
    try:
        with request.build_opener(request.ProxyHandler({})).open(req, timeout=150) as resp:
            for line in resp:
                total_bytes += len(line)
                if total_bytes > 1_500_000:
                    raise SIWCError("gpt_stream_too_large")
                if not line.startswith(b"data: "):
                    continue
                try:
                    event = json.loads(line[6:].strip())
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                kind = event.get("type")
                if kind == "response.output_text.delta":
                    delta = event.get("delta")
                    if isinstance(delta, str):
                        total_chars += len(delta)
                        if total_chars > 12000:
                            raise SIWCError("gpt_reply_too_large")
                        chunks.append(delta)
                elif kind == "response.completed":
                    completed = True
                    break
                elif kind in {"response.failed", "error"}:
                    raise SIWCError("gpt_response_failed")
    except error.HTTPError as exc:
        raise SIWCError("gpt_http_" + str(exc.code)) from None
    except (OSError, TimeoutError):
        raise SIWCError("gpt_transport_unavailable") from None
    if not completed:
        raise SIWCError("gpt_stream_incomplete")
    answer = "".join(chunks).strip()
    if not answer:
        raise SIWCError("gpt_response_empty")
    return {"answer": answer, "model": model, "source": "chatgpt_plan_responses"}
