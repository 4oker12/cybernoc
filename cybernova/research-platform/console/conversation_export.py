"""Read-only complete conversation exports for the local authenticated console.

The screen and model context keep bounded windows; export independently walks
the durable SQLite history. Never send exports to an external LLM or website.
"""
from __future__ import annotations

import json


class ConversationExportError(ValueError):
    pass


def _all_task_messages(communications, task_id: str) -> list[dict]:
    messages = []
    after = 0
    while True:
        page = communications.read_dialog(task_id, after=after, limit=100)
        items = page["messages"]
        if not items:
            break
        messages.extend(items)
        cursor = page["next_after"]
        if cursor <= after:
            raise ConversationExportError("invalid_export_cursor")
        after = cursor
    return messages


def export_data(mode: str, ident: str, communications, collaborations, gpt_store) -> dict:
    if mode == "collab":
        # Reading metadata checks a valid collaboration, while the message
        # iterator explicitly does not inherit the 100-message UI window.
        run = collaborations.read(ident)
        messages = _all_task_messages(communications, ident)
        return {
            "kind": "collab", "id": ident, "title": run["goal"],
            "status": run["state"], "model": run["model"],
            "exchanges_completed": run["step"] // 2,
            "messages": [
                {"time": m["created_at"], "actor": m["actor"],
                 "type": m["kind"], "content": m["body"],
                 "evidence_refs": m["evidence_refs"]}
                for m in messages
            ],
        }
    if mode == "research":
        task = communications.get_task(ident)
        messages = _all_task_messages(communications, ident)
        return {
            "kind": "research", "id": ident, "title": task["title"],
            "status": task["status"], "model": None,
            "messages": [
                {"time": m["created_at"], "actor": m["actor"],
                 "type": m["kind"], "content": m["body"],
                 "evidence_refs": m["evidence_refs"]}
                for m in messages
            ],
        }
    if mode == "gpt":
        result = gpt_store.get_export_thread(ident)
        thread = result["thread"]
        return {
            "kind": "gpt", "id": ident, "title": thread["title"],
            "status": "saved", "model": thread["model"],
            "messages": [
                {"time": m["created_at"], "actor": m["role"],
                 "type": "message", "content": m["content"]}
                for m in result["messages"]
            ],
        }
    raise ConversationExportError("unsupported_export_mode")


ACTOR_NAMES = {
    "human": "Вы", "user": "Вы", "assistant": "ChatGPT",
    "chatgpt": "ChatGPT · наставник", "qwen": "DeepSeek · исследователь",
    "controller": "Cybernova · система",
}


def to_markdown(data: dict) -> str:
    title = str(data["title"]).replace("\n", " ").replace("\r", " ")
    lines = [
        "# Cybernova — полная история обсуждения",
        "",
        "Диалог: " + title,
        "ID: " + data["id"],
        "Режим: " + data["kind"],
        "Статус: " + data["status"],
        "Модель: " + str(data.get("model") or "не указана"),
        "Сообщений: " + str(len(data["messages"])),
        "",
    ]
    if "exchanges_completed" in data:
        lines.extend(["Завершено обменов: " + str(data["exchanges_completed"]), ""])
    for i, message in enumerate(data["messages"], 1):
        actor = message["actor"]
        if data["kind"] == "gpt" and actor == "assistant":
            actor_name = "ChatGPT"
        elif data["kind"] == "research" and actor == "qwen":
            actor_name = "Исследователь"
        else:
            actor_name = ACTOR_NAMES.get(actor, actor)
        lines.extend([
            "## " + str(i) + ". " + actor_name,
            "Время (UTC): " + str(message["time"]) +
            " · Тип: " + str(message["type"]),
            "",
            message["content"],
            "",
        ])
        if message.get("evidence_refs"):
            lines.extend(["Связанные доказательства: " +
                          ", ".join(message["evidence_refs"]), ""])
    return "\n".join(lines).rstrip() + "\n"


def render_export(data: dict, format: str) -> tuple[str, str, str]:
    if format == "md":
        return to_markdown(data), "text/markdown; charset=utf-8", "md"
    if format == "json":
        return (json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                "application/json; charset=utf-8", "json")
    raise ConversationExportError("unsupported_export_format")
