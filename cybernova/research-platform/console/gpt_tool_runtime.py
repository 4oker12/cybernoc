"""Local tool runtime implementation shared by Cybernova model adapters.

Account GPT and DeepSeek receive separate GPTToolRuntime instances, locks and
persistent browser profiles while retaining the same reviewed tool catalog.
"""
from __future__ import annotations

import ipaddress
import importlib.util
import hashlib
import logging
import os
from pathlib import Path
import platform
import re
import secrets
import string
import shutil
import subprocess
import sys
import time
import uuid
from collections import OrderedDict
from threading import RLock

try:
    from .tool_policy import task_intent_matches
    from .account_missions import (
        AccountMissionError, AccountMissionStore, account_mission_store,
        MISSION_STATUSES, STEP_STATUSES,
    )
    from .account_vault import AccountVaultError, account_vault
    from .browser_control import APPROVAL_TOOL_NAMES, BROWSER_CONTROL_TOOLS, BrowserSession, browser_control_call
    from .developer_tools import SOURCE
    from .research_web import RESEARCH_WEB_TOOLS, research_web_call
    from .computer_control import COMPUTER_TOOLS, COMPUTER_TOOL_NAMES, computer_control_call
    from .github_tools import GITHUB_TOOLS, GITHUB_NAMES, github_call
    from .github_write_tools import GITHUB_WRITE_TOOLS, GITHUB_WRITE_NAMES, github_write_call
    from .owner_input import owner_input_broker
except ImportError:
    from tool_policy import task_intent_matches
    from account_missions import (
        AccountMissionError, AccountMissionStore, account_mission_store,
        MISSION_STATUSES, STEP_STATUSES,
    )
    from account_vault import AccountVaultError, account_vault
    from browser_control import APPROVAL_TOOL_NAMES, BROWSER_CONTROL_TOOLS, BrowserSession, browser_control_call
    from developer_tools import SOURCE
    from research_web import RESEARCH_WEB_TOOLS, research_web_call
    from computer_control import COMPUTER_TOOLS, COMPUTER_TOOL_NAMES, computer_control_call
    from github_tools import GITHUB_TOOLS, GITHUB_NAMES, github_call
    from github_write_tools import GITHUB_WRITE_TOOLS, GITHUB_WRITE_NAMES, github_write_call
    from owner_input import owner_input_broker


try:
    from .diagnostics import event as diagnostic_event, failure as diagnostic_failure, tool_outcome
except ImportError:
    from diagnostics import event as diagnostic_event, failure as diagnostic_failure, tool_outcome

MAX_TOOL_OUTPUT_CHARS = 50000
MAX_TERMINAL_COMMAND_CHARS = 20000
MAX_TERMINAL_TIMEOUT_SECONDS = 300
logger = logging.getLogger(__name__)

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(r"(?i)(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![a-z0-9.-])")
_SECRET = re.compile(
    r"(?i)(Bearer\s+[A-Za-z0-9._~-]{8,}|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|"
    r"authorization|cookie)\s*[:=]\s*[^\s,;]+)"
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")

MAX_BROWSER_SESSIONS = 4
BROWSER_SESSION_IDLE_SECONDS = 900
EXPLICIT_ONLY_TOOLS = frozenset()  # Full local tool pool is exposed in automatic mode.

_TOOL_NAMES = frozenset(
    item["name"] for item in BROWSER_CONTROL_TOOLS
) | frozenset(item["name"] for item in RESEARCH_WEB_TOOLS) | {
    "terminal_run", "terminal_status", "owner_request_input", "browser_fill_owner_input",
    "account_mission_create", "account_mission_checkpoint", "account_mission_get",
    "account_mission_list", "account_mission_resume",
    "browser_generate_and_fill_password", "browser_fill_saved_credential",
    "browser_request_and_fill_payment_card",
    "account_vault_list", "account_vault_mark_verified",
} | COMPUTER_TOOL_NAMES | GITHUB_NAMES | GITHUB_WRITE_NAMES

# Composer tool bundles. Empty selection means automatic access to the full
# catalog; an explicit selection exposes only the chosen groups to the model.
TOOL_GROUPS = (
    {
        "id": "browser", "label": "Chrome / браузер", "icon": "globe",
        "description": "Изолированный Chromium: открывать сайты, читать DOM, переходить по ссылкам, создавать и переключать вкладки, назад/вперёд, обновлять страницы, читать Console и DevTools Network. Личный профиль Chrome не используется.",
    },
    {
        "id": "computer", "label": "Компьютер Windows", "icon": "monitor",
        "description": "Состояние ПК: CPU/RAM/диски, процессы и службы, автозагрузка, установленные программы, окна, Microsoft Defender и локальные файлы.",
    },
    {
        "id": "terminal", "label": "Терминал Windows", "icon": "terminal",
        "description": "CMD, Windows PowerShell 5.1 и PowerShell 7 для локальной работы. Доступны автоматически; выполнение идёт с правами процесса Cybernova, без скрытого повышения привилегий.",
    },
    {
        "id": "web", "label": "Интернет / Research", "icon": "search",
        "description": "Искать в интернете, получать выдачу с пагинацией, открывать найденные страницы, читать первоисточники и сопоставлять источники.",
    },
    {
        "id": "network", "label": "Сеть / NOC", "icon": "network",
        "description": "DNS, TLS, IP, HTTP, шлюзы и сетевые проверки в заданном scope.",
    },
    {
        "id": "security", "label": "Security", "icon": "shield",
        "description": "Проверки безопасности и доступные лабораторные сканеры.",
    },
    {
        "id": "traffic", "label": "Traffic / HAR", "icon": "activity",
        "description": "Анализ HAR, JavaScript, сессий, графов и сетевых гипотез.",
    },
    {
        "id": "developer", "label": "Разработка", "icon": "code",
        "description": "Работа с workspace, Git, файлами проекта, тестами и изменениями кода.",
    },
    {
        "id": "github", "label": "GitHub", "icon": "git-branch",
        "description": "Полный доступ к выбранным репозиториям: файлы, ветки, коммиты, Issues, Pull Requests, Releases, Actions, настройки и collaborators через GitHub API. Обычная разработка выполняется автономно; удаление и администрирование — только по прямому поручению.",
    },
    {
        "id": "mcp", "label": "MCP / прочее", "icon": "plug",
        "description": "Подключённые MCP-сервисы и инструменты координации Cybernova.",
    },
)
TOOL_GROUP_IDS = frozenset(item["id"] for item in TOOL_GROUPS)


def normalize_tool_groups(groups=None) -> list[str]:
    if groups is None:
        return []
    if not isinstance(groups, (list, tuple)) or len(groups) > len(TOOL_GROUPS):
        raise ValueError("tool_groups_invalid")
    normalized = []
    for group in groups:
        if not isinstance(group, str) or group not in TOOL_GROUP_IDS:
            raise ValueError("tool_group_unknown")
        if group not in normalized:
            normalized.append(group)
    return normalized


def tool_group_for_name(name: str) -> str:
    if name.startswith(("browser_", "account_mission_", "account_vault_")) or name == "owner_request_input":
        return "browser"
    if name.startswith("computer_"):
        return "computer"
    if name.startswith("terminal_") or name == "safe_terminal":
        return "terminal"
    if name in {"google_search", "research_source_open"}:
        return "web"
    if name.startswith(("scoped_", "domain_", "network_")) or name in {
        "http_get", "http_header_review", "ip_network_summary",
        "gateway_status", "local_webui_health",
    }:
        return "network"
    if name.startswith("scanner_") or name == "python_static_review":
        return "security"
    if name.startswith("traffic_"):
        return "traffic"
    if name.startswith("github_"):
        return "github"
    if name.startswith("dev_"):
        return "developer"
    return "mcp"


def filter_tool_rows(rows, groups=None) -> list[dict]:
    selected = set(normalize_tool_groups(groups))
    safe_rows = [row for row in rows if isinstance(row, dict)
                 and isinstance(row.get("name"), str)]
    if not selected:
        return safe_rows
    return [row for row in safe_rows if tool_group_for_name(row["name"]) in selected]


# Routing chooses capabilities; dispatch still enforces the existing policy.
_ROUTE_HINTS = {
    "browser": r"браузер|хром|страниц|сайт|ссылк|вкладк|browser|chrome|https?://|html|\bdom\b|\bh1\b",
    "computer": r"компьютер|ноутбук|локальн.{0,12}файл|папк|процесс|служб|диск|окн[оа]|памят|windows|desktop|computer|defender|cpu|ram",
    "terminal": r"терминал|powershell|\bcmd\b|\bshell\b|\bterminal(?:_run|_status)?\b|консол|выполни команду|запусти команду|\bgit\s+(?:status|diff|log|show|grep|add|commit|push|fetch|branch|ls-remote)\b",
    "web": r"интернет|поиск|поищи|найди|знайди|гугл|источник|search|research|web|погод|weather|forecast|прогноз|курс валют|новост|\bcve\b|уязвимост",
    "network": r"\bdns\b|\btls\b|\bssl\b|\bip\b|\bhttp\b|\bget\b|\bcidr\b|\bcve\b|сеть|сетев|подсет|маршрут|шлюз|network|ping|traceroute",
    "security": r"security|аудит|безопасност|уязвимост|сканирован",
    "traffic": r"\bhar\b|трафик|traffic|devtools",
    "developer": r"git|репозитори|ветк|коммит|исходник|тест|разработ|проект|repository|branch|commit|code|test",
    "github": r"github|pull request|issue|репозитори|ветк|коммит",
    "mcp": r"\bmcp\b|tools/list|mcp-сервис",
}
_ROUTE_NEGATION = re.compile(
    r"(?i)(?:\bне\s+(?:используй|вызывай|запускай|подключай|применяй|открывай|выполняй|использовать|вызывать|запускать)"
    r"|\bбез\b|\bno\b|\b(?:do not|don't|never)\s+(?:use|call|run|execute)|\bwithout\b)"
    r"\s+(?:инструмент(?:ы|а|ов)?\s+|the\s+|using\s+)?"
)
_BROWSER_READ = (
    "browser_navigate", "browser_snapshot", "browser_read_page", "browser_find_text",
    "browser_read_table", "browser_follow_link", "browser_tabs", "browser_new_tab",
    "browser_switch_tab", "browser_back", "browser_forward", "browser_scroll",
    "browser_wait", "browser_reload", "browser_screenshot", "browser_open",
)
_BROWSER_INTERACT = (
    "browser_find_controls", "browser_click_button", "browser_fill", "browser_select",
    "browser_set_checked", "browser_press", "browser_submit", "browser_close_tab",
    "browser_register", "browser_login",
)
_COMPUTER_BASE = (
    "computer_system_overview", "computer_performance_snapshot", "computer_process_list",
    "computer_disk_overview", "computer_service_overview", "computer_process_inventory",
)
_COMPUTER_CAPABILITIES = (
    (r"файл|папк|директор|file|folder|directory|архив|archive",
     ("computer_list_directory", "computer_search_files", "computer_search_everywhere",
      "computer_read_text_file", "computer_file_hash", "computer_open_folder",
      "computer_archive_inspect", "computer_archive_extract",
      "computer_plan_file_organization", "computer_apply_file_organization")),
    (r"окн|интерфейс|ui\b|desktop|скрин|screenshot|приложен|application",
     ("computer_ui_windows", "computer_ui_controls", "computer_ui_inputs",
      "computer_desktop_windows", "computer_desktop_tree", "computer_desktop_prepare",
      "computer_desktop_act", "computer_screenshot", "computer_open_app",
      "computer_ui_click", "computer_mouse_click", "computer_mouse_scroll",
      "computer_keyboard_type", "computer_keyboard_keypress")),
    (r"defender|антивирус|malware|вирус",
     ("computer_defender_status", "computer_defender_events",
      "computer_defender_scan", "computer_defender_scan_status")),
    (r"программ|пакет|установ|package|install",
     ("computer_installed_programs", "computer_package_search",
      "computer_package_details", "computer_package_install")),
    (r"автозагруз|startup|питани|power", ("computer_startup_items", "computer_power_overview")),
)
_DEVELOPER_READ = ("dev_workspace", "dev_list", "dev_read", "dev_search", "dev_diff")
_DEVELOPER_WRITE = ("dev_edit", "dev_move", "dev_delete", "dev_test", "dev_commit",
                    "dev_command", "dev_push", "dev_open_pr")


def route_model_tool_rows(
    rows: list[dict], task: str, *, limit: int, selected_groups=None
) -> list[dict]:
    """Prefer task-specific tools and deterministic order; retain manual groups.

    Never register a tool absent from the supplied registry or change its
    schema. Selection is not a grant of authorization.
    """
    if type(limit) is not int or limit < 1:
        return []
    task = task.casefold()
    valid = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("name"), str):
            valid.setdefault(row["name"], row)
    manual = normalize_tool_groups(selected_groups or [])
    denied_groups = set()
    denied_names = set()
    for neg in _ROUTE_NEGATION.finditer(task):
        first = re.match(r"[\w.-]+", task[neg.end():])
        if not first:
            continue
        word = first.group(0)
        denied_names.update(name for name in valid if name.casefold() == word)
        if re.match(r"^(?:терминал|команд|powershell|cmd|shell|terminal|консол)", word):
            denied_groups.add("terminal")
        elif re.match(r"^(?:браузер|browser|chrome|хром)", word):
            denied_groups.add("browser")
    exact = [
        name for name in valid
        if re.search(r"(?<![\w.-])" + re.escape(name.casefold()) + r"(?![\w.-])", task)
    ]
    selected = []
    seen = set()

    def add(names):
        for name in names:
            if name not in valid or name in seen or name in denied_names:
                continue
            group = tool_group_for_name(name)
            if group in denied_groups or (manual and group not in manual):
                continue
            if "terminal" in denied_groups and re.search(r"shell|command|terminal|powershell", name, re.I):
                continue
            seen.add(name)
            selected.append(valid[name])

    def group_names(group):
        return [name for name in valid if tool_group_for_name(name) == group]

    add(exact)
    if manual:
        for group in manual:
            add(group_names(group))
        return selected[:limit]

    # Inventory explicitly asks about the catalog, not a particular action.
    if re.search(r"доступн\w*\s+инструмент|список\s+инструмент|available\s+tools|list\s+tools|tools/list", task):
        for group in _ROUTE_HINTS:
            add(group_names(group))
        return selected[:limit]

    relevant = [group for group, pattern in _ROUTE_HINTS.items()
                if group not in denied_groups and re.search(pattern, task)]
    if (_DOMAIN.search(task) and "browser" not in relevant and "web" not in relevant
            and "network" not in denied_groups and "network" not in relevant):
        relevant.append("network")
    # A named tool alone needs no broad companion bundle.
    exact_groups = {tool_group_for_name(name) for name in exact}
    only_names = re.sub(r"[\w.-]+", lambda m: "" if m.group(0) in valid else m.group(0), task)
    focused_name = bool(exact) and bool(re.fullmatch(
        r"[\s.,:;!?]*(?:вызови|используй|call|use|invoke)?[\s.,:;!?]*", only_names))

    for group in relevant:
        if focused_name and group in exact_groups:
            continue
        if group == "browser":
            add(_BROWSER_READ)
            if re.search(r"клик|нажм|заполни|форм|выбер|войд|логин|регистрац|вход|submit|click|fill|login|register|interact|интерфейс", task):
                add(_BROWSER_INTERACT)
            if re.search(r"devtools|console|network|консол|сетев|трафик", task):
                add(("browser_console", "browser_network"))
        elif group == "computer":
            add(_COMPUTER_BASE)
            for pattern, names in _COMPUTER_CAPABILITIES:
                if re.search(pattern, task):
                    add(names)
        elif group == "terminal":
            add(("terminal_status", "terminal_run", "safe_terminal"))
        elif group == "developer":
            add(_DEVELOPER_READ)
            if re.search(r"исправ|измени|реализ|добав|напиши|доработ|тест|коммит|push|commit|edit|fix|implement|test", task):
                add(_DEVELOPER_WRITE)
        else:
            add(group_names(group))

    # Custom MCP services are not restricted to a static name allowlist.
    terms = set(re.findall(r"[a-z][a-z0-9]{2,}", task))
    for name in group_names("mcp"):
        if terms.intersection(re.split(r"[_.-]+", name.casefold())):
            add((name,))

    # Legacy small, remote-only catalogs and unclassified MCP tasks still
    # support discovery. Never refill a focused browsing/search selection
    # with unrelated shell or desktop tools.
    if not selected and not denied_groups and not denied_names:
        if len(valid) <= 16 and not any(name.startswith(("terminal_", "computer_", "browser_")) for name in valid):
            add(valid)
        else:
            add(group_names("mcp"))
            add(("computer_system_overview", "local_webui_health", "gateway_status"))
    return selected[:limit]

def tool_group_summary(tool_names) -> list[dict]:
    names = {name for name in tool_names if isinstance(name, str)}
    counts = {group["id"]: 0 for group in TOOL_GROUPS}
    for name in names:
        counts[tool_group_for_name(name)] += 1
    return [
        {**group, "count": counts[group["id"]], "available": counts[group["id"]] > 0}
        for group in TOOL_GROUPS
    ]


def _safe_fill_owner_input(session, label, value, input_type, expected_origin=""):
    try:
        return session.fill_owner_input(label, value, input_type, expected_origin)
    except Exception as exc:
        # Playwright exception text can echo a form value. Never propagate it.
        raise ValueError("protected_browser_fill_failed:" + type(exc).__name__) from None


def _safe_fill_payment_card(session, card, expected_origin, field_hosts, approved_hosts):
    try:
        return session.fill_owner_payment_card(
            card, expected_origin, field_hosts, approved_hosts,
        )
    except Exception as exc:
        # Payment data must never be copied into an exception, event or model result.
        raise ValueError("protected_payment_fill_failed:" + type(exc).__name__) from None


def _wipe_payment_card(card):
    if isinstance(card, dict):
        for key in list(card):
            card[key] = ""
        card.clear()


def _clear_payment_form_for_owner(session):
    try:
        return session.clear_payment_form()
    except Exception:
        return {"ok": False, "cleared_fields": []}


def _confirm_browser_write(conversation_key, details):
    if not isinstance(conversation_key, str) or not conversation_key:
        return False
    if not isinstance(details, dict):
        return False
    method = str(details.get("method") or "UNKNOWN").upper()[:16]
    request_label = str(details.get("request_label") or (method + " request"))[:120]
    page_origin = details.get("page_origin")
    target_origin = details.get("target_origin")
    action_label = str(details.get("action_label") or "browser action")[:120]
    resource_type = str(details.get("resource_type") or "other")[:40]
    purpose = (
        "Действие «" + action_label + "» инициировало " + resource_type
        + ": " + request_label + ". Подтверждение разрешает только этот запрос."
    )[:240]
    try:
        pending = owner_input_broker.request_and_wait(
            conversation_key, purpose, "browser_action_confirmation",
            request_label, timeout=300, expected_origin=page_origin,
            action_origin=target_origin, action_button=request_label,
        )
        if not pending.get("ok"):
            return False
        decision, expected, target, button = owner_input_broker.consume_browser_action_confirmation(
            conversation_key, pending["request_id"]
        )
        return bool(
            decision and expected == page_origin
            and target == target_origin and button == request_label
        )
    except Exception:
        return False


def extract_user_targets(messages: list[dict]) -> set[str]:
    """Only allow active host checks against targets explicitly named by the user."""
    text = "\n".join(
        str(item.get("content") or "")
        for item in messages if isinstance(item, dict) and item.get("role") == "user"
    )
    targets = {x.lower().rstrip(".") for x in _DOMAIN.findall(text)}
    if re.search(r"(?i)\blocalhost\b", text):
        targets.add("localhost")
    for raw in _IPV4.findall(text):
        try:
            ipaddress.ip_address(raw)
            targets.add(raw.lower())
        except ValueError:
            pass
    return targets


def _function_tool(name: str, description: str, parameters: dict) -> dict:
    return {
        "type": "function",
        "name": name,
        "description": description,
        "parameters": parameters,
        "strict": True,
    }


def _convert_mcp_tool(item: dict) -> dict:
    description = item.get("description", "")
    if item["name"] == "browser_click_button":
        description += (
            " In Account GPT, high-impact confirmation actions cannot be submitted; "
            "stop and ask the user to perform or explicitly authorize the action."
        )
    return _function_tool(
        item["name"], description[:1100],
        item.get("inputSchema") or {
            "type": "object", "properties": {}, "required": [],
            "additionalProperties": False,
        },
    )


def build_tool_catalog() -> list[dict]:
    """Shared reviewed local tool catalog for Account GPT and DeepSeek."""
    terminal_schema = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": (
                    "Arbitrary Windows CMD or PowerShell command, including multiple commands, "
                    "pipes, redirects, variables and multiline scripts. Runs as the current "
                    "Cybernova backend user. Do not use it to read credentials, cookies, private "
                    "keys or unrelated personal data. Do not attempt privilege escalation. "
                    "Ask before destructive or irreversible changes unless the user explicitly "
                    "requested that exact operation."
                ),
            },
            "shell": {"type": "string", "enum": ["cmd", "powershell", "pwsh"]},
            "cwd": {
                "type": "string",
                "description": "Working directory. Empty string uses the current user's home directory.",
            },
            "timeout_seconds": {
                "type": "integer", "minimum": 1, "maximum": 300,
                "description": "Execution timeout from 1 to 300 seconds.",
            },
            "max_output_chars": {
                "type": "integer", "minimum": 1000, "maximum": 50000,
                "description": "Maximum combined stdout/stderr characters returned.",
            },
        },
        "required": ["command", "shell", "cwd", "timeout_seconds", "max_output_chars"],
        "additionalProperties": False,
    }
    status_schema = {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    }
    rows = [
        _function_tool(
            "terminal_run",
            "Run arbitrary Windows CMD, Windows PowerShell 5.1, or PowerShell 7 commands and multiline scripts on the local machine hosting Cybernova. No command allowlist: supports navigation, file operations, search, diagnostics, package tools, scripts, pipes and redirects. Runs with the backend process's current Windows permissions; it does not silently elevate. Output is bounded and redacted.",
            terminal_schema,
        ),
        _function_tool(
            "terminal_status",
            "Detect local Windows CMD, Windows PowerShell 5.1 and PowerShell 7 availability, process elevation state, and installed computer-control dependencies. Does not expose environment variables or secrets.",
            status_schema,
        ),
    ]
    rows.extend(_convert_mcp_tool(item) for item in BROWSER_CONTROL_TOOLS)
    rows.extend(_convert_mcp_tool(item) for item in RESEARCH_WEB_TOOLS)
    rows.extend(_convert_mcp_tool(item) for item in COMPUTER_TOOLS)
    rows.extend(_convert_mcp_tool(item) for item in GITHUB_TOOLS)
    rows.extend(_convert_mcp_tool(item) for item in GITHUB_WRITE_TOOLS)
    mission_statuses = sorted(MISSION_STATUSES)
    step_statuses = sorted(STEP_STATUSES)
    rows.extend([
        _function_tool(
            "account_mission_create",
            "Create a durable account-setup mission. Stores only non-secret goal and success criteria in the local SQLite data store. Use for multi-step registrations or service setup; never put passwords, OTPs, cookies, API keys, payment data or verification URLs with tokens in mission text.",
            {"type": "object", "properties": {
                "service": {"type": "string", "maxLength": 120},
                "goal": {"type": "string", "maxLength": 2000},
                "success_criteria": {"type": "string", "maxLength": 1200},
            }, "required": ["service", "goal", "success_criteria"], "additionalProperties": False},
        ),
        _function_tool(
            "account_mission_checkpoint",
            "Persist one idempotent account-setup checkpoint. Record only a short sanitized summary and next action, never secrets or raw page contents. Mark an external action started before it happens and completed only after verifying the provider's state. Use waiting_owner for SMS/OTP or a required owner input. page_url must be the clean HTTPS page URL; query strings and tokens are stripped.",
            {"type": "object", "properties": {
                "mission_id": {"type": "string", "maxLength": 100},
                "step_key": {"type": "string", "maxLength": 80},
                "step_name": {"type": "string", "maxLength": 160},
                "step_status": {"type": "string", "enum": step_statuses},
                "summary": {"type": "string", "maxLength": 1200},
                "next_action": {"type": "string", "maxLength": 600},
                "page_url": {"type": "string", "maxLength": 2048},
                "mission_status": {"type": "string", "enum": [""] + mission_statuses},
            }, "required": ["mission_id", "step_key", "step_name", "step_status",
                           "summary", "next_action", "page_url", "mission_status"],
               "additionalProperties": False},
        ),
        _function_tool(
            "account_mission_get",
            "Read one account mission and its ordered checkpoints. Use this after a restart or when returning to a previous account task. If resume_requires_reconciliation is true, inspect the provider's current state before repeating the last action.",
            {"type": "object", "properties": {
                "mission_id": {"type": "string", "maxLength": 100},
            }, "required": ["mission_id"], "additionalProperties": False},
        ),
        _function_tool(
            "account_mission_list",
            "List recent account missions. Use at the start of a new account-setup request to find an existing matching mission rather than creating a duplicate. Empty status means all statuses.",
            {"type": "object", "properties": {
                "status": {"type": "string", "enum": [""] + mission_statuses},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            }, "required": ["status", "limit"], "additionalProperties": False},
        ),
        _function_tool(
            "account_mission_resume",
            "Explicitly resume a blocked or waiting account mission. This changes only the mission status; it does NOT replay any browser action. Read the returned checkpoints and reconcile the live provider state first.",
            {"type": "object", "properties": {
                "mission_id": {"type": "string", "maxLength": 100},
            }, "required": ["mission_id"], "additionalProperties": False},
        ),
        _function_tool(
            "owner_request_input",
            "Pause the current task and request one sensitive value through Cybernova's local protected dialog. Allowed types: otp, password, contact. The value is never returned to the model or written to logs/files. For a password, set offer_vault_save=true to show the owner an optional local encrypted-vault checkbox. The request is bound to the current HTTPS origin and conversation. This generic tool is not for payment cards; use browser_request_and_fill_payment_card for an observed HTTPS card form.",
            {"type": "object", "properties": {
                "purpose": {"type": "string", "maxLength": 240},
                "input_type": {"type": "string", "enum": ["otp", "password", "contact"]},
                "field_label": {"type": "string", "maxLength": 120},
                "offer_vault_save": {"type": "boolean"},
                "service": {"type": "string", "maxLength": 120},
                "username": {"type": "string", "maxLength": 254},
                "account_label": {"type": "string", "maxLength": 120},
            }, "required": ["purpose", "input_type", "field_label", "offer_vault_save",
                           "service", "username", "account_label"], "additionalProperties": False},
        ),
        _function_tool(
            "browser_fill_owner_input",
            "Fill one owner-supplied password, one-time code, or contact value. The secret is fetched internally, origin-checked and never returned to the model. The request can be consumed once.",
            {"type": "object", "properties": {
                "request_id": {"type": "string", "maxLength": 80},
                "field_label": {"type": "string", "maxLength": 120},
            }, "required": ["request_id", "field_label"], "additionalProperties": False},
        ),
        _function_tool(
            "browser_request_and_fill_payment_card",
            "When a user-requested account registration or payment reaches a card form, inspect the visible payment fields and request card details in Cybernova's protected in-chat dialog. The owner sees the merchant and any cross-origin payment-frame hosts and explicitly approves those hosts. Card number, expiry, CVV and cardholder data stay in memory only, are filled directly into the current HTTPS form, are never returned to the model, and are never saved. Do not use for a purchase or subscription.",
            {"type": "object", "properties": {
                "purpose": {"type": "string", "maxLength": 240},
            }, "required": ["purpose"], "additionalProperties": False},
        ),
        _function_tool(
            "browser_generate_and_fill_password",
            "Generate a strong random password locally, save it encrypted in the account vault, and fill the currently visible password field. The password is NEVER returned to the model or tool result. Use only during a user-requested account creation. The record starts pending until account creation and sign-in are verified.",
            {"type": "object", "properties": {
                "service": {"type": "string", "maxLength": 120},
                "username": {"type": "string", "maxLength": 254},
                "account_label": {"type": "string", "maxLength": 120},
                "field_label": {"type": "string", "maxLength": 120},
            }, "required": ["service", "username", "account_label", "field_label"],
               "additionalProperties": False},
        ),
        _function_tool(
            "browser_fill_saved_credential",
            "Retrieve one password internally from the encrypted account vault and fill a visible password field only when the current HTTPS origin exactly matches the stored service origin. The password is never returned to the model.",
            {"type": "object", "properties": {
                "record_id": {"type": "string", "maxLength": 100},
                "field_label": {"type": "string", "maxLength": 120},
            }, "required": ["record_id", "field_label"], "additionalProperties": False},
        ),
        _function_tool(
            "account_vault_list",
            "List account-vault metadata only: service, username, origin, status and record ID. Passwords and encryption material are never returned.",
            {"type": "object", "properties": {
                "service": {"type": "string", "maxLength": 120},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            }, "required": ["service", "limit"], "additionalProperties": False},
        ),
        _function_tool(
            "account_vault_mark_verified",
            "Mark a pending credential record active only after the account was created, sign-in was verified, and the service identity matches. Does not expose the password.",
            {"type": "object", "properties": {
                "record_id": {"type": "string", "maxLength": 100},
            }, "required": ["record_id"], "additionalProperties": False},
        ),
    ])
    return rows


def _decode_cmd_output(value: bytes) -> str:
    try:
        return value.decode("oem", errors="replace")
    except LookupError:
        return value.decode("utf-8", errors="replace")


def _redact_output(value: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    value = _SECRET.sub("[REDACTED]", value)
    value = _EMAIL.sub("[REDACTED EMAIL]", value)
    return value[:max(1000, min(int(limit), MAX_TOOL_OUTPUT_CHARS))]


def _shell_executable(shell: str) -> str:
    if platform.system() != "Windows":
        raise ValueError("local_windows_terminal_unavailable")
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    if shell == "cmd":
        candidate = shutil.which("cmd.exe") or str(Path(system_root) / "System32" / "cmd.exe")
    elif shell == "powershell":
        candidate = shutil.which("powershell.exe") or str(
            Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        )
    elif shell == "pwsh":
        candidate = shutil.which("pwsh.exe") or shutil.which("pwsh") or ""
    else:
        raise ValueError("terminal_shell_invalid")
    if not candidate or not Path(candidate).is_file():
        raise ValueError("terminal_shell_not_installed:" + shell)
    return candidate


def _terminal_argv(shell: str, executable: str, command: str) -> list[str]:
    if shell == "cmd":
        return [executable, "/d", "/s", "/c", command]
    return [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]


def _validate_terminal_request(command: object, shell: object, cwd: object,
                               timeout_seconds: object, max_output_chars: object) -> tuple[str, str, Path, int, int]:
    if not isinstance(command, str) or not command.strip() or len(command) > MAX_TERMINAL_COMMAND_CHARS:
        raise ValueError("terminal_command_invalid_or_too_large")
    if "\x00" in command:
        raise ValueError("terminal_command_contains_nul")
    if shell not in {"cmd", "powershell", "pwsh"}:
        raise ValueError("terminal_shell_invalid")
    if not isinstance(cwd, str) or len(cwd) > 1000:
        raise ValueError("terminal_working_directory_invalid")
    timeout = int(timeout_seconds) if type(timeout_seconds) is int else 0
    if not 1 <= timeout <= MAX_TERMINAL_TIMEOUT_SECONDS:
        raise ValueError("terminal_timeout_out_of_range")
    output_limit = int(max_output_chars) if type(max_output_chars) is int else 0
    if not 1000 <= output_limit <= MAX_TOOL_OUTPUT_CHARS:
        raise ValueError("terminal_output_limit_out_of_range")
    raw_cwd = os.path.expandvars(os.path.expanduser(cwd.strip())) if cwd.strip() else str(Path.home())
    working_dir = Path(raw_cwd)
    if not working_dir.is_absolute():
        working_dir = Path.home() / working_dir
    try:
        working_dir = working_dir.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("terminal_working_directory_not_found") from None
    if not working_dir.is_dir():
        raise ValueError("terminal_working_directory_not_directory")
    return command, shell, working_dir, timeout, output_limit


def _terminal_environment() -> dict[str, str]:
    env = dict(os.environ)
    sensitive_name = re.compile(
        r"(?i)(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|COOKIE|AUTH)"
    )
    for key in list(env):
        if sensitive_name.search(key):
            env.pop(key, None)
    return env


def _run_terminal(command: str, shell: str = "cmd", cwd: str = "",
                  timeout_seconds: int = 60, max_output_chars: int = 20000) -> dict:
    if platform.system() != "Windows":
        return {
            "ok": False, "error": "local_windows_terminal_unavailable",
            "execution_host": platform.system().lower(),
        }
    command, shell, working_dir, timeout, output_limit = _validate_terminal_request(
        command, shell, cwd, timeout_seconds, max_output_chars,
    )
    try:
        executable = _shell_executable(shell)
        argv = _terminal_argv(shell, executable, command)
    except ValueError as exc:
        return {"ok": False, "error": str(exc), "shell": shell}
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv, cwd=str(working_dir), shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_terminal_environment(), creationflags=creationflags,
        )
    except OSError as exc:
        return {
            "ok": False, "error": type(exc).__name__, "shell": shell,
            "cwd": str(working_dir),
        }
    timed_out = False
    try:
        stdout_raw, stderr_raw = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        taskkill = shutil.which("taskkill.exe") or str(
            Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")
            / "System32" / "taskkill.exe"
        )
        try:
            if Path(taskkill).is_file():
                subprocess.run(
                    [taskkill, "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=8, check=False,
                )
            else:
                process.kill()
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass
        try:
            stdout_raw, stderr_raw = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout_raw, stderr_raw = b"", b""
    stdout = _decode_cmd_output(stdout_raw or b"")
    stderr = _decode_cmd_output(stderr_raw or b"")
    combined = stdout + (("\n" if stdout and stderr else "") + stderr)
    output = _redact_output(combined, output_limit)
    truncated = len(combined) > output_limit
    return {
        "ok": process.returncode == 0 and not timed_out,
        "command": _SECRET.sub("[REDACTED]", _EMAIL.sub("[REDACTED EMAIL]", command))[:500],
        "shell": {"cmd": "Windows CMD", "powershell": "Windows PowerShell", "pwsh": "PowerShell 7"}[shell],
        "shell_id": shell,
        "cwd": str(working_dir),
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "output": output,
        "output_truncated": truncated,
        "execution_host": "local_windows",
        "execution_identity": "current_backend_process_token",
        "elevated": None,
    }


class BrowserSessionPool:
    """Bounded per-conversation Chromium sessions with idle LRU eviction.

    Conversation identifiers are hashed before they become directory names.
    Eviction closes browser processes but deliberately retains profile data.
    """

    def __init__(self, profile_root: str | Path, *,
                 session_factory=BrowserSession,
                 max_sessions: int = MAX_BROWSER_SESSIONS,
                 idle_seconds: int = BROWSER_SESSION_IDLE_SECONDS,
                 clock=None):
        if type(max_sessions) is not int or not 1 <= max_sessions <= 32:
            raise ValueError("browser_session_limit_invalid")
        if type(idle_seconds) is not int or not 60 <= idle_seconds <= 86400:
            raise ValueError("browser_session_idle_timeout_invalid")
        self.profile_root = Path(profile_root).expanduser()
        self.session_factory = session_factory
        self.max_sessions = max_sessions
        self.idle_seconds = idle_seconds
        self._clock = clock or time.monotonic
        self._lock = RLock()
        self._sessions: OrderedDict[str, dict] = OrderedDict()

    @staticmethod
    def _key(conversation_key: str | None) -> str:
        if not isinstance(conversation_key, str) or not conversation_key.strip() \
                or len(conversation_key) > 256 or "\x00" in conversation_key:
            raise ValueError("browser_conversation_required")
        return hashlib.sha256(conversation_key.encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _close_entries(entries: list[dict]) -> None:
        for entry in entries:
            try:
                entry["session"].close()
            except Exception:
                pass

    def acquire(self, conversation_key: str | None) -> tuple[str, dict]:
        key = self._key(conversation_key)
        now = self._clock()
        retired: list[dict] = []
        selected = None
        with self._lock:
            for old_key, old_entry in list(self._sessions.items()):
                if old_entry["active"] == 0 and now - old_entry["last_used"] >= self.idle_seconds:
                    retired.append(self._sessions.pop(old_key))
            selected = self._sessions.get(key)
            if selected is not None:
                selected["active"] += 1
                selected["last_used"] = now
                self._sessions.move_to_end(key)
        self._close_entries(retired)

        if selected is not None:
            return key, selected

        retired = []
        with self._lock:
            # Another caller may have created this conversation while stale
            # sessions were being closed.
            selected = self._sessions.get(key)
            if selected is not None:
                selected["active"] += 1
                selected["last_used"] = self._clock()
                self._sessions.move_to_end(key)
            else:
                if len(self._sessions) >= self.max_sessions:
                    idle_key = next(
                        (candidate for candidate, entry in self._sessions.items()
                         if entry["active"] == 0),
                        None,
                    )
                    if idle_key is not None:
                        retired.append(self._sessions.pop(idle_key))
                if len(self._sessions) >= self.max_sessions:
                    selected = None
                else:
                    profile_dir = self.profile_root / "conversations" / key
                    session = self.session_factory(profile_dir=profile_dir)
                    selected = {
                        "session": session, "profile_dir": profile_dir,
                        "active": 1, "last_used": self._clock(),
                        "call_lock": RLock(),
                    }
                    self._sessions[key] = selected
        self._close_entries(retired)
        if selected is None:
            raise ValueError("browser_session_capacity_reached")
        return key, selected

    def release(self, key: str, entry: dict) -> None:
        retired = None
        with self._lock:
            current = self._sessions.get(key)
            if current is not entry:
                return
            current["active"] = max(0, current["active"] - 1)
            current["last_used"] = self._clock()
            if current["active"] == 0 and current.get("close_when_idle"):
                retired = self._sessions.pop(key)
            else:
                self._sessions.move_to_end(key)
        if retired is not None:
            self._close_entries([retired])

    def close_conversation(self, conversation_key: str) -> None:
        key = self._key(conversation_key)
        retired = None
        with self._lock:
            current = self._sessions.get(key)
            if current is None:
                return
            if current["active"] == 0:
                retired = self._sessions.pop(key)
            else:
                current["close_when_idle"] = True
        if retired is not None:
            self._close_entries([retired])

    def close(self) -> None:
        with self._lock:
            entries = list(self._sessions.values())
            self._sessions.clear()
        self._close_entries(entries)

    @property
    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)


class GPTToolRuntime:
    """Shared local tool catalog with isolated Chromium per model conversation."""

    def __init__(self, browser_profile_dir: str | Path | None = None, *,
                 browser_session_factory=BrowserSession,
                 max_browser_sessions: int = MAX_BROWSER_SESSIONS,
                 browser_idle_seconds: int = BROWSER_SESSION_IDLE_SECONDS):
        self._lock = RLock()
        self.browser_profile_dir = (
            Path(browser_profile_dir).expanduser()
            if browser_profile_dir is not None else _browser_profile_path("gpt")
        )
        self._browser_pool = BrowserSessionPool(
            self.browser_profile_dir,
            session_factory=browser_session_factory,
            max_sessions=max_browser_sessions,
            idle_seconds=browser_idle_seconds,
        )
        self.tools = build_tool_catalog()
        self.tool_map = {item["name"]: item for item in self.tools}

    @property
    def explicit_only_tools(self) -> tuple[str, ...]:
        return tuple(sorted(EXPLICIT_ONLY_TOOLS))

    def tools_for_groups(self, groups=None) -> list[dict]:
        """Auto mode omits tools that require an explicit group selection."""
        selected = set(normalize_tool_groups(groups))
        rows = filter_tool_rows(self.tools, groups)
        if "terminal" not in selected and EXPLICIT_ONLY_TOOLS:
            rows = [item for item in rows if item["name"] not in EXPLICIT_ONLY_TOOLS]
        return rows

    def mcp_tools(self, groups=None) -> list[dict]:
        """Expose only the tools allowed by the user's current group selection."""
        return [
            {
                "name": item["name"],
                "description": item["description"],
                "inputSchema": item["parameters"],
            }
            for item in self.tools_for_groups(groups)
        ]

    def call(self, name: str, args: dict, *, authorized_targets=None,
             user_messages=None, enabled_groups=None,
             conversation_key: str | None = None) -> tuple[dict, bool]:
        """Record tool lifecycle without storing arguments or response content."""
        start = time.monotonic()
        diagnostic_event("tool_call_start", tool=name)
        try:
            result, failed = self._call_impl(
                name, args, authorized_targets=authorized_targets,
                user_messages=user_messages, enabled_groups=enabled_groups,
                conversation_key=conversation_key)
        except BaseException as exc:
            diagnostic_event("tool_call_failed", tool=name,
                             duration_ms=round((time.monotonic() - start) * 1000),
                             error_type=type(exc).__name__)
            raise
        fields = {"tool": name, "status": tool_outcome(result, failed),
                  "duration_ms": round((time.monotonic() - start) * 1000)}
        if isinstance(result, dict):
            if type(result.get("http_status")) is int:
                fields["http_status"] = result["http_status"]
            if fields["status"] == "failed":
                fields["error_type"] = "ToolResultError"
        diagnostic_event("tool_call_completed", **fields)
        return result, failed

    def _call_impl(self, name: str, args: dict, *, authorized_targets=None,
                   user_messages=None, enabled_groups=None,
                   conversation_key: str | None = None) -> tuple[dict, bool]:
        selected = set(normalize_tool_groups(enabled_groups))
        if selected and tool_group_for_name(name) not in selected:
            return {"ok": False, "error": "tool_group_not_enabled"}, True
        if name in EXPLICIT_ONLY_TOOLS and "terminal" not in selected:
            return {"ok": False, "error": "terminal_run_requires_explicit_group_selection"}, True
        if name not in _TOOL_NAMES or name not in self.tool_map:
            return {"ok": False, "error": "gpt_tool_not_registered"}, True
        if not isinstance(args, dict):
            return {"ok": False, "error": "tool_arguments_must_be_object"}, True
        try:
            if name in GITHUB_NAMES:
                return github_call(name, args)
            if name in GITHUB_WRITE_NAMES:
                return github_write_call(name, args, user_messages=user_messages)
            if name.startswith("account_mission_"):
                missions = account_mission_store()
                if name == "account_mission_create":
                    result = missions.create(
                        args.get("service"), args.get("goal"), args.get("success_criteria", "")
                    )
                    return {"ok": True, "mission": result}, False
                if name == "account_mission_checkpoint":
                    result = missions.checkpoint(
                        args.get("mission_id"), args.get("step_key"), args.get("step_name"),
                        args.get("step_status"), args.get("summary"),
                        args.get("next_action", ""), args.get("page_url", ""),
                        args.get("mission_status") or None,
                    )
                    return {"ok": True, "mission": result}, False
                if name == "account_mission_get":
                    return {"ok": True, "mission": missions.get(args.get("mission_id"))}, False
                if name == "account_mission_list":
                    return {"ok": True, "missions": missions.list(
                        args.get("status") or None, args.get("limit", 20)
                    )}, False
                if name == "account_mission_resume":
                    return {"ok": True, "mission": missions.resume(args.get("mission_id"))}, False
            if name == "owner_request_input":
                if not isinstance(conversation_key, str) or not conversation_key:
                    return {"ok": False, "error": "owner_input_session_unavailable"}, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        entry["session"].set_authorized_hosts(authorized_targets or set())
                        origin = entry["session"].current_origin()
                finally:
                    self._browser_pool.release(key, entry)
                result = owner_input_broker.request_and_wait(
                    conversation_key, args.get("purpose"), args.get("input_type"),
                    args.get("field_label"), timeout=300, expected_origin=origin,
                    offer_vault_save=args.get("offer_vault_save", False),
                    service=args.get("service", ""), username=args.get("username", ""),
                    account_label=args.get("account_label", ""),
                )
                return result, not bool(result.get("ok"))
            if name == "browser_request_and_fill_payment_card":
                user_text = " ".join(
                    str(message.get("content") or "")
                    for message in (user_messages or [])
                    if isinstance(message, dict) and message.get("role") == "user"
                )
                if not re.search(
                    r"(?i)(?:create.{0,50}account|register|sign[ -]?up|"
                    r"создай.{0,50}аккаунт|зарегистр|регай|заведи.{0,50}аккаунт|"
                    r"оплат|платеж|payment|checkout|purchase|billing|\bcard\b|"
                    r"добавить карту|привязать карту|карточк)",
                    user_text,
                ):
                    return {"ok": False, "error": "explicit_account_or_payment_intent_required"}, True
                if not isinstance(conversation_key, str) or not conversation_key:
                    return {"ok": False, "error": "browser_conversation_required"}, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        session = entry["session"]
                        session.set_authorized_hosts(authorized_targets or set())
                        form_info = session.inspect_payment_form()
                finally:
                    self._browser_pool.release(key, entry)
                request = owner_input_broker.request_and_wait(
                    conversation_key, args.get("purpose"), "payment_card",
                    "Данные банковской карты", timeout=300,
                    expected_origin=form_info["origin"],
                    payment_fields=form_info["fields"],
                    payment_field_hosts=form_info["field_hosts"],
                )
                if not request.get("ok"):
                    return request, True
                card = None
                try:
                    card, origin, field_hosts, approved_hosts = owner_input_broker.consume_payment_card(
                        conversation_key, request["request_id"]
                    )
                    key, entry = self._browser_pool.acquire(conversation_key)
                    try:
                        with entry["call_lock"]:
                            session = entry["session"]
                            session.set_authorized_hosts(authorized_targets or set())
                            result = _safe_fill_payment_card(
                                session, card, origin, field_hosts, approved_hosts,
                            )
                            result["owner_input_consumed"] = True
                            return result, not bool(result.get("ok"))
                    finally:
                        self._browser_pool.release(key, entry)
                finally:
                    _wipe_payment_card(card)
            if name == "browser_submit_payment":
                if not isinstance(conversation_key, str) or not conversation_key:
                    return {"ok": False, "error": "browser_conversation_required"}, True
                button_name = args.get("name")
                purpose = args.get("purpose")
                if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 240:
                    return {"ok": False, "error": "payment_confirmation_summary_required"}, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        session = entry["session"]
                        session.set_authorized_hosts(authorized_targets or set())
                        target = session.inspect_submit_target(button_name)
                finally:
                    self._browser_pool.release(key, entry)
                if not target.get("payment_target"):
                    return {"ok": False, "error": "payment_submit_target_not_recognized"}, True
                request = owner_input_broker.request_and_wait(
                    conversation_key, purpose, "payment_confirmation",
                    button_name, timeout=300,
                    expected_origin=target["merchant_origin"],
                    action_origin=target["action_origin"],
                    action_button=button_name,
                )
                if not request.get("ok"):
                    key, entry = self._browser_pool.acquire(conversation_key)
                    try:
                        with entry["call_lock"]:
                            session = entry["session"]
                            session.set_authorized_hosts(authorized_targets or set())
                            _clear_payment_form_for_owner(session)
                    finally:
                        self._browser_pool.release(key, entry)
                    return request, True
                decision, origin, action_origin, approved_button = (
                    owner_input_broker.consume_payment_confirmation(
                        conversation_key, request["request_id"]
                    )
                )
                if not decision:
                    key, entry = self._browser_pool.acquire(conversation_key)
                    try:
                        with entry["call_lock"]:
                            session = entry["session"]
                            session.set_authorized_hosts(authorized_targets or set())
                            _clear_payment_form_for_owner(session)
                    finally:
                        self._browser_pool.release(key, entry)
                    return {"ok": False, "status": "owner_declined_payment_action"}, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        session = entry["session"]
                        session.set_authorized_hosts(authorized_targets or set())
                        result = session.submit_payment_after_owner_approval(
                            approved_button, origin, action_origin,
                        )
                        return result, not bool(result.get("ok"))
                finally:
                    self._browser_pool.release(key, entry)
            if name == "browser_fill_owner_input":
                if not isinstance(conversation_key, str) or not conversation_key:
                    return {"ok": False, "error": "owner_input_session_unavailable"}, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        entry["session"].set_authorized_hosts(authorized_targets or set())
                        input_type, value, expected_origin = owner_input_broker.consume(
                            conversation_key, args.get("request_id")
                        )
                        result = _safe_fill_owner_input(
                            entry["session"], args.get("field_label"), value,
                            input_type, expected_origin,
                        )
                        result["owner_input_consumed"] = True
                        return result, not bool(result.get("ok"))
                finally:
                    self._browser_pool.release(key, entry)
            if name == "browser_generate_and_fill_password":
                user_text = " ".join(
                    str(message.get("content") or "")
                    for message in (user_messages or [])
                    if isinstance(message, dict) and message.get("role") == "user"
                )
                if not re.search(
                    r"(?i)(?:\bcreate\b.{0,50}\baccount\b|\bregister\b|"
                    r"\bsign[\s-]?up\b|создай.{0,50}аккаунт|зарегистр|регай|"
                    r"заведи.{0,50}аккаунт)",
                    user_text,
                ):
                    return {"ok": False, "error": "account_creation_intent_required"}, True
                if not isinstance(conversation_key, str) or not conversation_key:
                    return {"ok": False, "error": "browser_conversation_required"}, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        session = entry["session"]
                        session.set_authorized_hosts(authorized_targets or set())
                        origin = session.current_origin()
                        symbols = "!@#$%^&*_-+="
                        chars = [
                            secrets.choice(string.ascii_uppercase),
                            secrets.choice(string.ascii_lowercase),
                            secrets.choice(string.digits),
                            secrets.choice(symbols),
                        ] + [secrets.choice(string.ascii_letters + string.digits + symbols)
                             for _ in range(24)]
                        secrets.SystemRandom().shuffle(chars)
                        password = "".join(chars)
                        record = account_vault().store_password(
                            args.get("service"), args.get("username"), password,
                            origin, args.get("account_label", ""),
                        )
                        result = _safe_fill_owner_input(
                            session, args.get("field_label"), password, "password", origin
                        )
                        result["credential_record"] = record
                        result["password_generated_locally"] = True
                        return result, not bool(result.get("ok"))
                finally:
                    self._browser_pool.release(key, entry)
            if name == "browser_fill_saved_credential":
                if not isinstance(conversation_key, str) or not conversation_key:
                    return {"ok": False, "error": "browser_conversation_required"}, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        session = entry["session"]
                        session.set_authorized_hosts(authorized_targets or set())
                        origin = session.current_origin()
                        record, password = account_vault()._secret_for_browser_fill(
                            args.get("record_id"), origin
                        )
                        result = _safe_fill_owner_input(
                            session, args.get("field_label"), password,
                            "password", record["origin"],
                        )
                        result["credential_record"] = record
                        result["saved_credential_filled"] = True
                        return result, not bool(result.get("ok"))
                finally:
                    self._browser_pool.release(key, entry)
            if name == "account_vault_list":
                return {"ok": True, "entries": account_vault().list_entries(
                    args.get("limit", 30), args.get("service", "")
                )}, False
            if name == "account_vault_mark_verified":
                return {"ok": True, "entry": account_vault().mark_verified(
                    args.get("record_id")
                )}, False
            # Browser operations use their own per-conversation lock and worker
            # thread. They never hold the runtime-wide lock while Playwright runs.
            if name.startswith("browser_"):
                if name in APPROVAL_TOOL_NAMES and (
                        not isinstance(conversation_key, str) or not conversation_key):
                    return {
                        "ok": False, "error": "browser_conversation_required_for_write_approval",
                    }, True
                key, entry = self._browser_pool.acquire(conversation_key)
                try:
                    with entry["call_lock"]:
                        session = entry["session"]
                        session.set_authorized_hosts(authorized_targets or set())
                        setter = getattr(session, "set_write_approval_handler", None)
                        if callable(setter):
                            setter(lambda details: _confirm_browser_write(conversation_key, details))
                        return browser_control_call(name, args, session)
                finally:
                    self._browser_pool.release(key, entry)

            with self._lock:
                if name == "terminal_status":
                    if args:
                        raise ValueError("terminal_status_takes_no_arguments")
                    windows = platform.system() == "Windows"
                    shell_paths = {}
                    if windows:
                        for shell_id in ("cmd", "powershell", "pwsh"):
                            try:
                                shell_paths[shell_id] = _shell_executable(shell_id)
                            except ValueError:
                                shell_paths[shell_id] = None
                    cmd_exe = bool(shell_paths.get("cmd"))
                    modules = {}
                    for module in ("psutil", "pyautogui", "pywinauto", "win32com", "playwright"):
                        try:
                            modules[module] = importlib.util.find_spec(module) is not None
                        except (ImportError, ModuleNotFoundError, ValueError):
                            modules[module] = False
                    return {
                        "ok": True, "os": platform.system(),
                        "cmd_exe": cmd_exe,
                        "terminal": "Windows CMD" if windows and cmd_exe else None,
                        "shells": shell_paths,
                        "powershell_5_1": bool(shell_paths.get("powershell")),
                        "powershell_7": bool(shell_paths.get("pwsh")),
                        "execution_host": "local_windows" if windows else "remote_or_non_windows",
                        "computer_tool_dependencies": modules,
                        "computer_tool_dependencies_ready": all(
                            modules.get(item, False)
                            for item in ("psutil", "pyautogui", "pywinauto", "win32com")
                        ) if windows else False,
                    }, False
                if name == "terminal_run":
                    required = {"command", "shell", "cwd", "timeout_seconds", "max_output_chars"}
                    if set(args) != required:
                        raise ValueError("terminal_arguments_invalid")
                    result = _run_terminal(
                        args["command"], args["shell"], args["cwd"],
                        args["timeout_seconds"], args["max_output_chars"],
                    )
                    return result, not bool(result.get("ok"))
                if name in COMPUTER_TOOL_NAMES:
                    return computer_control_call(name, args, user_messages=user_messages)
                if name in {"google_search", "research_source_open"}:
                    return research_web_call(name, args)
                raise ValueError("gpt_tool_not_implemented")
        except Exception as exc:
            error_id = uuid.uuid4().hex[:12]
            detail = _SECRET.sub("[REDACTED]", _EMAIL.sub("[REDACTED EMAIL]", str(exc)))
            # Raw tracebacks can embed user input and site content. Keep only
            # traceback frame metadata in the private journal.
            logger.error("tool_failure id=%s tool=%s type=%s",
                         error_id, name, type(exc).__name__)
            diagnostic_failure("console", "tool_" + name, exc, error_id=error_id)
            return {
                "ok": False,
                "error": type(exc).__name__ + ":" + detail[:400],
                "error_id": error_id,
            }, True

    def close_conversation(self, conversation_key: str) -> None:
        self._browser_pool.close_conversation(conversation_key)

    def close(self):
        self._browser_pool.close()



def _browser_profile_path(agent_name: str) -> Path:
    configured = os.environ.get("CYBERNOVA_GPT_BROWSER_PROFILE")
    if configured:
        base = Path(configured).expanduser()
        return base if agent_name == "gpt" else base.parent / "deepseek-chromium-profile"
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "CyberNova" / "data" / f"{agent_name}-chromium-profile"
    return Path.home() / ".local" / "share" / "cybernova" / f"{agent_name}-chromium-profile"


# Separate runtime locks, BrowserSession instances and persistent profiles.
# Both models retain the same inspected tool catalog and safety policies.
runtime = GPTToolRuntime(browser_profile_dir=_browser_profile_path("gpt"))
deepseek_runtime = GPTToolRuntime(browser_profile_dir=_browser_profile_path("deepseek"))
