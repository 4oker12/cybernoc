"""Local tool runtime dedicated to Cybernova's Account GPT mode.

The GPT agent gets its own tool loop and browser session. This module does not
register tools with or modify the DeepSeek research agent.
"""
from __future__ import annotations

import ipaddress
import importlib.util
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from threading import RLock

try:
    from .browser_control import BROWSER_CONTROL_TOOLS, BrowserSession, browser_control_call
    from .developer_tools import SOURCE
    from .research_web import RESEARCH_WEB_TOOLS, research_web_call
    from .computer_control import COMPUTER_TOOLS, COMPUTER_TOOL_NAMES, computer_control_call
except ImportError:
    from browser_control import BROWSER_CONTROL_TOOLS, BrowserSession, browser_control_call
    from developer_tools import SOURCE
    from research_web import RESEARCH_WEB_TOOLS, research_web_call
    from computer_control import COMPUTER_TOOLS, COMPUTER_TOOL_NAMES, computer_control_call


MAX_TOOL_ROUNDS = 24
MAX_TOOL_CALLS = 64
MAX_TOOL_OUTPUT_CHARS = 50000
MAX_TERMINAL_COMMAND_CHARS = 20000
MAX_TERMINAL_TIMEOUT_SECONDS = 300

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(r"(?i)(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![a-z0-9.-])")
_SECRET = re.compile(
    r"(?i)(Bearer\s+[A-Za-z0-9._~-]{8,}|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret|"
    r"authorization|cookie)\s*[:=]\s*[^\s,;]+)"
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")

_TOOL_NAMES = frozenset(
    item["name"] for item in BROWSER_CONTROL_TOOLS
    if item["name"] != "browser_submit"
) | frozenset(item["name"] for item in RESEARCH_WEB_TOOLS) | {
    "terminal_run", "terminal_status",
} | COMPUTER_TOOL_NAMES

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
        "description": "CMD и PowerShell для системной диагностики; команды и операции ограничиваются политикой безопасности.",
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
    if name.startswith("browser_"):
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


def tool_group_summary(tool_names) -> list[dict]:
    names = {name for name in tool_names if isinstance(name, str)}
    counts = {group["id"]: 0 for group in TOOL_GROUPS}
    for name in names:
        counts[tool_group_for_name(name)] += 1
    return [
        {**group, "count": counts[group["id"]], "available": counts[group["id"]] > 0}
        for group in TOOL_GROUPS
    ]


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
    """Tools visible only to Account GPT; no DeepSeek tool registry mutation."""
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
    rows.extend(
        _convert_mcp_tool(item)
        for item in BROWSER_CONTROL_TOOLS
        if item["name"] != "browser_submit"
    )
    rows.extend(_convert_mcp_tool(item) for item in RESEARCH_WEB_TOOLS)
    rows.extend(_convert_mcp_tool(item) for item in COMPUTER_TOOLS)
    return rows


def _decode_cmd_output(value: bytes) -> str:
    try:
        return value.decode("oem", errors="replace")
    except LookupError:
        return value.decode("utf-8", errors="replace")


def _redact_output(value: str) -> str:
    value = _SECRET.sub("[REDACTED]", value)
    value = _EMAIL.sub("[REDACTED EMAIL]", value)
    return value[:MAX_TOOL_OUTPUT_CHARS]


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
        "command": command[:500],
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


class GPTToolRuntime:
    """One isolated Chromium session and bounded terminal for Account GPT."""
    def __init__(self):
        self._lock = RLock()
        self._browser: BrowserSession | None = None
        self.tools = build_tool_catalog()
        self.tool_map = {item["name"]: item for item in self.tools}

    def tools_for_groups(self, groups=None) -> list[dict]:
        """Return the full catalog or only explicitly selected tool bundles."""
        return filter_tool_rows(self.tools, groups)

    def mcp_tools(self, groups=None) -> list[dict]:
        """Expose the same selected local tool catalog to MCP/Ollama-style agents."""
        return [
            {
                "name": item["name"],
                "description": item["description"],
                "inputSchema": item["parameters"],
            }
            for item in self.tools_for_groups(groups)
        ]

    def call(self, name: str, args: dict, *, authorized_targets=None,
             user_messages=None, enabled_groups=None) -> tuple[dict, bool]:
        selected = set(normalize_tool_groups(enabled_groups))
        if selected and tool_group_for_name(name) not in selected:
            return {"ok": False, "error": "tool_group_not_enabled"}, True
        if name not in _TOOL_NAMES or name not in self.tool_map:
            return {"ok": False, "error": "gpt_tool_not_registered"}, True
        if not isinstance(args, dict):
            return {"ok": False, "error": "tool_arguments_must_be_object"}, True
        with self._lock:
            try:
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
                if name.startswith("browser_"):
                    if name == "browser_submit":
                        raise ValueError("browser_submit_requires_separate_approval")
                    if self._browser is None:
                        self._browser = BrowserSession()
                    self._browser.set_authorized_hosts(authorized_targets or set())
                    return browser_control_call(name, args, self._browser)
                raise ValueError("gpt_tool_not_implemented")
            except (OSError, ValueError, TypeError) as exc:
                return {"ok": False, "error": type(exc).__name__ + ":" + str(exc)[:180]}, True

    def close(self):
        with self._lock:
            if self._browser is not None:
                self._browser.close()
                self._browser = None


runtime = GPTToolRuntime()
