"""Local tool runtime dedicated to Cybernova's Account GPT mode.

The GPT agent gets its own tool loop and browser session. This module does not
register tools with or modify the DeepSeek research agent.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
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


MAX_TOOL_ROUNDS = 12
MAX_TOOL_CALLS = 24
MAX_TOOL_OUTPUT_CHARS = 12000

# Only one simple command is accepted per call. No shell operators, variables,
# command substitution, script blocks, redirection or chained commands.
_FORBIDDEN_SCRIPT = re.compile(r"[;\|&<>$(){}" + chr(96) + r"%!^\"']")
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
                    "One read-only Windows CMD command. Supported diagnostics: "
                    "hostname, whoami, ver, ipconfig /all, route print -4, "
                    "netstat -ano, netstat -e, arp -a, getmac /v, "
                    "netsh interface show interface, netsh interface ipv4 show config, "
                    "netsh advfirewall show allprofiles, ping -n <count> <host>, "
                    "tracert -d -h <hops> -w <ms> <host>, pathping, nslookup <host>, "
                    "curl.exe -I --connect-timeout <seconds> --max-time <seconds> https://<host>/, "
                    "git status, git log, git diff --stat, python --version. "
                    "Exactly one command; no shell operators, scripts or writes. "
                    "Network targets must have been named by the user in this task."
                ),
            },
        },
        "required": ["command"],
        "additionalProperties": False,
    }
    status_schema = {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    }
    rows = [
        _function_tool(
            "terminal_run",
            "Run one bounded, read-only diagnostic command in the local Windows Command Prompt (cmd.exe) process hosting Cybernova. This is the user's laptop only when the Cybernova backend is running locally. Never use it for writes, installs, privilege escalation or arbitrary scripts.",
            terminal_schema,
        ),
        _function_tool(
            "terminal_status",
            "Check which operating system and local Windows CMD executable host this Account GPT tool runtime. Does not expose environment variables or secrets.",
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


def _target_from_command(command: str, name: str) -> str | None:
    patterns = {
        "nslookup": r"(?i)^\s*nslookup(?:\.exe)?\s+([^\s]+)",
        "curl": r"(?i)https://([a-z0-9.-]+)(?:/|\s|$)",
    }
    pattern = patterns.get(name)
    if pattern:
        match = re.search(pattern, command)
        return match.group(1).lower().rstrip(".") if match else None
    tokens = command.split()
    candidates = [
        token for token in tokens[1:]
        if token and not token.startswith("-") and not token.startswith("/")
    ]
    return candidates[-1] if candidates else None


def _validate_terminal_command(command: object, authorized_targets: set[str]) -> str:
    if not isinstance(command, str) or not 1 <= len(command.strip()) <= 900:
        raise ValueError("terminal_command_invalid")
    command = command.strip()
    if "\n" in command or "\r" in command or _FORBIDDEN_SCRIPT.search(command):
        raise ValueError("terminal_single_readonly_command_required")

    first_token = command.split(None, 1)[0].lower()
    first = first_token.rsplit("\\", 1)[-1]
    base = first[:-4] if first.endswith(".exe") else first

    if base == "git":
        if not re.fullmatch(
            r"(?i)git\s+(?:status(?:\s+--short)?|log(?:\s+--oneline)?|diff\s+--stat|diff\s+--name-only)",
            command,
        ):
            raise ValueError("terminal_git_subcommand_not_allowlisted")
        return command
    if base in {"python", "py"}:
        if not re.fullmatch(r"(?i)(?:python(?:\.exe)?|py(?:\.exe)?)\s+--version", command):
            raise ValueError("terminal_python_command_not_allowlisted")
        return command

    if base in {"hostname", "whoami", "ver"}:
        if len(command.split()) != 1:
            raise ValueError("terminal_local_command_arguments_forbidden")
        return command
    if base == "ipconfig":
        if not re.fullmatch(r"(?i)ipconfig(?:\.exe)?\s+/(?:all|displaydns)", command):
            raise ValueError("terminal_ipconfig_argument_not_allowlisted")
        return command
    if base == "route":
        if not re.fullmatch(r"(?i)route(?:\.exe)?\s+print(?:\s+-(?:4|6))?", command):
            raise ValueError("terminal_route_argument_not_allowlisted")
        return command
    if base == "netstat":
        if not re.fullmatch(r"(?i)netstat(?:\.exe)?\s+(?:-an|-ano|-e|-s)", command):
            raise ValueError("terminal_netstat_argument_not_allowlisted")
        return command
    if base == "arp":
        if not re.fullmatch(r"(?i)arp(?:\.exe)?\s+-a", command):
            raise ValueError("terminal_arp_argument_not_allowlisted")
        return command
    if base == "getmac":
        if not re.fullmatch(r"(?i)getmac(?:\.exe)?\s+/v", command):
            raise ValueError("terminal_getmac_argument_not_allowlisted")
        return command
    if base == "netsh":
        if not re.fullmatch(
            r"(?i)netsh(?:\.exe)?\s+(?:interface\s+show\s+interface|"
            r"interface\s+ipv4\s+show\s+config|advfirewall\s+show\s+allprofiles|"
            r"wlan\s+show\s+interfaces)",
            command,
        ):
            raise ValueError("terminal_netsh_readonly_command_not_allowlisted")
        return command

    if base not in {"ping", "tracert", "pathping", "nslookup", "curl"}:
        raise ValueError("terminal_command_not_allowlisted")

    if base == "nslookup":
        if not re.fullmatch(r"(?i)nslookup(?:\.exe)?\s+[A-Za-z0-9._:-]+", command):
            raise ValueError("terminal_nslookup_custom_server_or_options_forbidden")
    elif base == "ping":
        match = re.fullmatch(
            r"(?i)ping(?:\.exe)?\s+-n\s+(\d{1,2})(?:\s+-w\s+(\d{1,5}))?\s+([A-Za-z0-9._:-]+)",
            command,
        )
        if not match:
            raise ValueError("terminal_ping_options_not_allowlisted")
        if not 1 <= int(match.group(1)) <= 20:
            raise ValueError("terminal_ping_count_out_of_range")
        if match.group(2) and not 100 <= int(match.group(2)) <= 5000:
            raise ValueError("terminal_ping_timeout_out_of_range")
    elif base == "tracert":
        match = re.fullmatch(
            r"(?i)tracert(?:\.exe)?(?:\s+-d)?(?:\s+-h\s+(\d{1,2}))?"
            r"(?:\s+-w\s+(\d{1,5}))?\s+([A-Za-z0-9._:-]+)",
            command,
        )
        if not match:
            raise ValueError("terminal_tracert_options_not_allowlisted")
        if match.group(1) and not 1 <= int(match.group(1)) <= 30:
            raise ValueError("terminal_traceroute_hops_out_of_range")
        if match.group(2) and not 100 <= int(match.group(2)) <= 2000:
            raise ValueError("terminal_traceroute_timeout_out_of_range")
    elif base == "pathping":
        match = re.fullmatch(
            r"(?i)pathping(?:\.exe)?(?:\s+-n)?\s+-q\s+(\d{1,2})"
            r"(?:\s+-w\s+(\d{1,5}))?\s+([A-Za-z0-9._:-]+)",
            command,
        )
        if not match:
            raise ValueError("terminal_pathping_options_not_allowlisted")
        if not 1 <= int(match.group(1)) <= 10:
            raise ValueError("terminal_pathping_queries_out_of_range")
        if match.group(2) and not 100 <= int(match.group(2)) <= 2000:
            raise ValueError("terminal_pathping_timeout_out_of_range")
    elif base == "curl":
        match = re.fullmatch(
            r"(?i)curl(?:\.exe)?\s+-I\s+--connect-timeout\s+(\d{1,2})"
            r"\s+--max-time\s+(\d{1,2})\s+https://([a-z0-9.-]+)/?",
            command,
        )
        if not match:
            raise ValueError("terminal_curl_head_only_options_not_allowlisted")
        if not 1 <= int(match.group(1)) <= 10 or not 1 <= int(match.group(2)) <= 30:
            raise ValueError("terminal_curl_timeout_out_of_range")

    target = _target_from_command(command, base)
    if not target:
        raise ValueError("terminal_network_target_missing")
    normalized = target.lower().rstrip(".")
    try:
        normalized = str(ipaddress.ip_address(normalized))
    except ValueError:
        pass
    if normalized not in authorized_targets:
        raise ValueError("terminal_target_not_explicitly_named_by_user")
    return command


def _run_terminal(command: str, authorized_targets: set[str]) -> dict:
    if platform.system() != "Windows":
        return {
            "ok": False, "error": "local_windows_terminal_unavailable",
            "execution_host": platform.system().lower(),
        }
    command = _validate_terminal_command(command, authorized_targets)
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    cmd = shutil.which("cmd.exe") or str(Path(system_root) / "System32" / "cmd.exe")
    if not Path(cmd).is_file():
        return {"ok": False, "error": "windows_cmd_not_found"}
    timeout = 45 if command.lower().startswith(("pathping", "pathping.exe")) else 20
    env_names = (
        "PATH", "SystemRoot", "WINDIR", "USERPROFILE", "LOCALAPPDATA",
        "APPDATA", "TEMP", "TMP", "ProgramFiles", "ProgramFiles(x86)",
        "HOMEDRIVE", "HOMEPATH", "ComSpec", "PATHEXT",
    )
    env = {key: os.environ[key] for key in env_names if key in os.environ}
    try:
        result = subprocess.run(
            [cmd, "/d", "/s", "/c", command],
            cwd=str(SOURCE), shell=False, capture_output=True, text=False,
            timeout=timeout, stdin=subprocess.DEVNULL, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "command": command, "error": "terminal_timeout",
                "timeout_seconds": timeout}
    except OSError as exc:
        return {"ok": False, "command": command, "error": type(exc).__name__}
    stdout = _decode_cmd_output(result.stdout or b"")
    stderr = _decode_cmd_output(result.stderr or b"")
    output = _redact_output((stdout + "\n" + stderr).strip())
    return {
        "ok": result.returncode == 0,
        "command": command,
        "exit_code": result.returncode,
        "output": output,
        "execution_host": "local_windows",
        "shell": "Windows CMD",
    }


class GPTToolRuntime:
    """One isolated Chromium session and bounded terminal for Account GPT."""
    def __init__(self):
        self._lock = RLock()
        self._browser: BrowserSession | None = None
        self.tools = build_tool_catalog()
        self.tool_map = {item["name"]: item for item in self.tools}

    def call(self, name: str, args: dict, *, authorized_targets=None, user_messages=None) -> tuple[dict, bool]:
        if name not in _TOOL_NAMES or name not in self.tool_map:
            return {"ok": False, "error": "gpt_tool_not_registered"}, True
        if not isinstance(args, dict):
            return {"ok": False, "error": "tool_arguments_must_be_object"}, True
        with self._lock:
            try:
                if name == "terminal_status":
                    if args:
                        raise ValueError("terminal_status_takes_no_arguments")
                    return {
                        "ok": True, "os": platform.system(),
                        "cmd_exe": bool(
                            shutil.which("cmd.exe") or Path(
                                os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows",
                                "System32", "cmd.exe",
                            ).is_file()
                        ),
                        "terminal": "Windows CMD" if platform.system() == "Windows" else None,
                        "execution_host": "local_windows" if platform.system() == "Windows" else "remote_or_non_windows",
                    }, False
                if name == "terminal_run":
                    if set(args) != {"command"}:
                        raise ValueError("terminal_arguments_invalid")
                    result = _run_terminal(args["command"], set(authorized_targets or ()))
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
