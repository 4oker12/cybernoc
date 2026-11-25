"""Small, safe day-to-day terminal diagnostics shared by both models.

This is deliberately NOT an arbitrary shell. Only fixed, read-only commands,
without user-controlled argv, are supported. Source is operator configured.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

try:
    from .developer_tools import SOURCE
except ImportError:
    from developer_tools import SOURCE


TERMINAL_COMMANDS = ("pwd", "list", "python --version", "git status", "git log")
SECRET_NAME = re.compile(r"(?i)(?:^\.env|secret|token|password|credential|\.key$|\.pem$|id_rsa|id_ed25519)")
TERMINAL_TOOLS = [{
    "name": "safe_terminal",
    "description": (
        "Read-only terminal diagnostics in the configured Cybernova source checkout. "
        "Only these exact commands are accepted: pwd, list, python --version, "
        "git status, git log. No shell, scripts, flags, file contents, or write operations."
    ),
    "inputSchema": {
        "type": "object", "properties": {
            "command": {"type": "string", "enum": list(TERMINAL_COMMANDS)},
        }, "required": ["command"], "additionalProperties": False,
    },
}]


def safe_terminal(command: str, *, source: Path | None = None, runner=None) -> dict:
    if not isinstance(command, str) or command not in TERMINAL_COMMANDS:
        raise ValueError("terminal_command_not_allowlisted")
    folder = (source or SOURCE).resolve()
    if not folder.is_dir():
        return {"ok": False, "command": command, "error": "workspace_unavailable"}
    if command == "pwd":
        return {"ok": True, "command": command, "output": str(folder)[:500]}
    if command == "list":
        names = []
        for path in sorted(folder.iterdir(), key=lambda p: p.name.lower()):
            if path.name.startswith(".") or SECRET_NAME.search(path.name) or path.is_symlink():
                continue
            names.append(("dir " if path.is_dir() else "file ") + path.name[:120])
            if len(names) >= 40:
                break
        return {"ok": True, "command": command, "output": "\n".join(names)[:4500]}
    argv = {
        "python --version": [sys.executable, "--version"],
        "git status": ["git", "--no-optional-locks", "status", "--short", "--untracked-files=no"],
        "git log": ["git", "--no-optional-locks", "log", "-5", "--format=%h %s"],
    }[command]
    if argv[0] == "git" and not shutil.which("git"):
        return {"ok": False, "command": command, "error": "git_not_installed"}
    execute = runner or subprocess.run
    try:
        result = execute(
            argv, cwd=str(folder), shell=False, capture_output=True, text=True,
            timeout=6, stdin=subprocess.DEVNULL,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(Path.home()),
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "command": command, "error": "terminal_unavailable"}
    text = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    # Never echo dangerous raw text or secret-bearing lines from a tool.
    lines = [
        line for line in text.splitlines()
        if not SECRET_NAME.search(line)
    ]
    return {
        "ok": result.returncode == 0, "command": command,
        "exit_code": result.returncode, "output": "\n".join(lines)[:4500],
    }
