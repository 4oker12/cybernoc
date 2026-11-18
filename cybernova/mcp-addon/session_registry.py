"""Typed MCP entry points for Cybernova bounded local research sessions.

These tools never accept shell commands, file paths, external URLs or target hosts.
The original terminal approval mechanism remains unchanged.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

OPS = Path("/workspace/cybernova-mcp-addon/session_ops.py")
PYTHON = "/venv/main/bin/python"
RUNUSER = "/usr/sbin/runuser"
SID = re.compile(r"^[0-9a-f]{32}$")
PRESET = "local_qwen_baseline"


def execute(operation: str, session_id: str = "") -> dict:
    if operation not in ("start", "status", "report"):
        return {"ok": False, "error": "Unknown operation"}
    if operation == "start":
        if session_id:
            return {"ok": False, "error": "Start accepts no input"}
        argv = [PYTHON, str(OPS), "start"]
    else:
        if type(session_id) is not str or not SID.fullmatch(session_id):
            return {"ok": False, "error": "Invalid session ID"}
        argv = [PYTHON, str(OPS), operation, session_id]
    if os.geteuid() == 0:
        argv = [RUNUSER, "-u", "cybernova", "--", *argv]
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, check=False, timeout=20, shell=False,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                   "HOME": "/nonexistent"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": type(exc).__name__}
    if len(proc.stdout) > 32_000:
        return {"ok": False, "error": "Oversized response"}
    try:
        result = json.loads(proc.stdout)
    except (TypeError, ValueError):
        return {"ok": False, "error": "Invalid response", "exit_code": proc.returncode}
    if type(result) is not dict:
        return {"ok": False, "error": "Unexpected response"}
    if proc.returncode != 0:
        result["ok"] = False
    return result


def register(server):
    @server.tool()
    def cybernova_session_start() -> dict:
        """Start one predefined localhost/offline Qwen validation session (no targets)."""
        return execute("start")

    @server.tool()
    def cybernova_session_status(session_id: str) -> dict:
        """Read the running/completed state of one bounded Cybernova session."""
        return execute("status", session_id)

    @server.tool()
    def cybernova_session_report(session_id: str) -> dict:
        """Read final safe metadata, tool IDs and evidence verification count."""
        return execute("report", session_id)
