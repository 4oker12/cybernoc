"""Additive MCP tools. Existing CyberSec Vast tools are left unchanged."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys

OPS = Path("/workspace/cybernova-mcp-addon/deployment_ops.py")
RUNUSER = "/usr/sbin/runuser"
PYTHON = "/venv/main/bin/python"

def execute(name: str, arg: str | None = None) -> dict:
    allowed = {"status","preview","stage","apply","rollback","events"}
    if name not in allowed:
        return {"ok":False,"error":"Unknown operation"}
    if arg is not None and (not isinstance(arg,str) or len(arg)>80):
        return {"ok":False,"error":"Invalid argument"}
    args = [PYTHON,str(OPS),name]
    if arg is not None: args.append(arg)
    if os.geteuid() == 0:
        args = [RUNUSER,"-u","cybernova","--",*args]
    try:
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,text=True,timeout=180,
                              shell=False,check=False)
        if len(result.stdout)>40000:
            return {"ok":False,"error":"Oversized output"}
        try:
            parsed=json.loads(result.stdout)
        except (ValueError,TypeError):
            return {"ok":False,"error":"Invalid deployment output",
                    "exit_code":result.returncode}
        if not isinstance(parsed,dict):
            return {"ok":False,"error":"Unexpected deployment response"}
        if result.returncode!=0:
            parsed["ok"]=False
        return parsed
    except (FileNotFoundError,subprocess.TimeoutExpired) as exc:
        return {"ok":False,"error":type(exc).__name__}

def register(mcp):
    @mcp.tool()
    def deployment_status() -> dict:
        """Read Cybernova active release, updater status and recent deployment reports."""
        return execute("status")

    @mcp.tool()
    def deployment_preview() -> dict:
        """Read the approved GitHub branch HEAD and compare it to the updater cursor."""
        return execute("preview")

    @mcp.tool()
    def deployment_stage(commit_sha: str) -> dict:
        """Stage and test the specified 40-character branch HEAD. Refuses while watcher runs."""
        return execute("stage",commit_sha)

    @mcp.tool()
    def deployment_apply(commit_sha: str) -> dict:
        """Promote a tested stage using the guarded updater. Refuses while watcher runs."""
        return execute("apply",commit_sha)

    @mcp.tool()
    def deployment_rollback(target: str = "legacy") -> dict:
        """Restore verified managed release or legacy agent, stopping updater for review."""
        return execute("rollback",target)

    @mcp.tool()
    def deployment_recent_events(limit: int = 10) -> dict:
        """Read bounded local updater reports. This tool is not an MCP Events subscription."""
        return execute("events",str(limit))
