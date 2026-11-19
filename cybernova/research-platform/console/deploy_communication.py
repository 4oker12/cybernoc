"""Stage the separate Chat + Communication MCP without touching existing Vast agent.

Run only from an explicitly approved terminal command, after checking out this
feature commit into an isolated worktree. Never downloads scripts or accepts
network targets from Qwen. Install dependencies in a dedicated venv only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
VENV = Path("/workspace/cybernova-comm-venv")
PRIVATE = Path("/workspace/cybernova-comm-private")
DB = PRIVATE / "communications.sqlite3"
PORTS = (18794, 18796)
SERVICES = (
    ("cybernova-comm-mcp", "console.communication_mcp", PRIVATE / "mcp.log"),
    ("cybernova-chat-console", "console.server", PRIVATE / "console.log"),
)


def step(argv, *, cwd=None, timeout=180):
    print("STEP", " ".join(map(str, argv[:4])), flush=True)
    proc = subprocess.run(
        [str(x) for x in argv], cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode:
        print((proc.stdout or "")[-1200:], flush=True)
        print((proc.stderr or "")[-2400:], flush=True)
        raise RuntimeError("step_failed_" + str(proc.returncode))
    tail = (proc.stdout or "").strip()[-1000:]
    if tail:
        print(tail, flush=True)


def free_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))


def rpc(method, params=None):
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": method,
        "params": params or {},
    }
    url = "http://127.0.0.1:18796/mcp"
    req = Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    with build_opener(ProxyHandler({})).open(req, timeout=5) as response:
        body = response.read(200_000).decode("utf-8")
    if body.startswith("event:") or body.startswith("data:"):
        lines = [x[5:].strip() for x in body.splitlines() if x.startswith("data:")]
        if lines:
            body = lines[-1]
    result = json.loads(body)
    if "error" in result:
        raise RuntimeError("mcp_rpc_error_" + str(result["error"].get("code")))
    return result.get("result", {})


def main():
    print("SOURCE_ROOT", ROOT, flush=True)
    rev = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    print("SOURCE_COMMIT", rev, flush=True)
    if not (ROOT / "console" / "COMMUNICATION.md").is_file():
        raise RuntimeError("incorrect_worktree_or_old_version")
    for port in PORTS:
        free_port(port)
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    PRIVATE.chmod(0o700)
    if not (VENV / "bin" / "python").is_file():
        step([sys.executable, "-m", "venv", str(VENV)])
    py = VENV / "bin" / "python"
    step([py, "-m", "pip", "install", "--disable-pip-version-check",
          "-q", "-r", ROOT / "console" / "requirements.txt"], timeout=210)
    step([py, "-m", "compileall", "-q", ROOT / "console"], timeout=25)
    step([py, "-m", "unittest", "discover", "-s", ROOT / "tests",
          "-p", "test_*.py", "-q"], cwd=ROOT, timeout=110)
    step([py, "-c", "import fastapi,uvicorn,mcp; print('DEPENDENCIES_OK')"], timeout=10)
    env = os.environ.copy()
    env["CYBERNOVA_COMM_DB"] = str(DB)
    env["CYBERNOVA_COMM_WORKER"] = "1"
    started = []
    try:
        for name, module, logfile in SERVICES:
            command = "cd " + str(ROOT) + " && " + \
                      "CYBERNOVA_COMM_DB=" + str(DB) + " " + \
                      "CYBERNOVA_COMM_WORKER=1 " + \
                      "PYTHONUNBUFFERED=1 " + str(py) + " -m " + module + \
                      " >>" + str(logfile) + " 2>&1"
            step(["tmux", "new-session", "-d", "-s", name, command], timeout=10)
            started.append(name)
        opener = build_opener(ProxyHandler({}))
        checked = False
        for attempt in range(20):
            time.sleep(1)
            try:
                with opener.open("http://127.0.0.1:18794/api/status", timeout=3) as response:
                    status = json.load(response)
                if not status.get("ollama_ready"):
                    raise RuntimeError("ollama_unavailable")
                info = rpc("initialize", {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "cybernova-deploy-smoke", "version": "1"},
                })
                tools = rpc("tools/list", {})
                names = [x["name"] for x in tools.get("tools", [])]
                if "cybernova_pending_reviews" not in names or \
                   "cybernova_send_feedback" not in names:
                    raise RuntimeError("missing_mcp_communication_tools")
                # Non-mutating real MCP tool invocation.
                tasklist = rpc("tools/call", {
                    "name": "cybernova_list_tasks",
                    "arguments": {"limit": 1},
                })
                if not tasklist.get("content"):
                    raise RuntimeError("mcp_tool_call_missing_result")
                print(json.dumps({
                    "deployment": "SMOKE_PASSED", "commit": rev,
                    "chat_http_port": 18794,
                    "communication_mcp_port": 18796,
                    "base_mcp_ready": status.get("mcp_ready"),
                    "console_tools": len(status.get("tools", [])),
                    "communication_mcp_tools": len(names),
                    "communication_test_call": "cybernova_list_tasks",
                    "communication_db": str(DB),
                }, ensure_ascii=False), flush=True)
                checked = True
                break
            except Exception as exc:
                if attempt == 19:
                    raise RuntimeError("health_check_failed_" + type(exc).__name__) from exc
        if not checked:
            raise RuntimeError("health_checks_did_not_complete")
    except Exception:
        for name in started:
            subprocess.run(["tmux", "kill-session", "-t", name],
                           capture_output=True, timeout=5)
        for _, _, log in SERVICES:
            if log.is_file():
                print("SERVICE_LOG", log.name, log.read_text(errors="replace")[-1800:])
        raise


if __name__ == "__main__":
    main()
