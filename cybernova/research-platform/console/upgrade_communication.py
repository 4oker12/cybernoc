"""Safely upgrade ONLY Cybernova Chat / Communication MCP / access proxy.

Run after verifying the signed-off GitHub commit was fetched and checked out.
The existing Ollama, original Tool MCP, Open WebUI and Cloudflare tunnel
are left untouched. Tests run before restart; on failure try to roll back.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = Path("/workspace/cybernova-comm-private")
VENV = Path("/workspace/cybernova-comm-venv/bin/python")
DB = PRIVATE / "communications.sqlite3"
SESSIONS = (
    ("cybernova-comm-mcp", "console.communication_mcp", "mcp.log"),
    ("cybernova-chat-console", "console.server", "console.log"),
    ("cybernova-chat-access", "console.tunnel_access", "web_access.log"),
)


def run(argv, *, cwd=None, timeout=120):
    process = subprocess.run(
        [str(x) for x in argv], cwd=str(cwd) if cwd else None,
        text=True, capture_output=True, timeout=timeout,
    )
    if process.returncode:
        print("STEP_FAILED", argv[:3], process.returncode,
              (process.stderr or "")[-1800:], flush=True)
        raise RuntimeError("subprocess_failed")
    return (process.stdout or "").strip()


def running(name):
    return subprocess.run(
        ["tmux", "has-session", "-t", name],
        capture_output=True,
    ).returncode == 0


def stop_services():
    for name, _, _ in reversed(SESSIONS):
        if running(name):
            run(["tmux", "kill-session", "-t", name], timeout=15)


def start_services():
    for name, module, filename in SESSIONS:
        command = (
            "cd " + str(ROOT) + " && " +
            "CYBERNOVA_COMM_DB=" + str(DB) + " " +
            "CYBERNOVA_COMM_WORKER=1 PYTHONUNBUFFERED=1 " + str(VENV) +
            " -m " + module + " >>" + str(PRIVATE / filename) + " 2>&1"
        )
        run(["tmux", "new-session", "-d", "-s", name, command], timeout=15)


def local_get(port, path, *, basic=None):
    headers = {}
    if basic:
        headers["Authorization"] = (
            "Basic " + base64.b64encode(
                (basic[0] + ":" + basic[1]).encode()
            ).decode()
        )
    url = "http://127.0.0.1:" + str(port) + path
    req = Request(url, headers=headers)
    try:
        with build_opener(ProxyHandler({})).open(req, timeout=6) as response:
            return response.status, response.read(500000)
    except HTTPError as exc:
        return exc.code, exc.read(50000)


def mcp_call(method, arguments=None):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": arguments or {},
    }
    data = json.dumps(payload).encode()
    req = Request(
        "http://127.0.0.1:18796/mcp", method="POST",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    with build_opener(ProxyHandler({})).open(req, timeout=8) as response:
        text = response.read(500000).decode()
    if text.startswith("event:") or text.startswith("data:"):
        text = next((line[5:] for line in text.splitlines()
                     if line.startswith("data:")), "")
    value = json.loads(text)
    if value.get("error"):
        raise RuntimeError("mcp_jsonrpc_error")
    return value.get("result", {})


def check_health():
    credentials_file = PRIVATE / "web_access.txt"
    user, password = credentials_file.read_text().splitlines()
    credentials = (user, password)
    status_code, body = local_get(18794, "/api/status")
    if status_code != 200:
        raise RuntimeError("console_unhealthy")
    status = json.loads(body)
    if not status.get("ollama_ready") or not status.get("mcp_ready"):
        raise RuntimeError("backend_not_ready")
    tools = status.get("tools") or []
    if "comm_record_evidence" not in tools:
        raise RuntimeError("qwen_evidence_tool_missing")
    info = mcp_call("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "cybernova-upgrade", "version": "1"},
    })
    mcp_tools = mcp_call("tools/list", {}).get("tools") or []
    names = [x.get("name") for x in mcp_tools]
    if "cybernova_get_evidence" not in names or \
       "cybernova_tool_receipts" not in names:
        raise RuntimeError("review_evidence_mcp_missing")
    one, _ = local_get(18795, "/")
    two, _ = local_get(18795, "/api/status", basic=credentials)
    if (one, two) != (401, 200):
        raise RuntimeError("web_auth_not_enforced")
    packet, _ = local_get(18795, "/api/comm/review-packet")
    if packet != 401:
        raise RuntimeError("review_packet_exposed_without_auth")
    print(json.dumps({
        "status": "UPGRADE_VERIFIED", "console_tools": len(tools),
        "communication_mcp_tools": len(names),
        "basic_auth": "401_without_credentials_200_with_credentials",
        "review_packet_requires_auth": True,
        "mcp_exposed_publicly": False,
        "cloudflare_tunnel_restarted": False,
    }, ensure_ascii=False), flush=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: upgrade_communication.py <previous_git_sha>")
    previous_commit = sys.argv[1]
    current = run(["git", "rev-parse", "HEAD"], cwd=ROOT)
    if not previous_commit or previous_commit == current:
        raise RuntimeError("invalid_previous_commit")
    print("OLD_COMMIT", previous_commit, "NEW_COMMIT", current, flush=True)
    if not (PRIVATE / "web_access.txt").is_file():
        raise RuntimeError("password_file_missing")
    if not VENV.is_file():
        raise RuntimeError("venv_missing")
    run([VENV, "-m", "compileall", "-q", ROOT / "console"], timeout=20)
    run([VENV, "-m", "unittest", "discover", "-s", ROOT / "tests",
         "-p", "test_*.py", "-q"], cwd=ROOT, timeout=100)
    if shutil.which("node"):
        run(["node", "--check", ROOT / "console" / "static" / "app.js"], timeout=20)
    else:
        print("NODE_NOT_INSTALLED_JS_SYNTAX_CHECKED_BY_GITHUB_CI", flush=True)
    print("PREFLIGHT_PASSED", flush=True)

    changed = False
    try:
        stop_services()
        changed = True
        start_services()
        last_error = None
        for attempt in range(24):
            time.sleep(1)
            try:
                check_health()
                print("UPGRADE_EXIT=0", flush=True)
                return
            except (OSError, ValueError, RuntimeError, TimeoutError,
                    URLError, json.JSONDecodeError) as exc:
                last_error = type(exc).__name__ + ":" + str(exc)
        raise RuntimeError("services_failed_health_checks:" + str(last_error))
    except Exception as exc:
        print("UPGRADE_ERROR", type(exc).__name__, str(exc)[:350], flush=True)
        if changed:
            stop_services()
            try:
                run(["git", "checkout", "--detach", previous_commit],
                    cwd=ROOT, timeout=20)
                start_services()
                print("ROLLBACK_STARTED", flush=True)
            except Exception as rollback_exc:
                print("ROLLBACK_FAILED", type(rollback_exc).__name__, flush=True)
        raise


if __name__ == "__main__":
    main()
