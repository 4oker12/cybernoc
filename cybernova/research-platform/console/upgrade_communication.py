"""Safely upgrade ONLY Cybernova Chat / Communication MCP / access proxy.

Run after verifying the signed-off GitHub commit was fetched and checked out.
The existing Ollama, original Tool MCP, Open WebUI and Cloudflare tunnel
are left untouched. Tests run before restart; on failure try to roll back.
"""
from __future__ import annotations
from contextlib import closing

import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

try:
    from .upload_limits import MAX_UPLOAD_FILE_BYTES
except ImportError:
    from upload_limits import MAX_UPLOAD_FILE_BYTES
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



def backup_db():
    """Consistent SQLite online backup before any service restart."""
    if not DB.is_file() or DB.is_symlink():
        raise RuntimeError("communication_database_missing_or_symlink")
    backup_dir = PRIVATE / "upgrade-backups"
    if backup_dir.is_symlink():
        raise RuntimeError("backup_directory_symlink")
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup_dir.chmod(0o700)
    target = backup_dir / ("communications-pre-upgrade-" +
                            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
                            ".sqlite3")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        with closing(sqlite3.connect("file:" + str(DB) + "?mode=ro", uri=True)) as source, source:
            with closing(sqlite3.connect(str(target))) as dest, dest:
                source.backup(dest)
                integrity = dest.execute("PRAGMA integrity_check").fetchone()[0]
                if integrity != "ok":
                    raise RuntimeError("database_backup_integrity_failed")
    except Exception:
        target.unlink(missing_ok=True)
        raise
    print("COMM_DB_BACKUP_VERIFIED", target.name, flush=True)


def stop_services():
    for name, _, _ in reversed(SESSIONS):
        if running(name):
            run(["tmux", "kill-session", "-t", name], timeout=15)


def start_services():
    for name, module, filename in SESSIONS:
        command = (
            "cd " + str(ROOT) + " && " +
            "CYBERNOVA_COMM_DB=" + str(DB) + " " +
            "CYBERNOVA_COMM_WORKER=1 " +
            "CYBERNOVA_SIWC_DIR=" + str(PRIVATE / "chatgpt-siwc") + " " +
            "CYBERNOVA_SIWC_CALLBACK_PORT=18795 " +
            "PYTHONUNBUFFERED=1 " + str(VENV) +
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
    if status.get("upload_limit_bytes") != MAX_UPLOAD_FILE_BYTES:
        raise RuntimeError("upload_size_not_deployed")
    tools = status.get("tools") or []
    if "browser_network" not in tools or "browser_network" not in status.get("auto_executable", []):
        raise RuntimeError("qwen_devtools_network_not_executable")
    development_tools = {"dev_workspace", "dev_list", "dev_read", "dev_search",
                         "dev_edit", "dev_delete", "dev_move", "dev_diff",
                         "dev_test", "dev_commit", "dev_command", "dev_push",
                         "dev_open_pr"}
    if not development_tools.issubset(set(tools)):
        raise RuntimeError("qwen_developer_tools_missing")
    executable = set(status.get("auto_executable", []))
    if not {"dev_workspace", "dev_read", "dev_edit", "dev_test", "dev_commit"}.issubset(executable):
        raise RuntimeError("qwen_developer_core_not_executable")
    if {"dev_command", "dev_push", "dev_open_pr"} & executable:
        raise RuntimeError("qwen_developer_sensitive_action_no_approval")
    if status.get("developer", {}).get("mode") != "task_isolated_git_worktree":
        raise RuntimeError("qwen_developer_workspace_not_isolated")
    if "browser_open" not in tools:
        raise RuntimeError("qwen_browser_tool_missing")
    if "browser_open" not in status.get("auto_executable", []):
        raise RuntimeError("qwen_browser_tool_not_executable")
    if status.get("research_scope", {}).get("type") != "owner_selected_per_task":
        raise RuntimeError("research_scope_control_missing")
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
    unauth_siwc, _ = local_get(18795, "/api/siwc/status")
    auth_siwc, auth_body = local_get(18795, "/api/siwc/status",
                                    basic=credentials)
    if (unauth_siwc, auth_siwc) != (401, 200):
        raise RuntimeError("chatgpt_oauth_not_protected_or_unavailable")
    oauth_status = json.loads(auth_body)
    if oauth_status.get("mode") != "official_chatgpt_oauth" or \
       oauth_status.get("callback_port") != 18795 or \
       type(oauth_status.get("connected")) is not bool:
        raise RuntimeError("chatgpt_oauth_status_invalid")
    js_code, js_body = local_get(18795, "/static/app.js", basic=credentials)
    expected_js = "const MAX_UPLOAD_BYTES = " + str(MAX_UPLOAD_FILE_BYTES // (1024*1024)) + " * 1024 * 1024"
    if js_code != 200 or expected_js.encode() not in js_body:
        raise RuntimeError("browser_upload_limit_not_deployed")
    html_code, html_body = local_get(18795, "/", basic=credentials)
    required_tags = [
        b'<script defer src="/static/markdown.js"></script>',
        b'<script defer src="/static/app.js"></script>',
    ]
    if html_code != 200 or html_body.count(b"</script>") != 2 or any(
            html_body.count(tag) != 1 for tag in required_tags):
        raise RuntimeError("web_ui_scripts_malformed_or_missing")
    if b'async function sendGPT()' not in js_body or b'function setMode(mode)' not in js_body:
        raise RuntimeError("dual_chat_frontend_not_deployed")
    css_code, markdown_body = local_get(18795, "/static/markdown.js", basic=credentials)
    if css_code != 200 or b'window.CybernovaMarkdown' not in markdown_body:
        raise RuntimeError("markdown_renderer_unavailable")
    unauth_gpt, _ = local_get(18795, "/api/siwc/chats")
    auth_gpt, gpt_body = local_get(18795, "/api/siwc/chats", basic=credentials)
    if (unauth_gpt, auth_gpt) != (401, 200) or "threads" not in json.loads(gpt_body):
        raise RuntimeError("gpt_persistent_chats_route_unavailable")
    print(json.dumps({
        "status": "UPGRADE_VERIFIED", "console_tools": len(tools),
        "communication_mcp_tools": len(names),
        "basic_auth": "401_without_credentials_200_with_credentials",
        "review_packet_requires_auth": True,
        "mcp_exposed_publicly": False,
        "cloudflare_tunnel_restarted": False,
        "upload_limit_mib": MAX_UPLOAD_FILE_BYTES // (1024 * 1024),
        "chatgpt_oauth_route": "authenticated_ready",
        "gpt_regular_chat": "available",
        "markdown_rendering": "ready",
        "browser": "scoped_https_html_ready",
        "devtools_network": "chromium_ready",
        "owner_scope": "user_selected_per_task",
        "qwen_developer": "13_registered_tools_separate_git_worktrees",
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
    run([VENV, "-m", "pip", "install", "--disable-pip-version-check", "-q",
         "-r", ROOT / "console" / "requirements.txt"], timeout=210)
    # Install browser binaries while old Web UI is still online.
    run([VENV, "-m", "playwright", "install", "chromium"], timeout=240)
    run([VENV, "-m", "compileall", "-q", ROOT / "console"], timeout=20)
    run([VENV, "-m", "unittest", "discover", "-s", ROOT / "tests",
         "-p", "test_*.py", "-q"], cwd=ROOT, timeout=100)
    if shutil.which("node"):
        run(["node", "--check", ROOT / "console" / "static" / "app.js"], timeout=20)
    else:
        print("NODE_NOT_INSTALLED_JS_SYNTAX_CHECKED_BY_GITHUB_CI", flush=True)
    # A downloaded browser is not necessarily executable on a fresh Vast
    # image. Repair missing OS *shared libraries* only; never paper over
    # arbitrary browser failures with package installation. Keep existing
    # Cybernova services running while resolving host dependencies.
    launch_check = [VENV, "-c",
        "from playwright.sync_api import sync_playwright; "
        "p=sync_playwright().start(); "
        "b=p.chromium.launch(headless=True,args=['--no-sandbox']); "
        "b.close();p.stop()"]
    initial = subprocess.run([str(x) for x in launch_check],
                             capture_output=True, text=True, timeout=40)
    if initial.returncode:
        output = (initial.stderr or "")[-6000:]
        missing_lib = ("error while loading shared libraries:" in output or
                       "Host system is missing dependencies" in output)
        if not missing_lib or os.geteuid() != 0:
            print("CHROMIUM_SMOKE_FAILED", output[-1800:], flush=True)
            raise RuntimeError("chromium_launch_failed")
        print("CHROMIUM_INSTALLING_MISSING_OS_LIBRARIES", flush=True)
        run([VENV, "-m", "playwright", "install-deps", "chromium"],
            timeout=480)
        run(launch_check, timeout=40)
    print("CHROMIUM_LAUNCH_VERIFIED", flush=True)
    backup_db()
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
