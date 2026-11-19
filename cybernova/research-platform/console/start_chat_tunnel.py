"""Start a password-protected Cloudflare Quick Tunnel for Cybernova Chat.

Launches separate local services in tmux; existing Ollama, Console and Tool
MCP are not changed. The public URL is not a secret but credentials ARE.
Password is written once to a local root-only file, never printed to logs.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = Path("/workspace/cybernova-comm-private")
CREDENTIALS = PRIVATE / "web_access.txt"
URL_FILE = PRIVATE / "chat_tunnel_url.txt"
LOG_PROXY = PRIVATE / "web_access.log"
LOG_TUNNEL = PRIVATE / "chat_tunnel.log"
BRIDGE_PORT = 18795
TUNNEL_SESSION = "cybernova-chat-tunnel"
ACCESS_SESSION = "cybernova-chat-access"
URL_PATTERN = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com", re.I)
PYTHON = Path("/workspace/cybernova-comm-venv/bin/python")


def step(args: list[str], timeout: int = 20):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError("subprocess_failed_" + Path(args[0]).name +
                           "_exit_" + str(proc.returncode))
    return proc.stdout.strip()


def session_exists(name: str) -> bool:
    return subprocess.run(["tmux", "has-session", "-t", name],
                          capture_output=True).returncode == 0


def port_reachable(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def request_url(url: str, auth: tuple[str, str] | None = None):
    headers = {}
    if auth:
        raw = (auth[0] + ":" + auth[1]).encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    req = Request(url, headers=headers)
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(req, timeout=8) as resp:
            return resp.status, resp.read(300_000)
    except HTTPError as exc:
        return exc.code, exc.read(200_000)


def ready_local():
    unauth, _ = request_url("http://127.0.0.1:18795/")
    auth, _ = request_url("http://127.0.0.1:18795/api/status",
                          tuple(CREDENTIALS.read_text().splitlines()))
    return unauth == 401 and auth == 200


def main():
    print("SOURCE", ROOT, flush=True)
    if not (ROOT / "console" / "COMMUNICATION.md").is_file():
        raise RuntimeError("invalid_repo_checkout")
    if not PYTHON.is_file():
        raise RuntimeError("chat_venv_missing")
    if not port_reachable(18794):
        raise RuntimeError("chat_console_not_running")
    binary = shutil.which("cloudflared")
    if not binary:
        raise RuntimeError("cloudflared_binary_not_found")

    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    PRIVATE.chmod(0o700)
    if not CREDENTIALS.exists():
        with CREDENTIALS.open("x", encoding="utf-8") as out:
            os.chmod(CREDENTIALS, 0o600)
            out.write("cybernova\n" + secrets.token_urlsafe(34) + "\n")
    credentials = tuple(CREDENTIALS.read_text(encoding="utf-8").splitlines())
    if len(credentials) != 2 or len(credentials[1]) < 24:
        raise RuntimeError("bad_web_credentials")

    started = []
    try:
        if not session_exists(ACCESS_SESSION):
            command = (
                "cd " + str(ROOT) + " && exec " + str(PYTHON) +
                " -m console.tunnel_access >>" + str(LOG_PROXY) + " 2>&1"
            )
            step(["tmux", "new-session", "-d", "-s", ACCESS_SESSION, command])
            started.append(ACCESS_SESSION)
        for _ in range(12):
            if port_reachable(BRIDGE_PORT):
                break
            time.sleep(0.5)
        if not port_reachable(BRIDGE_PORT):
            raise RuntimeError("access_proxy_not_listening")
        if not ready_local():
            raise RuntimeError("access_proxy_auth_smoke_failed")
        print("LOCAL_AUTH_SMOKE_PASSED", flush=True)

        if not session_exists(TUNNEL_SESSION):
            command = (
                "exec " + binary +
                " tunnel --no-autoupdate --url http://127.0.0.1:18795" +
                " --loglevel info >>" + str(LOG_TUNNEL) + " 2>&1"
            )
            step(["tmux", "new-session", "-d", "-s", TUNNEL_SESSION, command])
            started.append(TUNNEL_SESSION)
        url = None
        if LOG_TUNNEL.is_file():
            URL_FILE.unlink(missing_ok=True)
        for attempt in range(100):
            time.sleep(1)
            if not session_exists(TUNNEL_SESSION):
                raise RuntimeError("cloudflared_exited_before_url")
            content = LOG_TUNNEL.read_text(errors="replace") if LOG_TUNNEL.exists() else ""
            candidates = URL_PATTERN.findall(content)
            if candidates:
                url = candidates[-1].rstrip("/")
                if attempt % 5 == 0:
                    print("TUNNEL_URL_RECEIVED", flush=True)
                try:
                    unauthorized, _ = request_url(url + "/")
                    authorized, body = request_url(url + "/api/status", credentials)
                    if unauthorized == 401 and authorized == 200 and \
                       b"communication" in body:
                        break
                except (OSError, TimeoutError, URLError):
                    pass
        else:
            raise RuntimeError("public_tunnel_health_check_failed")

        if not url:
            raise RuntimeError("no_tunnel_url")
        with URL_FILE.open("w", encoding="utf-8") as out:
            os.chmod(URL_FILE, 0o600)
            out.write(url + "\n")
        print(json.dumps({
            "status": "TUNNEL_READY",
            "url": url + "/",
            "authentication": "http_basic_over_cloudflare_https",
            "username": credentials[0],
            "password_location": str(CREDENTIALS),
            "public_unauthenticated_http_status": 401,
            "public_authenticated_http_status": 200,
            "chat_backend_port": 18794,
            "tunnel_access_port": 18795,
            "mcp_exposed": False,
        }, ensure_ascii=False), flush=True)
    except Exception as exc:
        print("ACCESS_DEPLOY_ERROR", type(exc).__name__, str(exc), flush=True)
        if LOG_TUNNEL.exists():
            tail = LOG_TUNNEL.read_text(errors="replace")[-700:]
            tail = URL_PATTERN.sub("<TUNNEL_URL>", tail)
            print("TUNNEL_LOG_TAIL", tail, flush=True)
        for name in reversed(started):
            subprocess.run(["tmux", "kill-session", "-t", name],
                           capture_output=True, timeout=6)
        raise


if __name__ == "__main__":
    main()
