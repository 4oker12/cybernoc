"""Portable single-container process supervisor for Cybernova.

Runs Tool MCP, Communication MCP, and first-party Chat as sibling processes
sharing one loopback namespace. Avoids granting public access to tool/MCP.
Docker/Podman/Kubernetes restart policy manages this supervisor. Never run
two copies against the same SQLite database or local GPU simultaneously.
"""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler

try:
    from .diagnostics import configure as configure_diagnostics
except ImportError:
    from diagnostics import configure as configure_diagnostics

MODULES = (
    "console.portable_tool_gateway",
    "console.communication_mcp",
    "console.server",
    "console.tunnel_access",
)
STOP_SECONDS = 7


def main():
    os.environ.setdefault("CYBERNOVA_COMM_DB", "/data/communications.sqlite3")
    os.environ.setdefault("CYBERNOVA_MCP_URL", "http://127.0.0.1:18792/mcp")
    os.environ.setdefault("CYBERNOVA_COMM_WORKER", "1")
    state = Path(os.environ["CYBERNOVA_COMM_DB"]).expanduser()
    state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    configure_diagnostics("supervisor")
    # Only the Basic-auth gateway is published; MCP/model stay loopback.
    auth_path = Path(os.environ.get("CYBERNOVA_ACCESS_SECRET_FILE", "/data/web_access.txt"))
    auth_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not auth_path.exists():
        fd = os.open(auth_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as secret_out:
            secret_out.write("cybernova\n" + secrets.token_urlsafe(36) + "\n")
            secret_out.flush()
            os.fsync(secret_out.fileno())
    if auth_path.is_symlink():
        raise RuntimeError("access_credentials_symlink_forbidden")
    processes = []
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True
        for process in processes:
            if process.poll() is None:
                process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for module in MODULES:
            process = subprocess.Popen(
                [sys.executable, "-u", "-m", module],
                env=os.environ.copy(),
                start_new_session=False,
            )
            processes.append(process)
            print("CYBERNOVA_STARTED", module, process.pid, flush=True)
            time.sleep(0.15)
        while not stopping:
            for module, process in zip(MODULES, processes):
                code = process.poll()
                if code is not None:
                    print("CYBERNOVA_SERVICE_STOPPED", module, code, flush=True)
                    logging.getLogger("cybernova.supervisor").error(
                        "service_stopped module=%s exit_code=%s", module, code,
                    )
                    stopping = True
                    break
            if not stopping:
                time.sleep(1)
    finally:
        stop()
        deadline = time.monotonic() + STOP_SECONDS
        for process in processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
    return 1


def doctor():
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:18794/api/status", timeout=8) as response:
            if response.status != 200:
                return 1
            import json
            body = json.load(response)
            if not body.get("mcp_ready"):
                return 1
            return 0
    except (OSError, TimeoutError, ValueError):
        return 1


if __name__ == "__main__":
    if sys.argv[1:] == ["doctor"]:
        sys.exit(doctor())
    sys.exit(main())
