"""Portable four-service supervisor with bounded readiness and shutdown."""
from __future__ import annotations

import json
import logging
import os
import secrets
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from urllib import error, request

try:
    from .diagnostics import configure as configure_diagnostics, event as diagnostic_event
except ImportError:
    from diagnostics import configure as configure_diagnostics, event as diagnostic_event

MODULES = (
    "console.portable_tool_gateway",
    "console.communication_mcp",
    "console.server",
    "console.tunnel_access",
)
STOP_SECONDS = 7
STARTUP_TIMEOUT_SECONDS = 60
POLL_INTERVAL_SECONDS = 0.25
logger = logging.getLogger("cybernova.supervisor")


def _startup_timeout() -> float:
    try:
        value = int(os.environ.get("CYBERNOVA_STARTUP_TIMEOUT_SECONDS", "60"))
    except (TypeError, ValueError):
        value = STARTUP_TIMEOUT_SECONDS
    return float(max(1, min(value, 300)))


def _tcp_ready(port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_probe(url: str, timeout: float = 2.0) -> tuple[int | None, bytes]:
    opener = request.build_opener(request.ProxyHandler({}))
    req = request.Request(url, headers={"Accept": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as response:
            return int(response.status), response.read(256_000)
    except error.HTTPError as exc:
        try:
            exc.read(4096)
        except OSError:
            pass
        return int(exc.code), b""
    except (OSError, TimeoutError, ValueError):
        return None, b""


def _probe_module(module: str) -> bool:
    if module == "console.portable_tool_gateway":
        return _tcp_ready(18792)
    if module == "console.communication_mcp":
        return _tcp_ready(18796)
    if module == "console.server":
        status, _ = _http_probe("http://127.0.0.1:18794/api/status")
        return status == 200
    if module == "console.tunnel_access":
        status, _ = _http_probe("http://127.0.0.1:18795/")
        # The gateway is Basic-auth protected. An unauthenticated 401 proves
        # that the listener and HTTP handler are alive; it is not auth success.
        return status in {200, 401}
    return False


def _wait_for_ready(module: str, process, timeout: float, *,
                    probe=None, sleep_fn=None, clock=None) -> tuple[bool, str, int | None]:
    probe = probe or _probe_module
    sleep_fn = sleep_fn or time.sleep
    clock = clock or time.monotonic
    deadline = clock() + max(0.0, float(timeout))
    while True:
        exit_code = process.poll()
        if exit_code is not None:
            return False, "early_exit", int(exit_code)
        if probe(module):
            return True, "ready", None
        remaining = deadline - clock()
        if remaining <= 0:
            return False, "readiness_timeout", None
        sleep_fn(min(POLL_INTERVAL_SECONDS, remaining))


def _shutdown_children(children, *, stop_seconds: float = STOP_SECONDS,
                       clock=None) -> None:
    """Stop only child PIDs created by this supervisor, in reverse startup order."""
    clock = clock or time.monotonic
    for module, process in reversed(children):
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                logger.warning("service_terminate_failed module=%s", module)

    deadline = clock() + max(0.1, float(stop_seconds))
    forced = []
    for module, process in reversed(children):
        if process.poll() is not None:
            continue
        try:
            process.wait(timeout=max(0.05, deadline - clock()))
        except subprocess.TimeoutExpired:
            forced.append((module, process))
        except OSError:
            forced.append((module, process))

    for module, process in forced:
        if process.poll() is None:
            try:
                process.kill()
                logger.error("service_force_kill module=%s pid=%s", module, process.pid)
            except OSError:
                logger.error("service_force_kill_failed module=%s", module)
        try:
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            logger.error("service_exit_unconfirmed module=%s pid=%s", module, process.pid)


def run_supervisor(*, modules=MODULES, process_factory=None, readiness_probe=None,
                   startup_timeout: float | None = None, stop_seconds: float = STOP_SECONDS,
                   sleep_fn=None, clock=None, signal_module=None) -> int:
    """Run children and return 0 on requested shutdown, 1 on child exit, 2 on startup failure."""
    process_factory = process_factory or subprocess.Popen
    readiness_probe = readiness_probe or _probe_module
    sleep_fn = sleep_fn or time.sleep
    clock = clock or time.monotonic
    signal_module = signal_module or signal
    timeout = _startup_timeout() if startup_timeout is None else max(0.0, float(startup_timeout))
    children = []
    stopping = {"requested": False}
    exit_code = 0

    def request_stop(*_):
        stopping["requested"] = True

    signal_module.signal(signal_module.SIGTERM, request_stop)
    signal_module.signal(signal_module.SIGINT, request_stop)
    try:
        for module in modules:
            if stopping["requested"]:
                break
            try:
                process = process_factory(
                    [sys.executable, "-u", "-m", module],
                    env=os.environ.copy(),
                    start_new_session=False,
                )
            except OSError as exc:
                logger.error("service_spawn_failed module=%s error_type=%s",
                             module, type(exc).__name__)
                print("CYBERNOVA_STARTUP_FAILED", module, "spawn",
                      type(exc).__name__, flush=True)
                exit_code = 2
                stopping["requested"] = True
                break
            children.append((module, process))
            diagnostic_event("service_spawn", module=module, pid=process.pid)
            print("CYBERNOVA_SPAWNED", module, process.pid, flush=True)
            ready, stage, child_exit = _wait_for_ready(
                module, process, timeout, probe=readiness_probe,
                sleep_fn=sleep_fn, clock=clock,
            )
            if not ready:
                print("CYBERNOVA_STARTUP_FAILED", module, stage,
                      child_exit if child_exit is not None else "-", flush=True)
                diagnostic_event("service_startup_failed", module=module, pid=process.pid,
                                 stage=stage, exit_code=child_exit if child_exit is not None else -1)
                exit_code = 2
                stopping["requested"] = True
                break
            diagnostic_event("service_ready", module=module, pid=process.pid)
            print("CYBERNOVA_SERVICE_READY", module, process.pid, flush=True)

        if exit_code == 0 and not stopping["requested"]:
            # CYBERNOVA_STARTED is emitted only after every required service
            # has passed its own readiness probe.
            diagnostic_event("supervisor_ready", status="ok")
            print("CYBERNOVA_STARTED", flush=True)
            while not stopping["requested"]:
                for module, process in children:
                    child_exit = process.poll()
                    if child_exit is not None:
                        print("CYBERNOVA_SERVICE_STOPPED", module, child_exit, flush=True)
                        logger.error("service_stopped module=%s exit_code=%s",
                                     module, child_exit)
                        diagnostic_event("service_stopped", module=module,
                                         pid=process.pid, exit_code=child_exit, status="failed")
                        exit_code = 1
                        stopping["requested"] = True
                        break
                if not stopping["requested"]:
                    sleep_fn(1.0)
    except KeyboardInterrupt:
        stopping["requested"] = True
    finally:
        diagnostic_event("supervisor_shutdown_start", status="requested" if exit_code == 0 else "failed")
        _shutdown_children(children, stop_seconds=stop_seconds, clock=clock)
        diagnostic_event("supervisor_shutdown_complete", status="ok" if exit_code == 0 else "failed")

    return 0 if stopping["requested"] and exit_code == 0 else exit_code


def _doctor_report() -> dict:
    tool_gateway = _tcp_ready(18792)
    communication_mcp = _tcp_ready(18796)
    api_status, api_body = _http_probe("http://127.0.0.1:18794/api/status", timeout=4)
    access_status, _ = _http_probe("http://127.0.0.1:18795/", timeout=4)
    try:
        api_data = json.loads(api_body) if api_body else {}
    except (ValueError, TypeError):
        api_data = {}
    api_reachable = api_status == 200
    mcp_ready = bool(api_data.get("mcp_ready")) if isinstance(api_data, dict) else False
    access_gateway = access_status in {200, 401}
    runtime_ready = all((
        tool_gateway, communication_mcp, api_reachable, mcp_ready, access_gateway,
    ))
    return {
        "tool_gateway": tool_gateway,
        "communication_mcp": communication_mcp,
        "api_reachable": api_reachable,
        "api_status": api_status,
        "mcp_ready": mcp_ready,
        "access_gateway": access_gateway,
        "access_status": access_status,
        "runtime_ready": runtime_ready,
    }


def doctor() -> int:
    report = _doctor_report()
    print(json.dumps(report, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if report["runtime_ready"] else 1


def main() -> int:
    os.environ.setdefault("CYBERNOVA_COMM_DB", "/data/communications.sqlite3")
    os.environ.setdefault("CYBERNOVA_MCP_URL", "http://127.0.0.1:18792/mcp")
    os.environ.setdefault("CYBERNOVA_COMM_WORKER", "1")
    state = Path(os.environ["CYBERNOVA_COMM_DB"]).expanduser()
    state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    configure_diagnostics("supervisor")

    # Check the credential path before exists(), reads or creation. Never
    # follow or overwrite a symlink supplied as the access-secret file.
    auth_path = Path(os.environ.get("CYBERNOVA_ACCESS_SECRET_FILE", "/data/web_access.txt"))
    if auth_path.is_symlink():
        raise RuntimeError("access_credentials_symlink_forbidden")
    auth_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not auth_path.exists():
        fd = os.open(auth_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as secret_out:
            secret_out.write("cybernova\n" + secrets.token_urlsafe(36) + "\n")
            secret_out.flush()
            os.fsync(secret_out.fileno())
    if auth_path.is_symlink():
        raise RuntimeError("access_credentials_symlink_forbidden")

    return run_supervisor()


if __name__ == "__main__":
    if sys.argv[1:] == ["doctor"]:
        sys.exit(doctor())
    sys.exit(main())
