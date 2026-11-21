"""Bounded local Windows computer-use and health-inspection tools for Account GPT.

The module exposes safe file navigation, application launch, system/performance
inventory, Microsoft Defender status/scanning, and optional visual UI inspection.
It never exposes arbitrary shell execution, file deletion, process termination,
registry writes, or security-setting changes.
"""
from __future__ import annotations

import base64
import fnmatch
import io
import os
import platform
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:  # surfaced as a clear runtime capability error
    psutil = None

MAX_ENTRIES = 100
MAX_SEARCH_HITS = 60
MAX_SEARCH_VISITS = 5000
MAX_FILE_BYTES = 250_000
MAX_TEXT_CHARS = 12_000

SENSITIVE_COMPONENTS = {
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
    ".config", ".local", "appdata", "application data",
    "cookies", "login data", "web data", "wallet", "wallets",
    "credentials", "secrets", "secret", "tokens", "token",
    "gpt-chromium-profile", "model_api_key", "web_access.txt",
    "ntuser.dat", "sam", "security", "system",
}
SENSITIVE_NAME = re.compile(
    r"(?i)(^\.env(?:\.|$)|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"password|passwd|credential|secret|cookie|login.?data|wallet|"
    r"id_rsa|id_ed25519|\.pem$|\.key$)"
)
SECRET_VALUE = re.compile(
    r"(?i)(Bearer\s+[A-Za-z0-9._~-]{8,}|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|"
    r"secret|authorization|cookie)\s*[:=]\s*[^\s,;]+)"
)
EMAIL_VALUE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
HIGH_IMPACT_UI = re.compile(
    r"(?i)(delete|remove|uninstall|format|reset|restore|shutdown|restart|"
    r"disable|deactivate|turn\s+off|stop|kill|terminate|submit|send|purchase|"
    r"pay|confirm|apply|save|scan|quarantine|clean|allow|block|enable|"
    r"install|update|оплат|удал|сброс|восстанов|отключ|выключ|перезапуск|"
    r"останов|подтверд|примен|сохран|скан|карантин|очист|разреш|установ|обнов)"
)
SAFE_UI_CONTROL_TYPES = {
    "Button", "TabItem", "TreeItem", "ListItem", "MenuItem", "Hyperlink",
}
TEXT_EXTENSIONS = {
    ".txt", ".log", ".md", ".json", ".csv", ".xml", ".ini", ".conf",
    ".yaml", ".yml", ".toml", ".out",
}

APP_COMMANDS = {
    "file_explorer": ("explorer.exe",),
    "task_manager": ("taskmgr.exe",),
    "resource_monitor": ("resmon.exe",),
    "performance_monitor": ("perfmon.exe",),
    "reliability_monitor": ("perfmon.exe", "/rel"),
    "event_viewer": ("mmc.exe", "eventvwr.msc"),
    "device_manager": ("mmc.exe", "devmgmt.msc"),
    "services": ("mmc.exe", "services.msc"),
    "system_information": ("msinfo32.exe",),
    "control_panel": ("control.exe",),
    "windows_security": ("explorer.exe", "windowsdefender:"),
    "windows_update": ("explorer.exe", "ms-settings:windowsupdate"),
    "startup_apps": ("explorer.exe", "ms-settings:startupapps"),
    "windows_settings": ("explorer.exe", "ms-settings:"),
    "disk_cleanup": ("cleanmgr.exe",),
}


def _tool(name: str, description: str, properties=None, required=None):
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
            "additionalProperties": False,
        },
    }


STRING = {"type": "string"}
INTEGER = {"type": "integer"}
COMPUTER_TOOLS = [
    _tool("computer_system_overview",
          "Inspect local Windows version, hardware capacity, uptime and boot time. Read-only."),
    _tool("computer_performance_snapshot",
          "Measure current CPU, RAM, swap, disk and network-I/O usage; include a short top-process sample. Read-only."),
    _tool("computer_process_list",
          "List running process names, PIDs and memory usage. Never returns command lines, environment variables or process handles.",
          {"limit": {**INTEGER, "description": "Maximum rows, 1 to 40"}}, ["limit"]),
    _tool("computer_disk_overview",
          "Inspect local fixed/removable drive capacity and free space. Read-only."),
    _tool("computer_service_overview",
          "Inspect a curated set of Windows security, firewall, update and management service states. Read-only."),
    _tool("computer_startup_items",
          "Inspect Windows Run/RunOnce registry entries and Startup-folder item names. Values are redacted; no changes are made."),
    _tool("computer_list_directory",
          "List one local directory under the user's profile, Windows, Program Files or ProgramData. Sensitive folders and secret-like filenames are hidden; file contents are not read.",
          {"path": {**STRING, "description": "Absolute path or path relative to the user profile"},
           "limit": {**INTEGER, "description": "Maximum entries, 1 to 100"}}, ["path", "limit"]),
    _tool("computer_search_files",
          "Search filenames (not file contents) beneath one approved local directory. Hidden, sensitive and symlinked folders are skipped; traversal is bounded.",
          {"root": STRING, "pattern": STRING,
           "limit": {**INTEGER, "description": "Maximum matches, 1 to 60"}}, ["root", "pattern", "limit"]),
    _tool("computer_read_text_file",
          "Read a small text/log/config file from an approved local directory. Sensitive paths and secret-like filenames are blocked; common secrets and email addresses are redacted.",
          {"path": STRING,
           "max_chars": {**INTEGER, "description": "Maximum returned characters, 500 to 12000"}}, ["path", "max_chars"]),
    _tool("computer_open_folder",
          "Open a local folder in Windows File Explorer. Only approved local roots are allowed; sensitive paths are blocked.",
          {"path": STRING}, ["path"]),
    _tool("computer_open_app",
          "Launch one allowlisted Windows diagnostic or settings application without elevation or shell execution.",
          {"app": {"type": "string", "enum": sorted(APP_COMMANDS)}}, ["app"]),
    _tool("computer_screenshot",
          "Capture the visible local desktop and send the image to Account GPT for visual inspection. Use only when needed; visible personal information may be included."),
    _tool("computer_ui_windows",
          "List visible top-level desktop windows by title for local UI navigation. No window contents or input values are read."),
    _tool("computer_ui_controls",
          "Inspect visible, enabled, non-input UI control labels in one exact window. Text fields, password fields and document contents are excluded.",
          {"window_title": STRING}, ["window_title"]),
    _tool("computer_ui_click",
          "Click one exact visible navigation control in one exact window. Only buttons/tabs/tree/list/menu links are eligible. Destructive, security-changing, scan, save, submit and confirmation labels are blocked.",
          {"window_title": STRING, "control_name": STRING,
           "control_type": {"type": "string", "enum": sorted(SAFE_UI_CONTROL_TYPES)}},
          ["window_title", "control_name", "control_type"]),
    _tool("computer_defender_status",
          "Inspect Microsoft Defender service state, platform executable presence and signature-version registry metadata. Read-only."),
    _tool("computer_defender_events",
          "Read recent Microsoft-Windows-Windows Defender operational events for scan completion and threat detections. Read-only."),
    _tool("computer_defender_scan",
          "Start a Microsoft Defender quick or full scan. Requires an explicit user instruction in the current conversation; full scans require explicit full-scan authorization. The scan can increase CPU/disk load.",
          {"scan_type": {"type": "string", "enum": ["quick", "full"]}}, ["scan_type"]),
    _tool("computer_defender_scan_status",
          "Check the locally started Defender scan process and recent Defender operational events. Read-only."),
]
COMPUTER_TOOL_NAMES = frozenset(item["name"] for item in COMPUTER_TOOLS)

_SCAN_JOBS: dict[int, dict] = {}


def _redact(value: str) -> str:
    value = SECRET_VALUE.sub("[REDACTED]", value)
    return EMAIL_VALUE.sub("[REDACTED EMAIL]", value)


def _windows_only():
    if platform.system() != "Windows":
        raise RuntimeError("local_windows_computer_tools_unavailable")


def _roots() -> list[Path]:
    candidates = [
        Path.home(),
        Path(os.environ.get("WINDIR", r"C:\Windows")),
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("ProgramData", r"C:\ProgramData")),
        Path(os.environ.get("SystemDrive", "C:") + "\\"),
    ]
    roots = []
    for item in candidates:
        try:
            resolved = item.resolve(strict=True)
            if resolved.is_dir() and resolved not in roots:
                roots.append(resolved)
        except OSError:
            continue
    return roots


def _sensitive_component(name: str) -> bool:
    lowered = name.casefold()
    return lowered in SENSITIVE_COMPONENTS or bool(SENSITIVE_NAME.search(name))


def _resolve_local_path(raw: object, *, must_exist=True) -> Path:
    _windows_only()
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 1000:
        raise ValueError("computer_path_invalid")
    expanded = os.path.expandvars(os.path.expanduser(raw.strip()))
    candidate = Path(expanded)
    if not candidate.is_absolute():
        candidate = Path.home() / candidate
    try:
        absolute = Path(os.path.abspath(candidate))
        resolved = absolute.resolve(strict=must_exist)
    except (OSError, RuntimeError):
        raise ValueError("computer_path_not_found_or_unavailable") from None
    if any(_sensitive_component(part) for part in absolute.parts):
        raise ValueError("computer_sensitive_path_blocked")
    if any(node.is_symlink() for node in [absolute, *absolute.parents]):
        raise ValueError("computer_symlink_path_blocked")
    if not any(resolved == root or resolved.is_relative_to(root) for root in _roots()):
        raise ValueError("computer_path_outside_approved_roots")
    if must_exist and not resolved.exists():
        raise ValueError("computer_path_not_found")
    return resolved


def _decode(data: bytes) -> str:
    try:
        return data.decode("oem", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _fixed_command(argv: list[str], timeout=12) -> dict:
    try:
        result = subprocess.run(
            argv, shell=False, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=timeout, text=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "command_timeout"}
    except OSError as exc:
        return {"ok": False, "error": type(exc).__name__}
    return {
        "ok": result.returncode == 0,
        "exit_code": result.returncode,
        "output": _redact((_decode(result.stdout or b"") + "\n" +
                           _decode(result.stderr or b"")).strip())[:9000],
    }


def _system32(name: str) -> str:
    root = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
    candidate = root / name
    return str(candidate) if candidate.is_file() else (shutil.which(name) or str(candidate))


def _system_overview() -> dict:
    if psutil is None:
        return {"ok": False, "error": "psutil_dependency_missing"}
    _windows_only()
    vm = psutil.virtual_memory()
    boot = datetime.fromtimestamp(psutil.boot_time(), timezone.utc).astimezone()
    return {
        "ok": True,
        "os": platform.platform(),
        "windows_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor()[:160],
        "logical_cpu_count": psutil.cpu_count(logical=True),
        "physical_cpu_count": psutil.cpu_count(logical=False),
        "ram_total_bytes": vm.total,
        "ram_available_bytes": vm.available,
        "ram_used_percent": vm.percent,
        "boot_time_local": boot.isoformat(timespec="seconds"),
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
    }


def _performance_snapshot() -> dict:
    if psutil is None:
        return {"ok": False, "error": "psutil_dependency_missing"}
    _windows_only()
    cpu = psutil.cpu_percent(interval=0.6)
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk_io = psutil.disk_io_counters()
    net_io = psutil.net_io_counters(pernic=True)
    partitions = []
    for part in psutil.disk_partitions(all=False):
        if len(part.mountpoint) >= 2 and part.mountpoint[1] == ":":
            try:
                usage = psutil.disk_usage(part.mountpoint)
                partitions.append({
                    "drive": part.mountpoint,
                    "total_bytes": usage.total,
                    "free_bytes": usage.free,
                    "used_percent": usage.percent,
                })
            except OSError:
                pass
    processes = []
    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            info = proc.info
            memory = info.get("memory_info")
            processes.append({
                "pid": info.get("pid"),
                "name": (info.get("name") or "unknown")[:100],
                "rss_bytes": memory.rss if memory else 0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    top_memory = sorted(processes, key=lambda x: x["rss_bytes"], reverse=True)[:8]
    return {
        "ok": True,
        "cpu_percent_sample": cpu,
        "memory": {
            "total_bytes": vm.total, "available_bytes": vm.available,
            "used_percent": vm.percent,
        },
        "swap": {
            "total_bytes": swap.total, "used_bytes": swap.used,
            "used_percent": swap.percent,
        },
        "disks": partitions,
        "disk_io": ({
            "read_bytes": disk_io.read_bytes, "write_bytes": disk_io.write_bytes,
            "read_count": disk_io.read_count, "write_count": disk_io.write_count,
        } if disk_io else None),
        "network_io": {
            name: {"bytes_sent": value.bytes_sent, "bytes_recv": value.bytes_recv,
                   "packets_sent": value.packets_sent, "packets_recv": value.packets_recv,
                   "errors_in": value.errin, "errors_out": value.errout,
                   "drops_in": value.dropin, "drops_out": value.dropout}
            for name, value in net_io.items()
        },
        "top_processes_by_memory": top_memory,
    }


def _process_list(limit: int) -> dict:
    if psutil is None:
        return {"ok": False, "error": "psutil_dependency_missing"}
    _windows_only()
    limit = max(1, min(int(limit), 40))
    rows = []
    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            info = proc.info
            mem = info.get("memory_info")
            rows.append({
                "pid": info.get("pid"),
                "name": (info.get("name") or "unknown")[:100],
                "memory_bytes": mem.rss if mem else 0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    rows.sort(key=lambda item: item["memory_bytes"], reverse=True)
    return {"ok": True, "count_returned": min(limit, len(rows)), "processes": rows[:limit]}


def _disk_overview() -> dict:
    if psutil is None:
        return {"ok": False, "error": "psutil_dependency_missing"}
    _windows_only()
    rows = []
    for part in psutil.disk_partitions(all=False):
        if len(part.mountpoint) >= 2 and part.mountpoint[1] == ":":
            try:
                usage = psutil.disk_usage(part.mountpoint)
                rows.append({
                    "drive": part.mountpoint, "filesystem": part.fstype,
                    "total_bytes": usage.total, "used_bytes": usage.used,
                    "free_bytes": usage.free, "used_percent": usage.percent,
                })
            except OSError:
                continue
    return {"ok": True, "drives": rows}


def _list_directory(path_raw: str, limit: int) -> dict:
    path = _resolve_local_path(path_raw)
    if not path.is_dir():
        raise ValueError("computer_path_is_not_directory")
    limit = max(1, min(int(limit), MAX_ENTRIES))
    rows = []
    with os.scandir(path) as entries:
        for entry in sorted(entries, key=lambda item: (not item.is_dir(follow_symlinks=False), item.name.casefold())):
            if entry.is_symlink() or _sensitive_component(entry.name):
                continue
            try:
                stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            rows.append({
                "name": entry.name[:180],
                "type": "directory" if entry.is_dir(follow_symlinks=False) else "file",
                "size_bytes": None if entry.is_dir(follow_symlinks=False) else stat.st_size,
                "modified_local": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc
                ).astimezone().isoformat(timespec="seconds"),
            })
            if len(rows) >= limit:
                break
    return {"ok": True, "path": str(path), "entries": rows, "truncated": len(rows) >= limit}


def _search_files(root_raw: str, pattern: str, limit: int) -> dict:
    root = _resolve_local_path(root_raw)
    if not root.is_dir():
        raise ValueError("computer_search_root_not_directory")
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 120 or any(x in pattern for x in ("/", "\\", ":")):
        raise ValueError("computer_filename_pattern_invalid")
    limit = max(1, min(int(limit), MAX_SEARCH_HITS))
    hits, visited = [], 0
    for base, dirs, names in os.walk(root, followlinks=False):
        base_path = Path(base)
        depth = len(base_path.relative_to(root).parts)
        if depth >= 6:
            dirs[:] = []
        else:
            dirs[:] = [
                d for d in dirs
                if not _sensitive_component(d) and not (base_path / d).is_symlink()
                and not d.startswith("$")
            ]
        for name in names:
            visited += 1
            if visited > MAX_SEARCH_VISITS:
                return {"ok": True, "root": str(root), "pattern": pattern,
                        "hits": hits, "truncated": True, "visited_limit_reached": True}
            if _sensitive_component(name) or not fnmatch.fnmatch(name.casefold(), pattern.casefold()):
                continue
            item = base_path / name
            try:
                stat = item.stat(follow_symlinks=False)
            except OSError:
                continue
            hits.append({
                "path": str(item), "size_bytes": stat.st_size,
                "modified_local": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc
                ).astimezone().isoformat(timespec="seconds"),
            })
            if len(hits) >= limit:
                return {"ok": True, "root": str(root), "pattern": pattern,
                        "hits": hits, "truncated": True, "visited": visited}
    return {"ok": True, "root": str(root), "pattern": pattern,
            "hits": hits, "truncated": False, "visited": visited}


def _read_text_file(path_raw: str, max_chars: int) -> dict:
    path = _resolve_local_path(path_raw)
    if not path.is_file() or path.suffix.casefold() not in TEXT_EXTENSIONS:
        raise ValueError("computer_text_file_type_not_allowed")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("computer_text_file_too_large")
    max_chars = max(500, min(int(max_chars), MAX_TEXT_CHARS))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raise ValueError("computer_text_file_read_failed") from None
    redacted = _redact(text)
    return {
        "ok": True, "path": str(path), "size_bytes": path.stat().st_size,
        "content": redacted[:max_chars],
        "truncated": len(redacted) > max_chars,
    }


def _open_folder(path_raw: str) -> dict:
    path = _resolve_local_path(path_raw)
    if not path.is_dir():
        raise ValueError("computer_path_is_not_directory")
    explorer = _system32("explorer.exe")
    process = subprocess.Popen([explorer, str(path)], shell=False,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "opened": str(path), "process_id": process.pid,
            "application": "Windows File Explorer"}


def _open_app(app: str) -> dict:
    _windows_only()
    if app not in APP_COMMANDS:
        raise ValueError("computer_app_not_allowlisted")
    argv = list(APP_COMMANDS[app])
    executable = _system32(argv[0])
    process = subprocess.Popen([executable, *argv[1:]], shell=False,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True, "app": app, "process_id": process.pid,
            "launched": argv[0], "elevated": False}


def _startup_items() -> dict:
    _windows_only()
    import winreg
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    rows = []
    for hive, key_path in keys:
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    rows.append({
                        "registry": key_path, "name": str(name)[:120],
                        "command": _redact(str(value))[:500],
                    })
                    index += 1
        except OSError:
            continue
    startup_dirs = [
        Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    for folder in startup_dirs:
        try:
            if folder.is_dir() and not any(_sensitive_component(p) for p in folder.parts):
                for item in folder.iterdir():
                    if not item.is_symlink() and not _sensitive_component(item.name):
                        rows.append({"startup_folder": str(folder), "name": item.name[:180]})
        except OSError:
            continue
    return {"ok": True, "items": rows[:100], "count": min(len(rows), 100)}


def _service_overview() -> dict:
    if psutil is None:
        return {"ok": False, "error": "psutil_dependency_missing"}
    _windows_only()
    wanted = {
        "WinDefend", "WdNisSvc", "SecurityHealthService", "wscsvc",
        "MpsSvc", "wuauserv", "BITS", "Winmgmt", "EventLog",
        "Dnscache", "Dhcp", "NlaSvc", "LanmanWorkstation",
    }
    rows = []
    for service in psutil.win_service_iter():
        try:
            info = service.as_dict()
            if info.get("name") in wanted:
                rows.append({
                    "name": info.get("name"),
                    "display_name": info.get("display_name"),
                    "status": info.get("status"),
                    "start_type": info.get("start_type"),
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return {"ok": True, "services": sorted(rows, key=lambda x: x["name"] or "")}


def _find_mpcmdrun() -> Path | None:
    roots = [
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) /
        r"Microsoft\Windows Defender\Platform",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender",
    ]
    candidates = []
    for root in roots:
        try:
            if root.is_file() and root.name.casefold() == "mpcmdrun.exe":
                candidates.append(root)
            elif root.is_dir():
                candidates.extend(root.glob("*/MpCmdRun.exe"))
                direct = root / "MpCmdRun.exe"
                if direct.is_file():
                    candidates.append(direct)
        except OSError:
            continue
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def _defender_status() -> dict:
    _windows_only()
    services = {}
    for service in ("WinDefend", "WdNisSvc", "SecurityHealthService", "wscsvc"):
        result = _fixed_command([_system32("sc.exe"), "query", service])
        match = re.search(r"(?im)^\s*STATE\s*:\s*\d+\s+([A-Z_]+)", result.get("output", ""))
        services[service] = match.group(1) if match else (
            "UNKNOWN" if result.get("ok") else result.get("error", "QUERY_FAILED")
        )
    signatures = {}
    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as key:
            for name in ("AVSignatureVersion", "AVSignatureLastUpdated", "EngineVersion"):
                try:
                    value, _kind = winreg.QueryValueEx(key, name)
                    signatures[name] = str(value)[:120]
                except OSError:
                    continue
    except OSError:
        signatures = {"registry_read": "unavailable"}
    antivirus_products = {"available": False, "products": []}
    try:
        from win32com.client import GetObject
        security_center = GetObject(r"winmgmts:\\.\root\SecurityCenter2")
        products = []
        for product in security_center.ExecQuery(
            "SELECT displayName, productState FROM AntiVirusProduct"
        ):
            products.append({
                "name": _redact(str(getattr(product, "displayName", "")))[:160],
                "product_state_raw": int(getattr(product, "productState", 0)),
            })
        antivirus_products = {"available": True, "products": products}
    except Exception as exc:
        antivirus_products = {"available": False, "reason": type(exc).__name__, "products": []}
    exe = _find_mpcmdrun()
    return {
        "ok": True, "services": services,
        "security_center_antivirus_products": antivirus_products,
        "signature_metadata": signatures,
        "mpcmdrun_present": bool(exe),
        "mpcmdrun_path": str(exe) if exe else None,
        "note": "Service state and signature metadata are not a complete antivirus-product inventory.",
    }


def _defender_events() -> dict:
    _windows_only()
    query = "*[System[(EventID=1000 or EventID=1001 or EventID=1116 or EventID=1117 or EventID=5007)]]"
    result = _fixed_command([
        _system32("wevtutil.exe"), "qe",
        "Microsoft-Windows-Windows Defender/Operational",
        "/q:" + query, "/rd:true", "/c:15", "/f:text",
    ], timeout=18)
    if not result.get("ok"):
        return {"ok": False, "error": "defender_event_log_query_failed",
                "details": result.get("output", "")[:1500]}
    return {"ok": True, "events": result.get("output", "")[:10000],
            "event_ids": [1000, 1001, 1116, 1117, 5007]}


def extract_user_computer_approvals(messages) -> set[str]:
    """Only the latest user turn can authorize a Defender scan."""
    if not isinstance(messages, list):
        return set()
    latest_user_index = None
    for index in range(len(messages) - 1, -1, -1):
        item = messages[index]
        if isinstance(item, dict) and item.get("role") == "user":
            latest_user_index = index
            break
    if latest_user_index is None:
        return set()
    latest = str(messages[latest_user_index].get("content") or "").casefold()
    previous_assistant = ""
    for index in range(latest_user_index - 1, -1, -1):
        item = messages[index]
        if isinstance(item, dict) and item.get("role") == "assistant":
            previous_assistant = str(item.get("content") or "").casefold()
            break
    affirmative = bool(re.search(
        r"\b(разрешаю|подтверждаю|запускай|запусти|проведи|выполни|начинай|"
        r"run|start|perform|launch|authorize|confirm)\b", latest
    ))
    if not affirmative and re.fullmatch(r"\s*(да|yes|подтверждаю|разрешаю)[!. ]*\s*", latest):
        affirmative = bool(re.search(
            r"(defender|антивирус|вирус|полную проверку|быструю проверку|scan)",
            previous_assistant,
        ))
    if not affirmative:
        return set()
    context = latest + " " + previous_assistant
    if not re.search(r"(defender|антивирус|вирус|защит[аы]|malware)", context):
        return set()
    affirmative_only = bool(re.fullmatch(
        r"\s*(да|yes|подтверждаю|разрешаю)[!. ]*\s*", latest
    ))
    scan_context = latest + (" " + previous_assistant if affirmative_only else "")
    if re.search(r"(полную|полный|full)\s*(провер|скан|scan)", scan_context):
        return {"defender_full_scan"}
    if re.search(r"(быструю|быстрый|quick)\s*(провер|скан|scan)", scan_context):
        return {"defender_quick_scan"}
    if re.search(r"(провер|скан|scan)", latest):
        return {"defender_quick_scan"}
    return set()


def _start_defender_scan(scan_type: str, approved_actions: set[str]) -> dict:
    _windows_only()
    if scan_type not in {"quick", "full"}:
        raise ValueError("defender_scan_type_invalid")
    required = "defender_full_scan" if scan_type == "full" else "defender_quick_scan"
    if required not in approved_actions:
        phrase = (
            "Напишите: «Разрешаю полную проверку Microsoft Defender»."
            if scan_type == "full" else
            "Напишите: «Разрешаю быструю проверку Microsoft Defender»."
        )
        return {"ok": False, "approval_required": True, "scan_type": scan_type,
                "required_user_confirmation": phrase}
    exe = _find_mpcmdrun()
    if exe is None:
        return {"ok": False, "error": "defender_mpcmdrun_not_found"}
    scan_number = "2" if scan_type == "full" else "1"
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        process = subprocess.Popen(
            [str(exe), "-Scan", "-ScanType", scan_number],
            shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=flags,
        )
    except OSError as exc:
        return {"ok": False, "error": "defender_scan_start_failed",
                "details": type(exc).__name__}
    _SCAN_JOBS[process.pid] = {
        "pid": process.pid, "scan_type": scan_type,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "process": process,
    }
    return {
        "ok": True, "started": True, "scan_type": scan_type,
        "process_id": process.pid,
        "note": "Scan was requested from Microsoft Defender. Check scan status and Defender Operational events for completion and detections.",
    }


def _defender_scan_status() -> dict:
    _windows_only()
    rows = []
    for pid, job in list(_SCAN_JOBS.items()):
        process = job.get("process")
        return_code = process.poll() if process is not None else None
        rows.append({
            "process_id": pid, "scan_type": job.get("scan_type"),
            "started_at": job.get("started_at"),
            "launcher_process": "running" if return_code is None else "finished",
            "launcher_exit_code": return_code,
        })
    events = _defender_events()
    return {"ok": True, "known_scan_launches": rows,
            "defender_events": events.get("events", events.get("details", ""))[:7000],
            "event_query_ok": events.get("ok", False)}


def _screenshot() -> dict:
    _windows_only()
    try:
        import pyautogui
        image = pyautogui.screenshot()
        image.thumbnail((1600, 1000))
        buffer = io.BytesIO()
        image.convert("RGB").save(buffer, format="JPEG", quality=72, optimize=True)
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    except Exception as exc:
        return {"ok": False, "error": "desktop_screenshot_unavailable",
                "details": type(exc).__name__}
    return {"ok": True, "image_data_url": "data:image/jpeg;base64," + encoded,
            "note": "Desktop image is being sent to Account GPT for visual analysis."}


def _desktop():
    _windows_only()
    try:
        from pywinauto import Desktop
    except ImportError:
        raise RuntimeError("pywinauto_dependency_missing") from None
    return Desktop(backend="uia")


def _ui_windows() -> dict:
    desktop = _desktop()
    rows = []
    for window in desktop.windows(visible_only=True):
        try:
            title = (window.window_text() or "").strip()
            if title:
                rows.append({
                    "title": _redact(title)[:180],
                    "handle": int(window.handle),
                    "process_id": int(window.process_id()),
                })
        except Exception:
            continue
        if len(rows) >= 50:
            break
    return {"ok": True, "windows": rows}


def _find_window(title: str):
    if not isinstance(title, str) or not title.strip() or len(title) > 180:
        raise ValueError("computer_window_title_invalid")
    matches = []
    for window in _desktop().windows(visible_only=True):
        try:
            if window.window_text().strip() == title.strip():
                matches.append(window)
        except Exception:
            continue
    if len(matches) != 1:
        raise ValueError("computer_window_not_found_or_ambiguous")
    return matches[0]


def _ui_controls(window_title: str) -> dict:
    window = _find_window(window_title)
    rows = []
    for control in window.descendants():
        try:
            info = control.element_info
            name = (info.name or "").strip()
            kind = info.control_type or ""
            if not name or kind not in SAFE_UI_CONTROL_TYPES:
                continue
            if _sensitive_component(name) or HIGH_IMPACT_UI.search(name):
                continue
            if not control.is_visible() or not control.is_enabled():
                continue
            rect = control.rectangle()
            rows.append({
                "name": _redact(name)[:140], "control_type": kind,
                "rectangle": [rect.left, rect.top, rect.right, rect.bottom],
            })
        except Exception:
            continue
        if len(rows) >= 120:
            break
    return {"ok": True, "window_title": window_title,
            "controls": rows, "count": len(rows)}


def _ui_click(window_title: str, control_name: str, control_type: str) -> dict:
    if control_type not in SAFE_UI_CONTROL_TYPES:
        raise ValueError("computer_ui_control_type_blocked")
    if not isinstance(control_name, str) or not control_name.strip() or len(control_name) > 140:
        raise ValueError("computer_ui_control_name_invalid")
    if HIGH_IMPACT_UI.search(control_name) or _sensitive_component(control_name):
        raise ValueError("computer_ui_high_impact_action_blocked")
    window = _find_window(window_title)
    matches = []
    for control in window.descendants():
        try:
            info = control.element_info
            if (info.control_type == control_type and
                    (info.name or "").strip() == control_name.strip() and
                    control.is_visible() and control.is_enabled()):
                matches.append(control)
        except Exception:
            continue
    if len(matches) != 1:
        raise ValueError("computer_ui_control_not_found_or_ambiguous")
    matches[0].click_input()
    return {"ok": True, "window_title": window_title,
            "clicked_control": control_name, "control_type": control_type}


def computer_control_call(name: str, args: dict, *, user_messages=None) -> tuple[dict, bool]:
    if name not in COMPUTER_TOOL_NAMES:
        return {"ok": False, "error": "computer_tool_not_registered"}, True
    if not isinstance(args, dict):
        return {"ok": False, "error": "computer_tool_arguments_invalid"}, True
    try:
        if name in {"computer_system_overview", "computer_performance_snapshot",
                    "computer_process_list", "computer_disk_overview",
                    "computer_service_overview", "computer_startup_items",
                    "computer_defender_status", "computer_defender_events",
                    "computer_defender_scan_status", "computer_screenshot",
                    "computer_ui_windows"} and args:
            raise ValueError("computer_tool_takes_no_arguments")
        if name == "computer_system_overview":
            return _system_overview(), False
        if name == "computer_performance_snapshot":
            return _performance_snapshot(), False
        if name == "computer_process_list":
            return _process_list(args.get("limit", 25)), False
        if name == "computer_disk_overview":
            return _disk_overview(), False
        if name == "computer_service_overview":
            return _service_overview(), False
        if name == "computer_startup_items":
            return _startup_items(), False
        if name == "computer_list_directory":
            if set(args) != {"path", "limit"}:
                raise ValueError("computer_list_directory_arguments_invalid")
            return _list_directory(args["path"], args["limit"]), False
        if name == "computer_search_files":
            if set(args) != {"root", "pattern", "limit"}:
                raise ValueError("computer_search_files_arguments_invalid")
            return _search_files(args["root"], args["pattern"], args["limit"]), False
        if name == "computer_read_text_file":
            if set(args) != {"path", "max_chars"}:
                raise ValueError("computer_read_text_file_arguments_invalid")
            return _read_text_file(args["path"], args["max_chars"]), False
        if name == "computer_open_folder":
            if set(args) != {"path"}:
                raise ValueError("computer_open_folder_arguments_invalid")
            return _open_folder(args["path"]), False
        if name == "computer_open_app":
            if set(args) != {"app"}:
                raise ValueError("computer_open_app_arguments_invalid")
            return _open_app(args["app"]), False
        if name == "computer_screenshot":
            result = _screenshot()
            return result, not bool(result.get("ok"))
        if name == "computer_ui_windows":
            return _ui_windows(), False
        if name == "computer_ui_controls":
            if set(args) != {"window_title"}:
                raise ValueError("computer_ui_controls_arguments_invalid")
            return _ui_controls(args["window_title"]), False
        if name == "computer_ui_click":
            if set(args) != {"window_title", "control_name", "control_type"}:
                raise ValueError("computer_ui_click_arguments_invalid")
            return _ui_click(args["window_title"], args["control_name"], args["control_type"]), False
        if name == "computer_defender_status":
            return _defender_status(), False
        if name == "computer_defender_events":
            return _defender_events(), False
        if name == "computer_defender_scan":
            if set(args) != {"scan_type"}:
                raise ValueError("computer_defender_scan_arguments_invalid")
            approved = extract_user_computer_approvals(user_messages or [])
            result = _start_defender_scan(args["scan_type"], approved)
            return result, not bool(result.get("ok"))
        if name == "computer_defender_scan_status":
            return _defender_scan_status(), False
        raise ValueError("computer_tool_not_implemented")
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        return {"ok": False, "error": type(exc).__name__ + ":" + str(exc)[:220]}, True
