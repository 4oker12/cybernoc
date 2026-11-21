"""Bounded local Windows computer-use and health-inspection tools for Account GPT.

The module exposes safe file navigation, application launch, system/performance
inventory, Microsoft Defender status/scanning, and optional visual UI inspection.
It never exposes arbitrary shell execution, file deletion, process termination,
registry writes, or security-setting changes.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import io
import os
import platform
import re
import shutil
import subprocess
import time
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

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
    r"останов|подтверд|примен|сохран|скан|карантин|очист|разреш|установ|обнов|"
    r"\b(ok|yes|next|continue|finish|accept|agree|да|ок|далее|продолжить|готово)\b)"
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
    _tool("computer_installed_programs",
          "Inventory installed Windows applications from uninstall registry entries. Read-only; never returns uninstall commands.",
          {"limit": {**INTEGER, "description": "Maximum rows, 1 to 100"}}, ["limit"]),
    _tool("computer_power_overview",
          "Inspect active Windows power plan, battery status and available CPU temperature sensors. Read-only."),
    _tool("computer_file_hash",
          "Calculate SHA-256 for one approved local file, up to 1 GiB. Does not execute the file.",
          {"path": STRING}, ["path"]),
    _tool("computer_package_search",
          "Search the configured official Windows Package Manager (winget) community source. Search only; no install.",
          {"query": STRING}, ["query"]),
    _tool("computer_package_details",
          "Show metadata for one exact winget package ID from the configured winget source. Read-only.",
          {"package_id": STRING}, ["package_id"]),
    _tool("computer_package_install",
          "Install one exact winget package ID in user scope only. Requires explicit approval of the exact package ID in the current or immediately preceding user turn. No elevation is requested.",
          {"package_id": STRING}, ["package_id"]),
    _tool("computer_archive_inspect",
          "Inspect ZIP or TAR archive members without extracting. Rejects unsafe paths, links and oversized archives.",
          {"path": STRING}, ["path"]),
    _tool("computer_archive_extract",
          "Safely extract a ZIP or TAR archive into an existing approved destination. Rejects traversal, links, overwrites and oversized archives. Requires explicit approval of the exact source and destination paths.",
          {"path": STRING, "destination": STRING}, ["path", "destination"]),
    _tool("computer_plan_file_organization",
          "Create a dry-run plan for sorting direct files from one approved folder into an existing destination by extension, file type or year-month. No files are moved.",
          {"source": STRING, "destination": STRING,
           "group_by": {"type": "string", "enum": ["extension", "file_type", "year_month"]}},
          ["source", "destination", "group_by"]),
    _tool("computer_apply_file_organization",
          "Move files according to a previously previewed organization plan. Never overwrites. Requires explicit approval of exact source, destination and grouping.",
          {"source": STRING, "destination": STRING,
           "group_by": {"type": "string", "enum": ["extension", "file_type", "year_month"]}},
          ["source", "destination", "group_by"]),
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
    net_before = psutil.net_io_counters(pernic=True)
    disk_before = psutil.disk_io_counters()
    process_objects = []
    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            proc.cpu_percent(None)
            process_objects.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    sample_seconds = 0.6
    cpu = psutil.cpu_percent(interval=sample_seconds)
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
    for proc in process_objects:
        try:
            info = proc.as_dict(attrs=["pid", "name", "memory_info"])
            memory = info.get("memory_info")
            processes.append({
                "pid": info.get("pid"),
                "name": (info.get("name") or "unknown")[:100],
                "rss_bytes": memory.rss if memory else 0,
                "cpu_percent": proc.cpu_percent(None),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    top_memory = sorted(processes, key=lambda x: x["rss_bytes"], reverse=True)[:8]
    top_cpu = sorted(processes, key=lambda x: x["cpu_percent"], reverse=True)[:8]
    network_rates = {}
    for name, value in net_io.items():
        before = net_before.get(name)
        if before is not None:
            network_rates[name] = {
                "sent_bytes_per_second": round(max(0, value.bytes_sent - before.bytes_sent) / sample_seconds, 1),
                "received_bytes_per_second": round(max(0, value.bytes_recv - before.bytes_recv) / sample_seconds, 1),
            }
    disk_rates = None
    if disk_io and disk_before:
        disk_rates = {
            "read_bytes_per_second": round(max(0, disk_io.read_bytes - disk_before.read_bytes) / sample_seconds, 1),
            "write_bytes_per_second": round(max(0, disk_io.write_bytes - disk_before.write_bytes) / sample_seconds, 1),
        }
    return {
        "ok": True,
        "sample_seconds": sample_seconds,
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
            "rates": disk_rates,
        } if disk_io else None),
        "network_io": {
            name: {"bytes_sent": value.bytes_sent, "bytes_recv": value.bytes_recv,
                   "packets_sent": value.packets_sent, "packets_recv": value.packets_recv,
                   "errors_in": value.errin, "errors_out": value.errout,
                   "drops_in": value.dropin, "drops_out": value.dropout}
            for name, value in net_io.items()
        },
        "network_rates": network_rates,
        "top_processes_by_memory": top_memory,
        "top_processes_by_cpu": top_cpu,
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
            if folder.is_dir():
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


def _installed_programs(limit: int) -> dict:
    _windows_only()
    import winreg
    locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    rows, seen = [], set()
    for hive, base in locations:
        try:
            with winreg.OpenKey(hive, base, 0, winreg.KEY_READ) as root:
                count = winreg.QueryInfoKey(root)[0]
                for index in range(min(count, 1200)):
                    try:
                        subkey_name = winreg.EnumKey(root, index)
                        with winreg.OpenKey(root, subkey_name, 0, winreg.KEY_READ) as item:
                            def read_value(key):
                                try:
                                    return winreg.QueryValueEx(item, key)[0]
                                except OSError:
                                    return ""
                            name = str(read_value("DisplayName") or "").strip()
                            if not name or name.casefold() in seen:
                                continue
                            if int(read_value("SystemComponent") or 0) == 1:
                                continue
                            seen.add(name.casefold())
                            rows.append({
                                "name": _redact(name)[:180],
                                "version": str(read_value("DisplayVersion") or "")[:80],
                                "publisher": _redact(str(read_value("Publisher") or ""))[:140],
                                "install_date": str(read_value("InstallDate") or "")[:16],
                                "registry_view": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                            })
                    except OSError:
                        continue
        except OSError:
            continue
    rows.sort(key=lambda x: x["name"].casefold())
    limit = max(1, min(int(limit), 100))
    return {"ok": True, "count": len(rows), "programs": rows[:limit],
            "truncated": len(rows) > limit}


def _power_overview() -> dict:
    _windows_only()
    power = _fixed_command([_system32("powercfg.exe"), "/getactivescheme"])
    battery = None
    if psutil is not None:
        try:
            item = psutil.sensors_battery()
            if item is not None:
                battery = {
                    "percent": item.percent,
                    "plugged": item.power_plugged,
                    "seconds_left": item.secsleft if item.secsleft >= 0 else None,
                }
        except (AttributeError, OSError):
            battery = {"available": False}
    temperatures = []
    if psutil is not None:
        try:
            for sensor, entries in (psutil.sensors_temperatures() or {}).items():
                for entry in entries[:8]:
                    temperatures.append({
                        "sensor": str(sensor)[:80],
                        "label": str(entry.label or "")[:80],
                        "celsius": entry.current,
                        "high_celsius": entry.high,
                        "critical_celsius": entry.critical,
                    })
        except (AttributeError, OSError):
            pass
    return {
        "ok": True, "active_power_plan": power.get("output", "")[:1200],
        "battery": battery, "temperature_sensors": temperatures,
        "temperature_note": "Windows laptops may expose no temperature sensors through psutil; an empty list is not a zero-degree reading.",
    }


def _file_hash(path_raw: str) -> dict:
    path = _resolve_local_path(path_raw)
    if not path.is_file():
        raise ValueError("computer_hash_path_not_file")
    size = path.stat().st_size
    if size > 1024 * 1024 * 1024:
        raise ValueError("computer_hash_file_too_large")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"ok": True, "path": str(path), "size_bytes": size,
            "algorithm": "SHA-256", "sha256": digest.hexdigest()}


def _winget_path() -> str | None:
    found = shutil.which("winget.exe") or shutil.which("winget")
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidate = Path(local) / "Microsoft" / "WindowsApps" / "winget.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def _winget_run(args: list[str], timeout=45) -> dict:
    executable = _winget_path()
    if not executable:
        return {"ok": False, "error": "winget_not_available"}
    result = _fixed_command([executable, *args], timeout=timeout)
    result["manager"] = "Windows Package Manager (winget)"
    result["source"] = "winget"
    result["output"] = result.get("output", "")[:7000]
    return result


def _package_search(query: str) -> dict:
    _windows_only()
    if not isinstance(query, str) or not 2 <= len(query.strip()) <= 100:
        raise ValueError("winget_search_query_invalid")
    return _winget_run([
        "search", "--query", query.strip(), "--source", "winget",
        "--accept-source-agreements", "--disable-interactivity",
    ], timeout=60)


def _valid_package_id(package_id: str) -> str:
    if not isinstance(package_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._+-]{1,119}", package_id.strip()
    ):
        raise ValueError("winget_package_id_invalid")
    return package_id.strip()


def _package_details(package_id: str) -> dict:
    _windows_only()
    package_id = _valid_package_id(package_id)
    result = _winget_run([
        "show", "--id", package_id, "--exact", "--source", "winget",
        "--accept-source-agreements", "--disable-interactivity",
    ], timeout=60)
    result["package_id"] = package_id
    return result


def _latest_user_and_previous_assistant(messages):
    if not isinstance(messages, list):
        return "", ""
    user_index = None
    for index in range(len(messages) - 1, -1, -1):
        row = messages[index]
        if isinstance(row, dict) and row.get("role") == "user":
            user_index = index
            break
    if user_index is None:
        return "", ""
    latest = str(messages[user_index].get("content") or "")
    previous = ""
    for index in range(user_index - 1, -1, -1):
        row = messages[index]
        if isinstance(row, dict) and row.get("role") == "assistant":
            previous = str(row.get("content") or "")
            break
    return latest, previous


def _explicit_action_approved(messages, action_pattern: str, identifiers: list[str]) -> bool:
    latest, previous = _latest_user_and_previous_assistant(messages)
    simple_yes = bool(re.fullmatch(
        r"\s*(да|yes|подтверждаю|разрешаю|выполняй)[!. ]*\s*",
        latest, flags=re.I,
    ))
    context = latest + (" " + previous if simple_yes else "")
    if not re.search(action_pattern, context, flags=re.I):
        return False
    if not re.search(
        r"(?i)(разрешаю|подтверждаю|выполняй|запускай|установи|распакуй|"
        r"перемести|организуй|install|extract|move|organize|yes|да)",
        latest,
    ):
        return False
    normalized = context.casefold().replace("/", "\\")
    return all(
        isinstance(value, str) and value.strip()
        and value.casefold().replace("/", "\\") in normalized
        for value in identifiers
    )


def _package_install(package_id: str, user_messages) -> dict:
    _windows_only()
    package_id = _valid_package_id(package_id)
    if not _explicit_action_approved(
        user_messages, r"(установ|install)", [package_id]
    ):
        return {
            "ok": False, "approval_required": True,
            "package_id": package_id,
            "required_user_confirmation": f"Напишите: «Разрешаю установить пакет {package_id} из источника winget в область текущего пользователя».",
        }
    # Resolve the exact package from the selected source immediately before install.
    details = _package_details(package_id)
    if not details.get("ok"):
        return {"ok": False, "error": "winget_package_preflight_failed",
                "package_id": package_id, "details": details.get("output", "")[:2500]}
    result = _winget_run([
        "install", "--id", package_id, "--exact", "--source", "winget",
        "--scope", "user", "--silent", "--accept-package-agreements",
        "--accept-source-agreements", "--disable-interactivity",
    ], timeout=600)
    result["package_id"] = package_id
    result["elevation_requested"] = False
    result["preflight_verified"] = True
    return result


def _archive_member_path(destination: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("archive_member_name_invalid")
    normalized = name.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(name)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or any(
        part in {"..", ""} for part in posix.parts
    ):
        raise ValueError("archive_path_traversal_blocked")
    if any(_sensitive_component(part) for part in posix.parts):
        raise ValueError("archive_sensitive_member_blocked")
    target = destination.joinpath(*posix.parts)
    resolved = Path(os.path.abspath(target))
    if not resolved.is_relative_to(destination.resolve()):
        raise ValueError("archive_path_traversal_blocked")
    return resolved


def _archive_inspect(path_raw: str) -> dict:
    path = _resolve_local_path(path_raw)
    if not path.is_file() or path.suffix.casefold() not in {
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    }:
        raise ValueError("archive_format_not_supported")
    rows, total = [], 0
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            items = archive.infolist()
            if len(items) > 500:
                raise ValueError("archive_entry_limit_exceeded")
            for item in items:
                target = _archive_member_path(Path("C:\\CybernovaArchivePreview"), item.filename)
                mode = item.external_attr >> 16
                if __import__("stat").S_ISLNK(mode):
                    raise ValueError("archive_links_not_supported")
                total += item.file_size
                rows.append({"name": item.filename[:240], "size_bytes": item.file_size,
                             "directory": item.is_dir()})
    else:
        with tarfile.open(path, "r:*") as archive:
            items = archive.getmembers()
            if len(items) > 500:
                raise ValueError("archive_entry_limit_exceeded")
            for item in items:
                _archive_member_path(Path("C:\\CybernovaArchivePreview"), item.name)
                if not (item.isfile() or item.isdir()):
                    raise ValueError("archive_links_or_special_files_not_supported")
                total += item.size
                rows.append({"name": item.name[:240], "size_bytes": item.size,
                             "directory": item.isdir()})
    if total > 1024 * 1024 * 1024:
        raise ValueError("archive_uncompressed_size_limit_exceeded")
    return {"ok": True, "archive": str(path), "entries": rows[:100],
            "entry_count": len(rows), "uncompressed_bytes": total,
            "truncated": len(rows) > 100}


def _archive_extract(path_raw: str, destination_raw: str, user_messages) -> dict:
    path = _resolve_local_path(path_raw)
    destination = _resolve_local_path(destination_raw)
    if not path.is_file() or not destination.is_dir():
        raise ValueError("archive_source_or_destination_invalid")
    if not _explicit_action_approved(
        user_messages, r"(распак|извлеч|extract|unpack)",
        [str(path), str(destination)],
    ):
        return {
            "ok": False, "approval_required": True,
            "source": str(path), "destination": str(destination),
            "required_user_confirmation": f"Напишите: «Разрешаю распаковать {path} в {destination}».",
        }
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            items = archive.infolist()
            total = sum(item.file_size for item in items)
            if len(items) > 500 or total > 1024 * 1024 * 1024:
                raise ValueError("archive_size_limit_exceeded")
            plan = []
            for item in items:
                target = _archive_member_path(destination, item.filename)
                mode = item.external_attr >> 16
                if __import__("stat").S_ISLNK(mode):
                    raise ValueError("archive_links_not_supported")
                if item.file_size > 256 * 1024 * 1024:
                    raise ValueError("archive_member_size_limit_exceeded")
                if item.file_size and item.compress_size and item.file_size / item.compress_size > 1000:
                    raise ValueError("archive_compression_ratio_limit_exceeded")
                if target.exists():
                    raise ValueError("archive_extraction_would_overwrite")
                plan.append((item, target))
            extracted = []
            for item, target in plan:
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise ValueError("archive_extraction_would_overwrite")
                with archive.open(item, "r") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                extracted.append(str(target))
    else:
        with tarfile.open(path, "r:*") as archive:
            items = archive.getmembers()
            total = sum(item.size for item in items)
            if len(items) > 500 or total > 1024 * 1024 * 1024:
                raise ValueError("archive_size_limit_exceeded")
            plan = []
            for item in items:
                target = _archive_member_path(destination, item.name)
                if not (item.isfile() or item.isdir()):
                    raise ValueError("archive_links_or_special_files_not_supported")
                if item.size > 256 * 1024 * 1024:
                    raise ValueError("archive_member_size_limit_exceeded")
                if target.exists():
                    raise ValueError("archive_extraction_would_overwrite")
                plan.append((item, target))
            extracted = []
            for item, target in plan:
                if item.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise ValueError("archive_extraction_would_overwrite")
                source = archive.extractfile(item)
                if source is None:
                    raise ValueError("archive_member_read_failed")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                extracted.append(str(target))
    return {"ok": True, "archive": str(path), "destination": str(destination),
            "files_extracted": len(extracted), "paths": extracted[:100],
            "truncated": len(extracted) > 100}


def _organization_category(path: Path, group_by: str) -> str:
    suffix = path.suffix.casefold().lstrip(".") or "no_extension"
    if group_by == "extension":
        return suffix[:32]
    if group_by == "year_month":
        stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).astimezone()
        return stamp.strftime("%Y-%m")
    groups = {
        "images": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".heic"},
        "documents": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".odt"},
        "archives": {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"},
        "audio": {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"},
        "video": {".mp4", ".mkv", ".avi", ".mov", ".webm"},
        "code": {".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".yml", ".yaml", ".ps1", ".bat", ".cmd"},
        "installers": {".exe", ".msi", ".msix", ".appx"},
    }
    for category, suffixes in groups.items():
        if path.suffix.casefold() in suffixes:
            return category
    return "other"


def _organization_plan(source_raw: str, destination_raw: str, group_by: str) -> dict:
    source = _resolve_local_path(source_raw)
    destination = _resolve_local_path(destination_raw)
    if not source.is_dir() or not destination.is_dir():
        raise ValueError("organization_source_or_destination_invalid")
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("organization_overlapping_directories")
    if group_by not in {"extension", "file_type", "year_month"}:
        raise ValueError("organization_grouping_invalid")
    moves = []
    for item in sorted(source.iterdir(), key=lambda x: x.name.casefold()):
        if item.is_symlink() or not item.is_file() or _sensitive_component(item.name):
            continue
        category = _organization_category(item, group_by)
        target_dir = destination / category
        target = target_dir / item.name
        if target.exists():
            moves.append({"source": str(item), "destination": str(target),
                          "category": category, "status": "skipped_collision"})
        else:
            moves.append({"source": str(item), "destination": str(target),
                          "category": category, "status": "planned"})
        if len(moves) >= 100:
            break
    return {"ok": True, "source": str(source), "destination": str(destination),
            "group_by": group_by, "planned_count": sum(x["status"] == "planned" for x in moves),
            "moves": moves, "truncated": len(moves) >= 100}


def _apply_organization(source_raw: str, destination_raw: str, group_by: str,
                        user_messages) -> dict:
    plan = _organization_plan(source_raw, destination_raw, group_by)
    source, destination = plan["source"], plan["destination"]
    if not _explicit_action_approved(
        user_messages, r"(сортир|организ|перемест|move|organize)",
        [source, destination, group_by],
    ):
        return {
            "ok": False, "approval_required": True,
            "source": source, "destination": destination, "group_by": group_by,
            "preview": plan["moves"][:30],
            "required_user_confirmation": (
                f"Напишите: «Разрешаю переместить файлы из {source} в {destination} "
                f"с группировкой {group_by}»."
            ),
        }
    completed, failed, skipped = [], [], []
    for item in plan["moves"]:
        if item["status"] != "planned":
            skipped.append(item)
            continue
        src, dst = Path(item["source"]), Path(item["destination"])
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() or src.is_symlink():
                skipped.append({**item, "status": "skipped_changed_since_preview"})
                continue
            shutil.move(str(src), str(dst))
            completed.append(str(dst))
        except OSError as exc:
            failed.append({"source": str(src), "error": type(exc).__name__})
    return {"ok": not failed, "moved": len(completed), "skipped": len(skipped),
            "failed": failed[:20], "destination": destination,
            "moved_paths": completed[:100], "truncated": len(completed) > 100}


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
                    "computer_ui_windows", "computer_power_overview"} and args:
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
        if name == "computer_installed_programs":
            return _installed_programs(args.get("limit", 80)), False
        if name == "computer_power_overview":
            return _power_overview(), False
        if name == "computer_file_hash":
            if set(args) != {"path"}:
                raise ValueError("computer_file_hash_arguments_invalid")
            return _file_hash(args["path"]), False
        if name == "computer_package_search":
            if set(args) != {"query"}:
                raise ValueError("computer_package_search_arguments_invalid")
            return _package_search(args["query"]), False
        if name == "computer_package_details":
            if set(args) != {"package_id"}:
                raise ValueError("computer_package_details_arguments_invalid")
            return _package_details(args["package_id"]), False
        if name == "computer_package_install":
            if set(args) != {"package_id"}:
                raise ValueError("computer_package_install_arguments_invalid")
            result = _package_install(args["package_id"], user_messages or [])
            return result, not bool(result.get("ok"))
        if name == "computer_archive_inspect":
            if set(args) != {"path"}:
                raise ValueError("computer_archive_inspect_arguments_invalid")
            return _archive_inspect(args["path"]), False
        if name == "computer_archive_extract":
            if set(args) != {"path", "destination"}:
                raise ValueError("computer_archive_extract_arguments_invalid")
            result = _archive_extract(args["path"], args["destination"], user_messages or [])
            return result, not bool(result.get("ok"))
        if name == "computer_plan_file_organization":
            if set(args) != {"source", "destination", "group_by"}:
                raise ValueError("computer_plan_file_organization_arguments_invalid")
            return _organization_plan(args["source"], args["destination"], args["group_by"]), False
        if name == "computer_apply_file_organization":
            if set(args) != {"source", "destination", "group_by"}:
                raise ValueError("computer_apply_file_organization_arguments_invalid")
            result = _apply_organization(
                args["source"], args["destination"], args["group_by"], user_messages or []
            )
            return result, not bool(result.get("ok"))
        raise ValueError("computer_tool_not_implemented")
    except (OSError, ValueError, TypeError, RuntimeError, zipfile.BadZipFile, tarfile.TarError) as exc:
        return {"ok": False, "error": type(exc).__name__ + ":" + str(exc)[:220]}, True
