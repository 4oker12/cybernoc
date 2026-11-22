"""Read-only process and local listener inventory; no remote connections are made."""
from __future__ import annotations

import socket
import time
from collections import Counter
from datetime import datetime, timezone


def parent_links(rows):
    """An edge is valid only if the reported parent predates the child.

    Strict ordering also rules out cycles. Missing/reused PIDs are not guessed.
    """
    by_pid = {row["pid"]: row for row in rows}
    edges = {}
    for row in rows:
        parent = by_pid.get(row["parent_pid"])
        if (parent and parent["started"] is not None and row["started"] is not None
                and parent["started"] < row["started"]):
            edges[row["pid"]] = parent["pid"]
    return edges


def process_inventory(api, *, after_pid, limit, listeners, clean, sensitive):
    if (type(after_pid) is not int or not -1 <= after_pid <= 0xFFFFFFFF
            or type(limit) is not int or not 1 <= limit <= 50
            or type(listeners) is not bool):
        raise ValueError("process_inventory_arguments_invalid")
    unavailable = (api.NoSuchProcess, api.AccessDenied, api.ZombieProcess)

    def try_read(method):
        try:
            return method()
        except unavailable:
            return None

    rows = []
    objects = {}
    # Avoid psutil's process_iter object cache across calls/PID reuse.
    for pid in sorted(api.pids()):
        proc = try_read(lambda: api.Process(pid))
        if proc is None:
            continue
        started = try_read(proc.create_time)
        parent_pid = try_read(proc.ppid)
        if not proc.is_running():
            continue
        rows.append({"pid": pid, "parent_pid": parent_pid, "started": started})
        objects[pid] = proc
    edges = parent_links(rows)
    child_counts = Counter(edges.values())
    candidates = [row for row in rows if row["pid"] > after_pid]
    page = candidates[:limit]

    def cpu_sample(proc):
        cpu = try_read(proc.cpu_times)
        return (time.monotonic(), cpu.user + cpu.system) if cpu is not None else None

    first = {row["pid"]: cpu_sample(objects[row["pid"]]) for row in page}
    if first:
        time.sleep(0.1)
    counts = Counter()
    output = []
    for row in page:
        pid = row["pid"]
        proc = objects[pid]
        started = row["started"]
        second = cpu_sample(proc)
        initial = first[pid]
        exe = try_read(proc.exe)
        if exe:
            exe = None if any(sensitive(part) for part in exe.replace("/", "\\").split("\\")) else clean(exe)[:400]
        mem = try_read(proc.memory_info)
        name = try_read(proc.name)
        if not proc.is_running():
            continue
        cpu = None
        if initial and second and second[0] > initial[0] and second[1] >= initial[1]:
            cpu = round(100 * (second[1] - initial[1]) / (second[0] - initial[0]), 1)
        output.append({
            "pid": pid, "parent_pid": row["parent_pid"], "tree_parent_pid": edges.get(pid),
            "tree_child_count": child_counts[pid], "name": clean(name)[:120] if name else None,
            "executable_path": exe,
            "started_at_utc": datetime.fromtimestamp(started, timezone.utc).isoformat() if started is not None else None,
            "cpu_percent_one_core": cpu, "memory_bytes": mem.rss if mem else None,
        })
    sockets = []
    endpoint_status = "not_requested"
    truncated = False
    if listeners:
        try:
            connections = api.net_connections(kind="inet")
        except (api.AccessDenied, OSError, NotImplementedError):
            endpoint_status = "unavailable"
        else:
            endpoint_status = "best_effort"
            current = {row["pid"]: row for row in output
                       if row["started_at_utc"] is not None and objects[row["pid"]].is_running()}
            # Unowned endpoints cannot be attributed to a page. Report the count separately.
            for conn in connections:
                if not conn.laddr or conn.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                if conn.type == socket.SOCK_STREAM and conn.status == api.CONN_LISTEN:
                    protocol = "tcp"
                elif conn.type == socket.SOCK_DGRAM and not conn.raddr:
                    protocol = "udp"
                else:
                    continue
                if conn.pid is None:
                    counts["unowned"] += 1
                if conn.pid not in current:
                    continue
                ip, port = conn.laddr
                sockets.append((conn.pid, protocol, 4 if conn.family == socket.AF_INET else 6, ip, port))
            sockets = sorted(set(sockets))
            truncated = len(sockets) > 100
            sockets = [{"pid": pid, "protocol": protocol, "ip_version": version, "local_address": ip,
                        "port": port, "process_name": current[pid]["name"],
                        "executable_path": current[pid]["executable_path"]}
                       for pid, protocol, version, ip, port in sockets[:100]]
    return {"ok": True, "processes": output, "processes_observed": len(rows),
            "next_after_pid": page[-1]["pid"] if len(candidates) > limit else None,
            "command_line_status": "not_collected",
            "listeners": sockets, "listener_scope": "current_process_page", "listener_status": endpoint_status,
            "listener_list_truncated": truncated, "unowned_listener_count": counts["unowned"],
            "unowned_listener_scope": "system_wide"}
