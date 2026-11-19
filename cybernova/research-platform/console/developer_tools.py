"""Task-bound Cybernova coding-agent tools.

All work happens in a dedicated Git worktree per durable task; never edit the
running console checkout. Model-controlled test commands are executed without
root privileges. Publishing/updating remote refs requires the agent's existing
one-shot human approval workflow. The owner configures Git write credentials.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import threading

SOURCE = Path(os.environ.get(
    "CYBERNOVA_DEV_SOURCE", "/workspace/cybernova-chat-communication"
)).resolve()
WORKSPACES = Path(os.environ.get(
    "CYBERNOVA_DEV_WORKSPACES", "/workspace/cybernova-dev-workspaces"
)).resolve()
MAX_EDIT_BYTES = 150_000
MAX_RESULT = 14500
LOCK = threading.RLock()
BLOCKED = frozenset({".git", ".ssh", "node_modules", ".venv", "__pycache__", ".cache"})
SENSITIVE = re.compile(r"(?i)(?:^\.env(?:\.|$)|\.pem$|\.key$|credentials|secrets?|password|id_ed25519|id_rsa)")

def _tool(name, description, properties=None, required=None):
    return {"name": name, "description": description, "inputSchema": {
        "type": "object", "properties": properties or {},
        "required": required or [], "additionalProperties": False}}

FILE = {"path": {"type": "string", "description": "Relative file path inside Qwen's private project worktree"}}
DEV_TOOLS = [
    _tool("dev_workspace", "Create or reopen my separate Git worktree and branch for this Cybernova task."),
    _tool("dev_list", "List tracked project paths and directories (bounded).",
          {"prefix": {"type": "string"}, "limit": {"type": "integer"}}),
    _tool("dev_read", "Read a source file from my task worktree, with line numbers.",
          {**FILE, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["path"]),
    _tool("dev_search", "Search source files for an exact substring (case-insensitive) with line numbers.",
          {"query": {"type": "string"}, "limit": {"type": "integer"}}, ["query"]),
    _tool("dev_edit", "Create a source file or replace exactly one occurrence of text in a source file in my task worktree. Returns diff.",
          {**FILE, "content": {"type": "string"},
           "old": {"type": "string", "description": "If provided, replace exactly one occurrence with content; otherwise create new file"}},
          ["path", "content"]),
    _tool("dev_diff", "Read Git status and source diffs of my task worktree."),
    _tool("dev_test", "Execute project's Python unit tests as unprivileged user. No elevated shell.",
          {"pattern": {"type": "string", "description": "unittest test filename pattern, default test_*.py"}}),
    _tool("dev_commit", "Commit the current task worktree changes onto my own Qwen branch.",
          {"message": {"type": "string"}}, ["message"]),
    _tool("dev_command", "Run custom argv command in the task worktree, without shell, as unprivileged user. Requires explicit owner approval.",
          {"argv": {"type": "array", "items": {"type": "string"}},
           "timeout": {"type": "integer"}}, ["argv"]),
    _tool("dev_push", "Push only my Qwen task branch to origin using configured write credentials. Requires owner approval.",
          {}),
    _tool("dev_open_pr", "Open GitHub PR from my pushed branch into selected base using gh CLI and configured credentials. Requires owner approval.",
          {"title": {"type": "string"}, "body": {"type": "string"},
           "base": {"type": "string"}}, ["title", "body"]),
]
DEV_NAMES = frozenset(t["name"] for t in DEV_TOOLS)
DEV_AUTOMATIC = frozenset({
    "dev_workspace", "dev_list", "dev_read", "dev_search",
    "dev_edit", "dev_diff", "dev_test", "dev_commit"
})


class DeveloperError(ValueError):
    pass


def _run(argv, *, cwd=SOURCE, timeout=25, env=None, uid=None):
    if not isinstance(argv, (list, tuple)) or not argv or any(
        not isinstance(x, str) or len(x) > 1500 for x in argv
    ):
        raise DeveloperError("invalid_argv")
    clean_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    clean_env.update(env or {})
    def child():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (min(timeout + 5, 180), min(timeout + 5, 180)))
        if uid is not None and os.geteuid() == 0:
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
    try:
        p = subprocess.run(list(argv), cwd=str(cwd), env=clean_env,
                           capture_output=True, text=True, errors="replace",
                           timeout=timeout, preexec_fn=child)
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "error": "command_timeout", "timeout": timeout}
    except OSError as exc:
        return {"ok": False, "error": type(exc).__name__}
    # Never forward unlimited compiler logs, native stack traces or secrets.
    return {"ok": p.returncode == 0, "exit_code": p.returncode,
            "stdout": p.stdout[-MAX_RESULT:], "stderr": p.stderr[-3000:]}


def _task_branch(task_id):
    if not isinstance(task_id, str) or len(task_id) > 140:
        raise DeveloperError("invalid_task_id")
    ident = hashlib.sha256(task_id.encode()).hexdigest()[:16]
    return f"cybernova/qwen/{ident}", WORKSPACES / ident


def _workspace(task_id):
    branch, dest = _task_branch(task_id)
    with LOCK:
        if not (SOURCE / ".git").exists():
            raise DeveloperError("development_repo_not_found")
        WORKSPACES.mkdir(parents=True, exist_ok=True)
        # Do not attach an existing path that wasn't created as a Git worktree.
        if dest.exists():
            proof = _run(["git", "rev-parse", "--show-toplevel"], cwd=dest)
            if not proof["ok"] or Path(proof["stdout"].strip()).resolve() != dest:
                raise DeveloperError("workspace_integrity_failed")
        else:
            exists = _run(["git", "show-ref", "--verify", "refs/heads/" + branch], cwd=SOURCE)
            cmd = ["git", "-c", "core.hooksPath=/dev/null", "worktree", "add"]
            cmd += ([str(dest), branch] if exists["ok"]
                    else ["-b", branch, str(dest), "HEAD"])
            created = _run(cmd, cwd=SOURCE, timeout=35)
            if not created["ok"]:
                raise DeveloperError("cannot_create_worktree: " + created["stderr"][-350:])
    return branch, dest


def _safe_path(root, relative, *, must_exist=False):
    if not isinstance(relative, str) or not relative or len(relative) > 300:
        raise DeveloperError("invalid_relative_file")
    p = Path(relative)
    if p.is_absolute() or ".." in p.parts or any(x in BLOCKED or SENSITIVE.search(x) for x in p.parts):
        raise DeveloperError("protected_or_outside_file")
    resolved = (root / p).resolve()
    if not resolved.is_relative_to(root) or (must_exist and not resolved.is_file()):
        raise DeveloperError("outside_or_missing_file")
    if any(node.is_symlink() for node in [root / Path(*p.parts[:i]) for i in range(1, len(p.parts) + 1)]):
        raise DeveloperError("symlink_denied")
    return resolved


def _list(root, prefix="", limit=160):
    if prefix:
        _safe_path(root, prefix)
    limit = max(1, min(int(limit), 400))
    files = []
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in sorted(dirs) if d not in BLOCKED and not SENSITIVE.search(d)
                   and not (Path(base) / d).is_symlink()]
        for name in sorted(names):
            p = Path(base) / name
            if p.is_symlink() or SENSITIVE.search(name):
                continue
            rel = p.relative_to(root).as_posix()
            if prefix and not rel.startswith(prefix):
                continue
            files.append(rel)
            if len(files) >= limit:
                return files
    return files


def _diff(root):
    status = _run(["git", "status", "--short"], cwd=root)
    diff = _run(["git", "diff", "--no-ext-diff", "--stat"], cwd=root)
    patch = _run(["git", "diff", "--no-ext-diff", "--", "."], cwd=root)
    return {"status": status["stdout"], "stat": diff["stdout"], "patch": patch["stdout"]}


def _unprivileged(argv, root, timeout):
    tmp = tempfile.mkdtemp(prefix="cybernova-dev-test-")
    try:
        uid = 65534 if os.geteuid() == 0 else None
        if uid is not None:
            os.chown(tmp, uid, uid)
        return _run(argv, cwd=root, timeout=timeout,
                    env={"HOME": tmp, "TMPDIR": tmp, "PYTHONPYCACHEPREFIX": tmp + "/pycache",
                         "PYTHONDONTWRITEBYTECODE": "1"},
                    uid=uid)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def dev_call(name, args, task_id):
    if name not in DEV_NAMES:
        raise DeveloperError("unknown_developer_tool")
    if not isinstance(args, dict):
        raise DeveloperError("invalid_arguments")
    branch, root = _workspace(task_id)
    if name == "dev_workspace":
        return {"ok": True, "branch": branch, "workspace": str(root),
                "source": str(SOURCE), "status": _diff(root)["status"]}
    if name == "dev_list":
        return {"ok": True, "files": _list(root, args.get("prefix", ""),
                                           args.get("limit", 160))}
    if name == "dev_read":
        target = _safe_path(root, args.get("path"), must_exist=True)
        if target.stat().st_size > 350_000:
            raise DeveloperError("file_too_large")
        lines = target.read_text(encoding="utf-8").splitlines()
        start = max(1, int(args.get("start_line") or 1))
        end = min(len(lines), start + 239, int(args.get("end_line") or start + 239))
        return {"ok": True, "path": str(target.relative_to(root)),
                "total_lines": len(lines),
                "content": "\n".join(f"{i}: {lines[i-1]}" for i in range(start, end+1))[:MAX_RESULT]}
    if name == "dev_search":
        q = args.get("query")
        if not isinstance(q, str) or not (2 <= len(q) <= 180):
            raise DeveloperError("invalid_search_query")
        hits = []
        for rel in _list(root, limit=4000):
            target = _safe_path(root, rel)
            if target.stat().st_size > 300_000:
                continue
            try:
                lines = target.read_text(encoding="utf-8").splitlines()
            except (UnicodeError, OSError):
                continue
            for idx, line in enumerate(lines, 1):
                if q.casefold() in line.casefold():
                    hits.append({"file": rel, "line": idx, "text": line[:230]})
                    if len(hits) >= min(100, max(1, int(args.get("limit") or 40))):
                        return {"ok": True, "hits": hits}
        return {"ok": True, "hits": hits}
    if name == "dev_edit":
        path = args.get("path")
        target = _safe_path(root, path)
        content = args.get("content")
        if not isinstance(content, str) or len(content.encode()) > MAX_EDIT_BYTES:
            raise DeveloperError("invalid_new_content")
        old = args.get("old")
        if old is None:
            if target.exists():
                raise DeveloperError("file_exists_use_old_to_replace")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        else:
            if not isinstance(old, str) or not old:
                raise DeveloperError("invalid_old_text")
            if not target.is_file() or target.stat().st_size > MAX_EDIT_BYTES:
                raise DeveloperError("old_file_not_found_or_too_large")
            before = target.read_text(encoding="utf-8")
            if before.count(old) != 1:
                raise DeveloperError("old_text_must_match_exactly_once")
            target.write_text(before.replace(old, content, 1), encoding="utf-8")
        return {"ok": True, "path": path, **_diff(root)}
    if name == "dev_diff":
        return {"ok": True, "branch": branch, **_diff(root)}
    if name == "dev_test":
        pat = args.get("pattern") or "test_*.py"
        if not isinstance(pat, str) or not re.fullmatch(r"test_[A-Za-z0-9_*?-]{0,60}\.py", pat):
            raise DeveloperError("invalid_test_pattern")
        project = root / "cybernova" / "research-platform"
        if not project.is_dir():
            raise DeveloperError("research_platform_not_in_repo")
        run = _unprivileged([sys.executable, "-m", "unittest", "discover",
                             "-s", "tests", "-p", pat, "-q"], project, 130)
        return {"branch": branch, "runner": "unittest_non_root", **run}
    if name == "dev_command":
        argv = args.get("argv")
        timeout = args.get("timeout") or 35
        if not isinstance(timeout, int) or not (1 <= timeout <= 100):
            raise DeveloperError("invalid_timeout")
        if not isinstance(argv, list) or not 1 <= len(argv) <= 24:
            raise DeveloperError("invalid_command")
        return {"branch": branch, "runner": "unprivileged_argv_no_shell",
                **_unprivileged(argv, root, timeout)}
    if name == "dev_commit":
        message = args.get("message")
        if not isinstance(message, str) or not 5 <= len(message) <= 180:
            raise DeveloperError("invalid_commit_message")
        with LOCK:
            stage = _run(["git", "add", "-A"], cwd=root)
            if not stage["ok"]:
                raise DeveloperError("git_stage_failed")
            result = _run(["git", "-c", "user.name=Cybernova Qwen",
                           "-c", "user.email=qwen@cybernova.local",
                           "-c", "core.hooksPath=/dev/null",
                           "commit", "-m", message], cwd=root)
        sha = _run(["git", "rev-parse", "HEAD"], cwd=root)["stdout"].strip()
        return {"branch": branch, "commit": sha, **result}
    if name == "dev_push":
        key = os.environ.get("CYBERNOVA_DEV_WRITE_KEY", "")
        if not key or not Path(key).is_file():
            raise DeveloperError("git_write_key_not_configured")
        ssh = "ssh -i " + key + " -o BatchMode=yes -o IdentitiesOnly=yes"
        return {"branch": branch, **_run(["git", "push", "-u", "origin", branch],
                         cwd=root, timeout=90, env={"GIT_SSH_COMMAND": ssh})}
    if name == "dev_open_pr":
        if not shutil.which("gh"):
            raise DeveloperError("github_cli_not_installed")
        title, body = args.get("title"), args.get("body")
        base = args.get("base") or "main"
        if not isinstance(title, str) or not 5 <= len(title) <= 160 or not isinstance(body, str) or len(body) > 12000:
            raise DeveloperError("invalid_pr_description")
        if not isinstance(base, str) or not re.fullmatch(r"[A-Za-z0-9/_-]{1,100}", base):
            raise DeveloperError("invalid_base_ref")
        token = os.environ.get("CYBERNOVA_DEV_GITHUB_TOKEN")
        if not token:
            raise DeveloperError("github_write_token_not_configured")
        return {"branch": branch, **_run(["gh", "pr", "create", "--head", branch,
                 "--base", base, "--title", title, "--body", body], cwd=root,
                 timeout=40, env={"GH_TOKEN": token})}
    raise DeveloperError("unknown_developer_tool")
