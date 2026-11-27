"""Read-only GitHub tools shared by DeepSeek and Account GPT.

Authentication is taken from GH_TOKEN/GITHUB_TOKEN or the GitHub CLI session.
Tokens are used only in memory and are never returned to the model or logs.
All exposed operations are GET-only; mutations remain in the approved developer
workflow and are deliberately not part of this tool group.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
from urllib import error, parse, request

API_BASE = "https://api.github.com"
MAX_API_BYTES = 1_000_000
MAX_FILE_BYTES = 512_000
MAX_FILE_CHARS = 30_000

_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SECRET_PATH = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.[^/]*)?|credentials?(?:\.[^/]*)?|"
    r"secrets?(?:\.[^/]*)?|id_(?:rsa|ed25519)|[^/]*\.(?:pem|key|p12|pfx|kdbx|sqlite3?|db))$"
)
_SECRET_TOKEN = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"Bearer\s+[A-Za-z0-9._~+/-]{8,})\b"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^(\s*[\w.-]*(?:token|secret|password|passwd|api[_-]?key|"
    r"private[_-]?key|authorization|cookie)[\w.-]*\s*[:=]\s*)[^\r\n#]+"
)
_SECRET_JSON = re.compile(
    r"""(?i)(["'][\w.-]*(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|authorization|cookie)[\w.-]*["']\s*:\s*["'])([^"']*)(["'])"""
)


class GitHubToolError(ValueError):
    pass


def _tool(name: str, description: str, properties=None) -> dict:
    properties = properties or {}
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        },
    }


_PAGE = {"type": "integer", "minimum": 1, "maximum": 100}
_REPO_ARG = {"type": "string", "minLength": 3, "maxLength": 205}
_BRANCH_ARG = {"type": "string", "maxLength": 200,
               "description": "Branch or ref; empty string uses the repository default."}
_STATE_ARG = {"type": "string", "enum": ["open", "closed", "all"]}

GITHUB_TOOLS = [
    _tool("github_status",
          "Check GitHub API identity, permissions for the configured source repository, and local Git branch/HEAD. API permissions and Git transport are separate; no write probe or credentials returned."),
    _tool("github_search_repositories",
          "Search GitHub repositories by name, topic or query. Read-only; returns a bounded metadata list.",
          {"query": {"type": "string", "minLength": 2, "maxLength": 180},
           "per_page": {"type": "integer", "minimum": 1, "maximum": 30}}),
    _tool("github_repo_info",
          "Read repository metadata, visibility, default branch, archive state and update time.",
          {"repo": _REPO_ARG}),
    _tool("github_list_branches",
          "List repository branches and their latest commit SHAs.",
          {"repo": _REPO_ARG, "per_page": _PAGE}),
    _tool("github_list_commits",
          "List recent commits for a branch or the repository default branch. Returns commit subjects and metadata, not patches.",
          {"repo": _REPO_ARG, "branch": _BRANCH_ARG, "per_page": _PAGE}),
    _tool("github_list_issues",
          "List GitHub Issues, excluding Pull Requests. State is open, closed or all.",
          {"repo": _REPO_ARG, "state": _STATE_ARG, "per_page": _PAGE}),
    _tool("github_list_pull_requests",
          "List Pull Requests and their source/target branches. Read-only; does not merge or update them.",
          {"repo": _REPO_ARG, "state": _STATE_ARG, "per_page": _PAGE}),
    _tool("github_list_workflows",
          "List GitHub Actions workflow definitions and their enabled state. Does not dispatch or modify workflows.",
          {"repo": _REPO_ARG, "per_page": _PAGE}),
    _tool("github_list_workflow_runs",
          "List GitHub Actions run metadata, optionally filtered by branch. Does not rerun jobs or download logs.",
          {"repo": _REPO_ARG, "branch": _BRANCH_ARG, "per_page": _PAGE}),
    _tool("github_compare_refs",
          "Compare two branches, tags or commits and return ahead/behind counts plus changed-file statistics. Does not return patches.",
          {"repo": _REPO_ARG,
           "base": {"type": "string", "minLength": 1, "maxLength": 200},
           "head": {"type": "string", "minLength": 1, "maxLength": 200}}),
    _tool("github_read_file",
          "Read a text file from a repository ref. Secret-named files and common credential values are blocked or redacted; binary and oversized files are rejected.",
          {"repo": _REPO_ARG,
           "path": {"type": "string", "minLength": 1, "maxLength": 300},
           "ref": _BRANCH_ARG,
           "max_chars": {"type": "integer", "minimum": 1000, "maximum": MAX_FILE_CHARS}}),
]
GITHUB_NAMES = frozenset(item["name"] for item in GITHUB_TOOLS)
_ARGUMENTS = {item["name"]: set(item["inputSchema"]["required"]) for item in GITHUB_TOOLS}


def _gh_executable() -> str | None:
    """Resolve an installed CLI even when the Windows process has an old PATH."""
    executable = shutil.which("gh") or shutil.which("gh.exe")
    if executable or platform.system() != "Windows":
        return executable
    local = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    candidates = [
        local / "Microsoft" / "WinGet" / "Links" / "gh.exe",
        local / "Programs" / "GitHub CLI" / "gh.exe",
    ]
    for key in ("ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(key):
            candidates.append(Path(os.environ[key]) / "GitHub CLI" / "gh.exe")
    packages = local / "Microsoft" / "WinGet" / "Packages"
    try:
        candidates.extend(
            folder / "bin" / "gh.exe"
            for folder in sorted(packages.glob("GitHub.cli_Microsoft.Winget.Source_*"))
        )
    except OSError:
        pass
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _auth_token() -> tuple[str, str]:
    for key in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value, "environment"
    executable = _gh_executable()
    if executable:
        try:
            result = subprocess.run(
                [executable, "auth", "token", "--hostname", "github.com"],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=5, check=False,
            )
            token = (result.stdout or "").strip()
            if result.returncode == 0 and token:
                return token, "gh_cli"
        except (OSError, subprocess.TimeoutExpired):
            pass
    return "", "anonymous"


def _api_get(path: str, token: str = ""):
    if not isinstance(path, str) or not path or path.startswith("/") or "://" in path:
        raise GitHubToolError("github_api_path_invalid")
    url = API_BASE + "/" + path
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Cybernova-ReadOnly-GitHub-Tools",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    req = request.Request(url, headers=headers, method="GET")
    try:
        with request.urlopen(req, timeout=18) as response:
            final = parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "api.github.com":
                raise GitHubToolError("github_redirect_rejected")
            raw = response.read(MAX_API_BYTES + 1)
    except error.HTTPError as exc:
        raise GitHubToolError("github_http_" + str(exc.code)) from None
    except error.URLError:
        raise GitHubToolError("github_network_error") from None
    except (TimeoutError, OSError):
        raise GitHubToolError("github_transport_error") from None
    if len(raw) > MAX_API_BYTES:
        raise GitHubToolError("github_response_too_large")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise GitHubToolError("github_response_not_json") from None


def _repo(value) -> str:
    if not isinstance(value, str) or not _REPO.fullmatch(value):
        raise GitHubToolError("github_repository_invalid_use_owner_slash_repo")
    if any(part in {".", ".."} for part in value.split("/")):
        raise GitHubToolError("github_repository_invalid")
    return value


def _ref(value, *, allow_empty=False) -> str:
    if not isinstance(value, str) or len(value) > 200:
        raise GitHubToolError("github_ref_invalid")
    if not value and allow_empty:
        return ""
    if (not value or value.startswith("/") or value.endswith("/") or
            "//" in value or ".." in value.split("/") or "@{" in value or
            any(ord(ch) < 33 or ch in "~^:?*[\\" for ch in value)):
        raise GitHubToolError("github_ref_invalid")
    return value


def _file_path(value) -> str:
    if not isinstance(value, str) or not value or len(value) > 300:
        raise GitHubToolError("github_file_path_invalid")
    if value.startswith("/") or "\\" in value:
        raise GitHubToolError("github_file_path_invalid")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise GitHubToolError("github_file_path_invalid")
    if _SECRET_PATH.search(value):
        raise GitHubToolError("github_sensitive_file_blocked")
    if any(re.search(r"(?i)(?:secret|credential|password|private[-_]?key)", part)
           for part in parts):
        raise GitHubToolError("github_sensitive_file_blocked")
    return value


def _page(value, maximum=100) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise GitHubToolError("github_page_size_invalid")
    return value


def _query(path: str, values: dict) -> str:
    query = parse.urlencode({key: value for key, value in values.items()
                             if value is not None and value != ""})
    return path + (("?" + query) if query else "")


def _redact_text(value: str) -> str:
    value = _SECRET_TOKEN.sub("[REDACTED TOKEN]", value)
    value = _SECRET_JSON.sub(r"\1[REDACTED]\3", value)
    return _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)


def _short(value, limit=240) -> str:
    return _redact_text(str(value or ""))[:limit]


def _list(data, key=None) -> list:
    values = data.get(key, []) if key and isinstance(data, dict) else data
    if not isinstance(values, list):
        raise GitHubToolError("github_response_shape_invalid")
    return values


def _repo_info(item: dict) -> dict:
    return {
        "full_name": item.get("full_name"),
        "description": _short(item.get("description"), 400),
        "private": item.get("private"),
        "visibility": item.get("visibility"),
        "default_branch": item.get("default_branch"),
        "archived": item.get("archived"),
        "updated_at": item.get("updated_at"),
        "html_url": item.get("html_url"),
        "permissions": item.get("permissions"),
    }


def _origin_repository(raw: str) -> str | None:
    """Return only owner/repo, never URL userinfo or arbitrary remotes."""
    match = re.fullmatch(r"git@github\.com:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", raw)
    if match:
        value = match.group(1)
    else:
        try:
            url = parse.urlsplit(raw)
            if url.scheme not in {"https", "ssh"} or url.hostname != "github.com":
                return None
            value = url.path.strip("/")
        except ValueError:
            return None
    if value.endswith(".git"):
        value = value[:-4]
    try:
        return _repo(value)
    except GitHubToolError:
        return None


def _local_git_context() -> dict:
    """Read only the configured source checkout. Do not invoke credential helpers."""
    try:
        from .developer_tools import SOURCE
    except ImportError:
        from developer_tools import SOURCE
    executable = shutil.which("git")
    state = {"available": bool(executable), "source_repo": None,
             "branch": None, "head": None, "root": None,
             "credential_helper_configured": None, "push_transport": "not_tested",
             "local_commit_requires_github_auth": False}
    if not executable or not SOURCE.is_dir():
        return state

    def read(*args):
        try:
            result = subprocess.run([executable, "-C", str(SOURCE), *args],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                errors="replace", timeout=5, check=False)
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    root = read("rev-parse", "--show-toplevel")
    if not root:
        return state
    state["root"] = _short(root, 600)
    branch = read("symbolic-ref", "--quiet", "--short", "HEAD")
    state["branch"] = _short(branch, 240) if branch else None
    sha = read("rev-parse", "HEAD")
    state["head"] = sha if sha and re.fullmatch(r"[0-9a-f]{40,64}", sha) else None
    remote = read("remote", "get-url", "origin")
    state["source_repo"] = _origin_repository(remote) if remote else None
    helper = read("config", "--get-all", "credential.helper")
    state["credential_helper_configured"] = bool(helper)
    return state


def _github_status(token: str, auth_source: str) -> dict:
    local = _local_git_context()
    result = {"ok": True, "api": "github.com",
              "authenticated": False, "auth_source": auth_source,
              "gh_cli_available": bool(_gh_executable()),
              "local_git": local, "repository_permissions": None,
              "permissions_status": "not_checked",
              "git_transport": "independent_of_api_authentication"}
    if token:
        try:
            user = _api_get("user", token)
        except GitHubToolError as exc:
            result.update(ok=False, authenticated=None, api_error=str(exc),
                          permissions_status="api_identity_unavailable")
            return result
        result.update(authenticated=True, account=user.get("login"),
                      account_type=user.get("type"), mode="authenticated_repo_scoped",
                      write_access="check_repository_permissions_and_branch_policy")
        if local["source_repo"]:
            try:
                info = _api_get("repos/" + local["source_repo"], token)
                permissions = info.get("permissions")
                if isinstance(permissions, dict):
                    result["repository_permissions"] = {
                        key: permissions[key] for key in ("pull", "push", "admin", "maintain", "triage")
                        if type(permissions.get(key)) is bool
                    }
                    result["permissions_status"] = "reported_by_github"
                else:
                    result["permissions_status"] = "not_reported_by_github"
            except GitHubToolError as exc:
                result.update(permissions_status="repository_api_unavailable",
                              repository_api_error=str(exc))
        return result
    result.update(public_api=True, mode="public_read_only",
                  auth_hint="API credentials are unavailable. Local Git may still use Windows Git Credential Manager. A local commit does not require GitHub authentication. Do not request or expose tokens.")
    try:
        rate = _api_get("rate_limit")
        core = (rate.get("resources") or {}).get("core", {}) if isinstance(rate, dict) else {}
        result.update(rate_limit_remaining=core.get("remaining"),
                      rate_limit_limit=core.get("limit"))
    except GitHubToolError as exc:
        result.update(ok=False, api_error=str(exc))
    return result


def _compact_issue(item: dict) -> dict:
    return {
        "number": item.get("number"),
        "title": _short(item.get("title"), 220),
        "state": item.get("state"),
        "author": (item.get("user") or {}).get("login"),
        "labels": [x.get("name") for x in item.get("labels", [])
                   if isinstance(x, dict)][:12],
        "body_preview": _short(item.get("body"), 280),
        "updated_at": item.get("updated_at"),
        "html_url": item.get("html_url"),
    }


def github_call(name: str, args: dict) -> tuple[dict, bool]:
    if name not in GITHUB_NAMES:
        return {"ok": False, "error": "github_tool_unknown"}, True
    if not isinstance(args, dict) or set(args) != _ARGUMENTS[name]:
        return {"ok": False, "error": "github_arguments_invalid"}, True
    try:
        token, auth_source = _auth_token()
        if name == "github_status":
            result = _github_status(token, auth_source)
            return result, not result["ok"]

        if name == "github_search_repositories":
            query = args["query"]
            if not isinstance(query, str) or not 2 <= len(query.strip()) <= 180:
                raise GitHubToolError("github_search_query_invalid")
            page = _page(args["per_page"], 30)
            data = _api_get(_query("search/repositories", {"q": query.strip(), "per_page": page}), token)
            return {"ok": True, "total_count": data.get("total_count"),
                    "repositories": [_repo_info(x) for x in _list(data, "items")[:page]]}, False

        repo = _repo(args["repo"]) if "repo" in args else ""
        if name == "github_repo_info":
            return {"ok": True, "repository": _repo_info(_api_get("repos/" + repo, token)),
                    "authenticated": bool(token), "auth_source": auth_source}, False

        if name == "github_list_branches":
            page = _page(args["per_page"])
            items = _list(_api_get(_query("repos/" + repo + "/branches", {"per_page": page}), token))
            return {"ok": True, "branches": [
                {"name": x.get("name"), "protected": x.get("protected"),
                 "commit_sha": (x.get("commit") or {}).get("sha")}
                for x in items[:page]
            ]}, False

        if name == "github_list_commits":
            branch = _ref(args["branch"], allow_empty=True)
            page = _page(args["per_page"])
            path = _query("repos/" + repo + "/commits", {"sha": branch, "per_page": page})
            items = _list(_api_get(path, token))
            commits = []
            for item in items[:page]:
                commit = item.get("commit") or {}
                author = commit.get("author") or {}
                commits.append({
                    "sha": item.get("sha"),
                    "short_sha": str(item.get("sha") or "")[:12],
                    "message": _short((commit.get("message") or "").splitlines()[0]
                                      if commit.get("message") else "", 240),
                    "author": (item.get("author") or {}).get("login") or author.get("name"),
                    "date": author.get("date"), "html_url": item.get("html_url"),
                })
            return {"ok": True, "commits": commits}, False

        if name == "github_list_issues":
            state = args["state"]
            if state not in {"open", "closed", "all"}:
                raise GitHubToolError("github_issue_state_invalid")
            page = _page(args["per_page"])
            items = _list(_api_get(_query("repos/" + repo + "/issues",
                                           {"state": state, "per_page": page}), token))
            issues = [_compact_issue(x) for x in items if "pull_request" not in x][:page]
            return {"ok": True, "issues": issues}, False

        if name == "github_list_pull_requests":
            state = args["state"]
            if state not in {"open", "closed", "all"}:
                raise GitHubToolError("github_pull_request_state_invalid")
            page = _page(args["per_page"])
            items = _list(_api_get(_query("repos/" + repo + "/pulls",
                                           {"state": state, "per_page": page}), token))
            prs = [{
                "number": x.get("number"), "title": _short(x.get("title"), 220),
                "state": x.get("state"), "draft": x.get("draft"),
                "head": (x.get("head") or {}).get("ref"),
                "base": (x.get("base") or {}).get("ref"),
                "updated_at": x.get("updated_at"), "html_url": x.get("html_url"),
            } for x in items[:page]]
            return {"ok": True, "pull_requests": prs}, False

        if name == "github_list_workflows":
            page = _page(args["per_page"])
            data = _api_get(_query("repos/" + repo + "/actions/workflows",
                                   {"per_page": page}), token)
            return {"ok": True, "workflows": [{
                "id": x.get("id"), "name": _short(x.get("name"), 180),
                "path": x.get("path"), "state": x.get("state"),
                "html_url": x.get("html_url"),
            } for x in _list(data, "workflows")[:page]]}, False

        if name == "github_list_workflow_runs":
            branch = _ref(args["branch"], allow_empty=True)
            page = _page(args["per_page"])
            data = _api_get(_query("repos/" + repo + "/actions/runs",
                                   {"branch": branch, "per_page": page}), token)
            return {"ok": True, "total_count": data.get("total_count"),
                    "workflow_runs": [{
                        "id": x.get("id"), "name": _short(x.get("name"), 180),
                        "display_title": _short(x.get("display_title"), 220),
                        "run_number": x.get("run_number"), "status": x.get("status"),
                        "conclusion": x.get("conclusion"), "branch": x.get("head_branch"),
                        "event": x.get("event"), "created_at": x.get("created_at"),
                        "updated_at": x.get("updated_at"), "html_url": x.get("html_url"),
                    } for x in _list(data, "workflow_runs")[:page]]}, False

        if name == "github_compare_refs":
            base = _ref(args["base"])
            head = _ref(args["head"])
            route = "repos/" + repo + "/compare/" + parse.quote(base, safe="/-._") + "..." + parse.quote(head, safe="/-._")
            data = _api_get(route, token)
            files = data.get("files") if isinstance(data, dict) else []
            return {"ok": True, "status": data.get("status"),
                    "ahead_by": data.get("ahead_by"), "behind_by": data.get("behind_by"),
                    "total_commits": data.get("total_commits"),
                    "files": [{
                        "filename": _short(x.get("filename"), 300),
                        "status": x.get("status"), "additions": x.get("additions"),
                        "deletions": x.get("deletions"), "changes": x.get("changes"),
                    } for x in (files if isinstance(files, list) else [])[:50]]}, False

        if name == "github_read_file":
            path = _file_path(args["path"])
            ref = _ref(args["ref"], allow_empty=True)
            max_chars = args["max_chars"]
            if type(max_chars) is not int or not 1000 <= max_chars <= MAX_FILE_CHARS:
                raise GitHubToolError("github_file_limit_invalid")
            encoded_path = "/".join(parse.quote(part, safe="-._") for part in path.split("/"))
            query = _query("repos/" + repo + "/contents/" + encoded_path, {"ref": ref})
            item = _api_get(query, token)
            if not isinstance(item, dict) or item.get("type") != "file":
                raise GitHubToolError("github_path_is_not_a_file")
            size = item.get("size")
            if type(size) is int and size > MAX_FILE_BYTES:
                raise GitHubToolError("github_file_too_large")
            if item.get("encoding") != "base64" or not isinstance(item.get("content"), str):
                raise GitHubToolError("github_file_not_text_or_not_available")
            try:
                raw = base64.b64decode(re.sub(r"\s+", "", item["content"]), validate=True)
                content = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                raise GitHubToolError("github_file_not_utf8_text") from None
            content = _redact_text(content)
            return {"ok": True, "repo": repo, "path": path,
                    "ref": ref,
                    "sha": item.get("sha"), "size_bytes": len(raw),
                    "content": content[:max_chars],
                    "truncated": len(content) > max_chars}, False

        return {"ok": False, "error": "github_tool_not_implemented"}, True
    except GitHubToolError as exc:
        return {"ok": False, "error": str(exc)}, True
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "error": "github_arguments_invalid"}, True
