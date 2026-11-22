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
    r"""(?i)(["'][\w.-]*(?:token|secret|password|passwd|api[_-]?key|"
    r"private[_-]?key|authorization|cookie)[\w.-]*["']\s*:\s*["'])([^"']*)(["'])"""
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
          "Check GitHub API connectivity and authentication. Reports only whether access is authenticated and the auth source; never returns credentials."),
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


def _auth_token() -> tuple[str, str]:
    for key in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(key, "").strip()
        if value:
            return value, "environment"
    executable = shutil.which("gh") or shutil.which("gh.exe")
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
    }


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
            if args:
                raise GitHubToolError("github_arguments_invalid")
            if token:
                user = _api_get("user", token)
                return {
                    "ok": True, "api": "github.com", "authenticated": True,
                    "auth_source": auth_source,
                    "gh_cli_available": bool(shutil.which("gh") or shutil.which("gh.exe")),
                    "account": user.get("login"),
                    "account_type": user.get("type"), "mode": "read_only",
                }, False
            rate = _api_get("rate_limit")
            core = (rate.get("resources") or {}).get("core", {}) if isinstance(rate, dict) else {}
            return {
                "ok": True, "api": "github.com", "authenticated": False,
                "auth_source": "anonymous", "public_api": True,
                "gh_cli_available": bool(shutil.which("gh") or shutil.which("gh.exe")),
                "auth_hint": "For private repositories, install GitHub CLI and run gh auth login on the Cybernova host, or configure GH_TOKEN/GITHUB_TOKEN outside chat.",
                "rate_limit_remaining": core.get("remaining"),
                "rate_limit_limit": core.get("limit"), "mode": "public_read_only",
            }, False

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
            return {"ok": True, "repository": _repo_info(_api_get("repos/" + repo, token))}, False

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
