"""Autonomous, repository-scoped GitHub write tools for Cybernova.

Credentials are obtained from the existing GitHub CLI session or GH_TOKEN /
GITHUB_TOKEN. Routine repository work is autonomous; destructive and repository-
administration operations require matching intent in the latest user request.
"""
from __future__ import annotations

import base64
from io import BytesIO
import json
import re
import zipfile
from urllib import error, parse, request

try:
    from .github_tools import (
        MAX_API_BYTES, GitHubToolError, _auth_token, _file_path, _redact_text, _repo, _ref,
    )
except ImportError:
    from github_tools import (
        MAX_API_BYTES, GitHubToolError, _auth_token, _file_path, _redact_text, _repo, _ref,
    )

API_BASE = "https://api.github.com"
MAX_WRITE_BODY_CHARS = 50_000
MAX_COMMIT_FILES = 40
MAX_COMMIT_FILE_BYTES = 250_000
MAX_COMMIT_TOTAL_BYTES = 1_000_000
MAX_LOG_BYTES = 8_000_000
_SECRET_VALUE = re.compile(
    r"(?i)(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|"
    r"Bearer\s+[A-Za-z0-9._~+/-]{16,})"
)


def _tool(name: str, description: str, properties: dict) -> dict:
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


_REPO_ARG = {"type": "string", "minLength": 3, "maxLength": 205}
_STRING = {"type": "string"}
_GITHUB_WRITE_COMMON = (
    "Uses the locally configured GitHub CLI session or GH_TOKEN/GITHUB_TOKEN. "
    "Credentials are never returned to the model or written to diagnostics. "
    "Ordinary repository work is autonomous; no per-call approval is requested. "
    "Repository deletion is not exposed. Destructive, access-control, secret, "
    "branch-protection and merge actions require matching intent in the latest "
    "user request. Only the selected owner/repository can be accessed."
)

GITHUB_WRITE_TOOLS = [
    _tool(
        "github_api_request",
        "Full repository-scoped GitHub REST API for operations not covered by a specialized tool. "
        "Supports GET, POST, PATCH, PUT and DELETE under /repos/{repo}/ only. "
        "Use relative paths such as: repository (the repo root/settings), git/refs, contents/README.md, pulls, pulls/12, "
        "issues/12/comments, releases, actions/runs/123/rerun, actions/workflows/ci.yml/dispatches, "
        "collaborators, branches/main/protection, actions/secrets/public-key, rulesets. "
        "query_json and body_json must be JSON objects encoded as strings; use empty strings when unused. "
        "For PUT contents/{path}, supply plain UTF-8 text in body_json.content; Cybernova base64-encodes it. "
        "Responses are secret-redacted and size-limited. Use github_read_file for readable file contents. "
        + _GITHUB_WRITE_COMMON,
        {
            "repo": _REPO_ARG,
            "method": {"type": "string", "enum": ["GET", "POST", "PATCH", "PUT", "DELETE"]},
            "path": {"type": "string", "minLength": 1, "maxLength": 500},
            "query_json": {"type": "string", "maxLength": 5000},
            "body_json": {"type": "string", "maxLength": MAX_WRITE_BODY_CHARS},
        },
    ),
    _tool(
        "github_create_branch",
        "Create a new branch from a branch or commit. Empty from_ref uses the repository default branch. "
        "Never overwrites an existing branch or modifies the default branch. " + _GITHUB_WRITE_COMMON,
        {
            "repo": _REPO_ARG,
            "branch": {"type": "string", "minLength": 1, "maxLength": 200},
            "from_ref": {"type": "string", "maxLength": 200},
        },
    ),
    _tool(
        "github_commit_files",
        "Create one atomic Git commit containing multiple text-file additions, updates and deletions "
        "on an existing non-default branch. Creates blobs/tree/commit and advances the branch without "
        "force-push. File paths containing credentials, private keys, databases or .env are blocked. "
        "Use this for normal code changes instead of one commit per file. " + _GITHUB_WRITE_COMMON,
        {
            "repo": _REPO_ARG,
            "branch": {"type": "string", "minLength": 1, "maxLength": 200},
            "message": {"type": "string", "minLength": 5, "maxLength": 180},
            "files": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_COMMIT_FILES,
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "minLength": 1, "maxLength": 300},
                        "operation": {"type": "string", "enum": ["upsert", "delete"]},
                        "content": {"type": "string", "maxLength": MAX_COMMIT_FILE_BYTES},
                    },
                    "required": ["path", "operation", "content"],
                    "additionalProperties": False,
                },
            },
        },
    ),
    _tool(
        "github_workflow_job_logs",
        "Download and decode the logs for one GitHub Actions job. Returns redacted text, not the ZIP bytes. Use after inspecting failed workflow jobs.",
        {
            "repo": _REPO_ARG,
            "job_id": {"type": "integer", "minimum": 1},
            "max_chars": {"type": "integer", "minimum": 1000, "maximum": 50000},
        },
    ),
    _tool(
        "github_merge_pull_request",
        "Merge an open, non-draft Pull Request only when the latest user request explicitly asks to merge, "
        "the supplied head SHA still matches, GitHub reports it mergeable, and all discovered checks are green. "
        "Never bypass failing, pending or missing checks. " + _GITHUB_WRITE_COMMON,
        {
            "repo": _REPO_ARG,
            "number": {"type": "integer", "minimum": 1},
            "method": {"type": "string", "enum": ["merge", "squash", "rebase"]},
            "expected_head_sha": {"type": "string", "minLength": 40, "maxLength": 40},
        },
    ),
]
GITHUB_WRITE_NAMES = frozenset(item["name"] for item in GITHUB_WRITE_TOOLS)


def _api_path(path: object) -> str:
    if (not isinstance(path, str) or not path or len(path) > 500
            or path.startswith("/") or "://" in path
            or any(ch in path for ch in ("?", "#", "\\", "%"))
            or any(ord(ch) < 32 for ch in path)):
        raise GitHubToolError("github_api_path_invalid")
    parts = path.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise GitHubToolError("github_api_path_invalid")
    return "/".join(parse.quote(part, safe="-._~") for part in parts)


def _json_object(raw: object, *, field: str, maximum: int) -> dict:
    if not isinstance(raw, str) or len(raw) > maximum:
        raise GitHubToolError("github_" + field + "_invalid")
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        raise GitHubToolError("github_" + field + "_not_json") from None
    if not isinstance(value, dict):
        raise GitHubToolError("github_" + field + "_must_be_object")
    return value


def _api_request(method: str, repo: str, path: str, token: str, *,
                 query: dict | None = None, body: dict | None = None):
    method = method.upper()
    if method not in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
        raise GitHubToolError("github_method_invalid")
    if method != "GET" and not token:
        raise GitHubToolError("github_write_auth_required_run_gh_auth_login")
    encoded = _api_path(path) if path else ""
    query_values = query or {}
    query_string = parse.urlencode(query_values, doseq=True)
    url = API_BASE + "/repos/" + repo + ("/" + encoded if encoded else "")
    if query_string:
        url += "?" + query_string
    raw_body = None if body is None or method == "GET" or (method == "DELETE" and not body) else json.dumps(
        body, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Cybernova-Autonomous-GitHub-Agent",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    if raw_body is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=raw_body, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=25) as response:
            final = parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "api.github.com":
                raise GitHubToolError("github_redirect_rejected")
            payload = response.read(MAX_API_BYTES + 1)
            status = response.status
    except error.HTTPError as exc:
        try:
            detail = json.loads(exc.read(8000).decode("utf-8", errors="replace"))
            message = _redact_text(str(detail.get("message") or ""))[:180]
        except (ValueError, AttributeError):
            message = ""
        if exc.code == 403:
            raise GitHubToolError("github_permission_denied_or_rate_limited" +
                                  (":" + message if message else "")) from None
        if exc.code == 404:
            raise GitHubToolError("github_resource_not_found_or_not_visible") from None
        if exc.code == 422:
            raise GitHubToolError("github_validation_failed" +
                                  (":" + message if message else "")) from None
        raise GitHubToolError("github_http_" + str(exc.code) +
                              (":" + message if message else "")) from None
    except error.URLError:
        raise GitHubToolError("github_network_error") from None
    except (TimeoutError, OSError):
        raise GitHubToolError("github_transport_error") from None
    if len(payload) > MAX_API_BYTES:
        raise GitHubToolError("github_response_too_large")
    if not payload:
        return {}, status
    try:
        return json.loads(payload.decode("utf-8")), status
    except (UnicodeDecodeError, ValueError):
        raise GitHubToolError("github_response_not_json") from None


def _sanitize(value, depth=0):
    if depth > 12:
        return "[depth-limited]"
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:500]:
            if re.search(r"(?i)(?:token|password|passwd|secret|authorization|cookie|private.?key)", str(key)):
                result[str(key)] = "[REDACTED]"
            else:
                result[str(key)] = _sanitize(item, depth + 1)
        return result
    if isinstance(value, list):
        return [_sanitize(item, depth + 1) for item in value[:500]]
    if isinstance(value, str):
        return _redact_text(value)[:20_000]
    return value


def _latest_user_text(messages) -> str:
    if not isinstance(messages, list):
        return ""
    for row in reversed(messages):
        if isinstance(row, dict) and row.get("role") == "user":
            return str(row.get("content") or "")[:10_000]
    return ""


def _require_intent(messages, pattern: str, reason: str):
    latest = _latest_user_text(messages)
    if re.search(r"(?i)(?:\bне\b|\bнет\b|\bнельзя\b|\bзапрещаю\b|\bотмена\b|"
                 r"\bdo\s+not\b|\bdon't\b|\bnever\b|\bdeny\b|\brefuse\b)", latest):
        raise GitHubToolError("github_action_not_authorized_by_user_request")
    if not re.search(pattern, latest, re.IGNORECASE):
        raise GitHubToolError("github_explicit_task_intent_required:" + reason)


def _guard_api_action(method: str, path: str, body: dict, user_messages):
    lowered = path.casefold()
    if re.fullmatch(r"pulls/\d+/merge", lowered):
        raise GitHubToolError("use_github_merge_pull_request_for_checked_merge")
    if method == "DELETE":
        _require_intent(
            user_messages,
            r"(?:удал|delete|remove|убер|очист|отвяз|revoke|archive)",
            "delete/remove",
        )
        if re.fullmatch(r"git/refs/heads/.+", lowered):
            pass
    admin_path = method != "GET" and bool(
        lowered == "repository" or re.search(
            r"(?:^|/)(?:collaborators|hooks|rulesets|environments|"
            r"actions/permissions|actions/secrets|branches/[^/]+/protection)(?:/|$)",
            lowered,
        )
    )
    if admin_path:
        _require_intent(
            user_messages,
            r"(?:созда|добав|удал|измен|настрой(?!к)|включ|отключ|переимен|архив|"
            r"разреш|запрет|rotate|create|add|delete|remove|change|update|set|"
            r"enable|disable|invite|revoke)",
            "repository administration action",
        )
        _require_intent(
            user_messages,
            r"(?:collaborator|участник|пользоват|доступ|прав[ао]|permission|hook|webhook|"
            r"защит|protection|secret|секрет|environment|окружени|ruleset|правил|"
            r"repo|репозитор|settings|настрой|visibility|видимост|archive|архив|rename|переимен)",
            "repository administration target",
        )
    if method == "PATCH" and lowered.startswith(("issues/", "pulls/")) and body.get("state") == "closed":
        _require_intent(user_messages, r"(?:закрой|закрыть|close|resolve|реши)", "close issue or pull request")
    if method == "POST" and lowered.endswith("/dispatches"):
        _require_intent(user_messages, r"(?:запусти|запустить|выполни|run|dispatch|workflow|pipeline)", "workflow dispatch")
    if method == "POST" and lowered == "releases":
        _require_intent(user_messages, r"(?:создай|создать|опубликуй|релиз|release|publish)", "publish release")
    if method == "POST" and lowered == "deployments":
        _require_intent(user_messages, r"(?:deploy|развер|deployment|запусти|запустить)", "deployment")
    if method == "POST" and lowered.endswith("/reviews") and str(body.get("event", "")).upper() in {"APPROVE", "REQUEST_CHANGES"}:
        _require_intent(user_messages, r"(?:approve|одобри|одобрить|request.changes|запроси изменения)", "submit PR review")


def _repo_default_branch(repo: str, token: str) -> str:
    info, _ = _api_request("GET", repo, "", token)
    branch = info.get("default_branch") if isinstance(info, dict) else None
    if not isinstance(branch, str) or not branch:
        raise GitHubToolError("github_default_branch_unavailable")
    return branch


def _create_branch(args: dict, token: str):
    repo = _repo(args["repo"])
    branch = _ref(args["branch"])
    from_ref = _ref(args["from_ref"], allow_empty=True)
    default = _repo_default_branch(repo, token)
    if branch == default:
        raise GitHubToolError("github_cannot_create_default_branch")
    source_ref = from_ref or default
    if re.fullmatch(r"[0-9a-f]{40}", source_ref):
        sha = source_ref
    else:
        source, _ = _api_request("GET", repo, "git/ref/heads/" + source_ref, token)
        sha = ((source.get("object") or {}).get("sha")
               if isinstance(source, dict) else None)
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise GitHubToolError("github_source_ref_unavailable")
    created, status = _api_request(
        "POST", repo, "git/refs", token,
        body={"ref": "refs/heads/" + branch, "sha": sha},
    )
    return {
        "ok": True, "repo": repo, "branch": branch, "from_ref": source_ref,
        "commit_sha": sha, "created": created.get("ref"), "http_status": status,
    }


def _commit_files(args: dict, token: str):
    repo = _repo(args["repo"])
    branch = _ref(args["branch"])
    message = args["message"]
    files = args["files"]
    if not isinstance(message, str) or not 5 <= len(message) <= 180:
        raise GitHubToolError("github_commit_message_invalid")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_COMMIT_FILES:
        raise GitHubToolError("github_commit_file_list_invalid")
    default = _repo_default_branch(repo, token)
    if branch == default:
        raise GitHubToolError("github_direct_default_branch_commit_blocked")
    ref_data, _ = _api_request("GET", repo, "git/ref/heads/" + branch, token)
    base_sha = ((ref_data.get("object") or {}).get("sha")
                if isinstance(ref_data, dict) else None)
    if not isinstance(base_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise GitHubToolError("github_branch_not_found")
    commit_data, _ = _api_request("GET", repo, "git/commits/" + base_sha, token)
    base_tree = ((commit_data.get("tree") or {}).get("sha")
                 if isinstance(commit_data, dict) else None)
    if not isinstance(base_tree, str):
        raise GitHubToolError("github_base_tree_unavailable")

    seen, total, entries, changed = set(), 0, [], []
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "operation", "content"}:
            raise GitHubToolError("github_commit_file_shape_invalid")
        path = _file_path(item["path"])
        operation, content = item["operation"], item["content"]
        if path in seen or operation not in {"upsert", "delete"} or not isinstance(content, str):
            raise GitHubToolError("github_commit_file_invalid")
        seen.add(path)
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_COMMIT_FILE_BYTES:
            raise GitHubToolError("github_commit_file_too_large")
        if operation == "delete":
            if content:
                raise GitHubToolError("github_delete_content_must_be_empty")
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
        else:
            if _SECRET_VALUE.search(content):
                raise GitHubToolError("github_sensitive_content_blocked")
            total += len(encoded)
            if total > MAX_COMMIT_TOTAL_BYTES:
                raise GitHubToolError("github_commit_total_too_large")
            blob, _ = _api_request(
                "POST", repo, "git/blobs", token,
                body={"content": content, "encoding": "utf-8"},
            )
            blob_sha = blob.get("sha") if isinstance(blob, dict) else None
            if not isinstance(blob_sha, str):
                raise GitHubToolError("github_blob_create_failed")
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob_sha})
        changed.append({"path": path, "operation": operation})

    tree, _ = _api_request(
        "POST", repo, "git/trees", token,
        body={"base_tree": base_tree, "tree": entries},
    )
    tree_sha = tree.get("sha") if isinstance(tree, dict) else None
    if not isinstance(tree_sha, str):
        raise GitHubToolError("github_tree_create_failed")
    commit, _ = _api_request(
        "POST", repo, "git/commits", token,
        body={"message": message, "tree": tree_sha, "parents": [base_sha]},
    )
    commit_sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(commit_sha, str):
        raise GitHubToolError("github_commit_create_failed")
    updated, status = _api_request(
        "PATCH", repo, "git/refs/heads/" + branch, token,
        body={"sha": commit_sha, "force": False},
    )
    return {
        "ok": True, "repo": repo, "branch": branch,
        "parent_sha": base_sha, "commit_sha": commit_sha,
        "updated_ref": updated.get("ref"), "http_status": status,
        "files_changed": changed, "file_count": len(changed),
    }


def _merge_pull_request(args: dict, token: str, user_messages):
    repo = _repo(args["repo"])
    number = args["number"]
    method = args["method"]
    expected = args["expected_head_sha"]
    if type(number) is not int or number < 1 or method not in {"merge", "squash", "rebase"}:
        raise GitHubToolError("github_merge_arguments_invalid")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise GitHubToolError("github_expected_head_sha_invalid")
    _require_intent(user_messages, r"(?:merge|мерж|объедин|влей|слей)", "merge pull request")
    pr, _ = _api_request("GET", repo, "pulls/" + str(number), token)
    if pr.get("state") != "open":
        raise GitHubToolError("github_pull_request_not_open")
    if pr.get("draft"):
        raise GitHubToolError("github_pull_request_is_draft")
    head_sha = ((pr.get("head") or {}).get("sha"))
    if head_sha != expected:
        raise GitHubToolError("github_pull_request_head_changed")
    if pr.get("mergeable") is not True:
        raise GitHubToolError("github_pull_request_not_confirmed_mergeable")
    checks, _ = _api_request(
        "GET", repo, "commits/" + head_sha + "/check-runs", token,
        query={"per_page": 100},
    )
    check_rows = checks.get("check_runs", []) if isinstance(checks, dict) else []
    status_data, _ = _api_request("GET", repo, "commits/" + head_sha + "/status", token)
    statuses = status_data.get("statuses", []) if isinstance(status_data, dict) else []
    has_checks = bool(check_rows or statuses)
    if not has_checks:
        raise GitHubToolError("github_merge_blocked_checks_not_found")
    bad_checks = [
        {"name": row.get("name"), "status": row.get("status"), "conclusion": row.get("conclusion")}
        for row in check_rows
        if row.get("status") != "completed" or row.get("conclusion") not in {"success", "neutral", "skipped"}
    ]
    bad_statuses = [
        {"context": row.get("context"), "state": row.get("state")}
        for row in statuses if row.get("state") != "success"
    ]
    if bad_checks or bad_statuses:
        raise GitHubToolError("github_merge_blocked_checks_not_green:" +
                              json.dumps({"checks": bad_checks[:10], "statuses": bad_statuses[:10]}))
    merged, status = _api_request(
        "PUT", repo, "pulls/" + str(number) + "/merge", token,
        body={"sha": expected, "merge_method": method},
    )
    if merged.get("merged") is not True:
        raise GitHubToolError("github_merge_failed")
    return {
        "ok": True, "repo": repo, "number": number, "merged": True,
        "merge_sha": merged.get("sha"), "method": method, "http_status": status,
    }



def _workflow_job_logs(args: dict, token: str):
    repo = _repo(args["repo"])
    job_id = args["job_id"]
    max_chars = args["max_chars"]
    if type(job_id) is not int or job_id < 1:
        raise GitHubToolError("github_job_id_invalid")
    if type(max_chars) is not int or not 1000 <= max_chars <= 50_000:
        raise GitHubToolError("github_log_limit_invalid")
    if not token:
        raise GitHubToolError("github_auth_required_for_workflow_logs")
    url = API_BASE + "/repos/" + repo + "/actions/jobs/" + str(job_id) + "/logs"
    req = request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "User-Agent": "Cybernova-Autonomous-GitHub-Agent",
        "X-GitHub-Api-Version": "2022-11-28",
    }, method="GET")
    try:
        with request.urlopen(req, timeout=35) as response:
            final = parse.urlsplit(response.geturl())
            host = (final.hostname or "").lower()
            trusted_redirect = (
                host == "api.github.com" or host.endswith(".blob.core.windows.net")
                or host.endswith(".githubusercontent.com")
            )
            if final.scheme != "https" or not trusted_redirect:
                raise GitHubToolError("github_log_redirect_rejected")
            raw = response.read(MAX_LOG_BYTES + 1)
    except error.HTTPError as exc:
        raise GitHubToolError("github_workflow_log_http_" + str(exc.code)) from None
    except error.URLError:
        raise GitHubToolError("github_network_error") from None
    except (TimeoutError, OSError):
        raise GitHubToolError("github_transport_error") from None
    if len(raw) > MAX_LOG_BYTES:
        raise GitHubToolError("github_workflow_log_too_large")
    chunks = []
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            for name in archive.namelist()[:80]:
                if name.endswith("/"):
                    continue
                info = archive.getinfo(name)
                if info.file_size > 2_000_000:
                    continue
                try:
                    value = archive.read(name).decode("utf-8", errors="replace")
                except (KeyError, OSError, RuntimeError):
                    continue
                chunks.append("===== " + name[:240] + " =====\n" + _redact_text(value))
    except zipfile.BadZipFile:
        chunks.append(_redact_text(raw.decode("utf-8", errors="replace")))
    combined = "\n".join(chunks)
    return {
        "ok": True, "repo": repo, "job_id": job_id,
        "log_files": len(chunks), "logs": combined[:max_chars],
        "truncated": len(combined) > max_chars,
    }


def github_write_call(name: str, args: dict, *, user_messages=None) -> tuple[dict, bool]:
    if name not in GITHUB_WRITE_NAMES:
        return {"ok": False, "error": "github_write_tool_unknown"}, True
    expected = {
        "github_api_request": {"repo", "method", "path", "query_json", "body_json"},
        "github_create_branch": {"repo", "branch", "from_ref"},
        "github_commit_files": {"repo", "branch", "message", "files"},
        "github_merge_pull_request": {"repo", "number", "method", "expected_head_sha"},
        "github_workflow_job_logs": {"repo", "job_id", "max_chars"},
    }[name]
    if not isinstance(args, dict) or set(args) != expected:
        return {"ok": False, "error": "github_arguments_invalid"}, True
    try:
        token, _ = _auth_token()
        if not token:
            raise GitHubToolError("github_auth_required_run_gh_auth_login_or_configure_token")
        if name == "github_create_branch":
            result = _create_branch(args, token)
        elif name == "github_commit_files":
            result = _commit_files(args, token)
        elif name == "github_merge_pull_request":
            result = _merge_pull_request(args, token, user_messages or [])
        elif name == "github_workflow_job_logs":
            result = _workflow_job_logs(args, token)
        else:
            repo = _repo(args["repo"])
            method = args["method"]
            if method not in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
                raise GitHubToolError("github_method_invalid")
            path = args["path"]
            _api_path(path)  # Validate without pre-encoding; _api_request encodes each segment.
            query = _json_object(args["query_json"], field="query", maximum=5000)
            body = _json_object(args["body_json"], field="body", maximum=MAX_WRITE_BODY_CHARS)
            _guard_api_action(method, path, body, user_messages or [])
            if method == "DELETE" and re.fullmatch(r"git/refs/heads/.+", path):
                branch = path[len("git/refs/heads/"):]
                if branch == _repo_default_branch(repo, token):
                    raise GitHubToolError("github_cannot_delete_default_branch")
            if _SECRET_VALUE.search(json.dumps(body, ensure_ascii=False)):
                raise GitHubToolError("github_sensitive_request_body_blocked")
            if method == "GET" and body:
                raise GitHubToolError("github_get_body_not_allowed")
            if method == "PUT" and path.startswith("contents/"):
                file_path = path[len("contents/"):]
                _file_path(file_path)
                if isinstance(body.get("content"), str):
                    body["content"] = base64.b64encode(body["content"].encode("utf-8")).decode("ascii")
            request_path = "" if path == "repository" else path
            data, status = _api_request(
                method, repo, request_path, token,
                query=query, body=body,
            )
            result = {
                "ok": True, "repo": repo, "method": method,
                "path": path, "http_status": status,
                "data": _sanitize(data),
            }
            if len(json.dumps(result, ensure_ascii=False)) > 50_000:
                result["data"] = {"truncated": True, "preview": json.dumps(
                    _sanitize(data), ensure_ascii=False
                )[:45_000]}
        return _sanitize(result), False
    except GitHubToolError as exc:
        return {"ok": False, "error": str(exc)[:700]}, True
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "error": "github_arguments_invalid"}, True
