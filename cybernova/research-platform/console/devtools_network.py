"""Controlled Chromium Network inspector for Cybernova's local Qwen.

This runs an ephemeral Playwright Chromium context, collecting only redacted
request/response metadata (not a HAR with secrets). The context can load public
HTTPS GET/HEAD resources on exact preapproved hostnames; all other network
requests and WebSockets are blocked. Chromium's DNS mapping pins the target
hostname to a globally routable IPv4 address validated before launch.

It does NOT attach to the human's own Chrome DevTools session. The separately
supported HAR import reads recordings exported from the human's DevTools.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import ipaddress
import re
import socket
from urllib.parse import parse_qsl, urlsplit

MAX_EVENTS = 500
MAX_PAGE_TEXT = 2600
MAX_SITE_HOSTS = 8
MAX_SECONDS = 17

NETWORK_TOOLS = [{
    "name": "browser_network",
    "description": (
        "Open ONE authorized public HTTPS site in an isolated Chromium browser "
        "and observe the DevTools-equivalent Network events. Return sanitized "
        "GET/HEAD request URLs, query PARAMETER NAMES, resource types, response "
        "statuses, request errors, and page title. Blocks POST/PUT/PATCH/DELETE, "
        "third parties, cookies, websocket connections and private IPs. "
        "No HAR body, credentials, JS evaluation or user browser access."
    ),
    "inputSchema": {"type": "object", "properties": {
        "url": {"type": "string", "description": "Absolute HTTPS URL on allowed public host"}},
        "required": ["url"], "additionalProperties": False},
}]
NETWORK_NAMES = frozenset({"browser_network"})


def _public_v4(host: str) -> str:
    found = socket.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    ips = {ipaddress.ip_address(result[4][0]) for result in found}
    if not ips:
        raise ValueError("network_dns_no_a_records")
    if not all(ip.is_global and isinstance(ip, ipaddress.IPv4Address) for ip in ips):
        raise ValueError("network_dns_includes_non_public_ip")
    return str(sorted(ips)[0])


def _clean_url(raw_url: str) -> dict:
    """Do not store query values, credentials, fragments, or long IDs in paths."""
    u = urlsplit(raw_url)
    host = u.hostname or ""
    path = u.path or "/"
    # URL paths can contain personal IDs or bearer tokens; avoid logging them.
    path = re.sub(r"(?i)(?:[0-9a-f]{16,}|\d{5,})", "{id}", path)
    path = re.sub(r"/[^/]{65,}", "/{long-segment}", path)
    return {
        "host": host[:150],
        "path": path[:280],
        "query_keys": sorted({k[:70] for k, v in parse_qsl(u.query, keep_blank_values=True)})[:12],
    }


def _decision(url: str, method: str, allowed_hosts: set[str]) -> str | None:
    try:
        u = urlsplit(url)
        if u.scheme != "https" or u.port not in (None, 443) or u.username or u.password:
            return "blocked_non_https_or_port"
        if not u.hostname or u.hostname not in allowed_hosts:
            return "blocked_external_host"
        if method not in {"GET", "HEAD"}:
            return "blocked_non_read_method"
        if any(ord(c) < 32 for c in url) or len(url) > 1200:
            return "blocked_unusual_url"
        return None
    except ValueError:
        return "blocked_invalid_url"


SAFE_HEADERS = frozenset({
    "content-type", "cache-control", "content-encoding",
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "x-powered-by", "server", "vary", "etag",
    "last-modified", "access-control-allow-origin", "access-control-allow-methods",
    "access-control-allow-credentials", "cross-origin-resource-policy",
    "referrer-policy", "permissions-policy", "x-cache",
})
SECRET_FIELD = re.compile(
    r"(?i)(?:password|passwd|secret|token|session|auth|jwt|bearer|"
    r"access.?key|api.?key|private.?key|cookie|csrf|nonce|email|phone|"
    r"address|customer|contract|account|balance|user.?id|personal)"
)
SENSITIVE_VALUE = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~-]{6,}|"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|"
    r"\b(?:[0-9a-f]{16,}|[A-Za-z0-9_-]{40,})\b)"
)


def _shape(value, *, depth=0):
    if depth >= 4:
        return {"type": type(value).__name__, "truncated": True}
    if isinstance(value, dict):
        return {str(k)[:64]: (
            "[REDACTED FIELD]" if SECRET_FIELD.search(str(k))
            else _shape(v, depth=depth + 1))
            for k, v in list(value.items())[:35]}
    if isinstance(value, list):
        return {"type": "array", "length": len(value),
                "items": [_shape(x, depth=depth + 1) for x in value[:2]]}
    if isinstance(value, str):
        return {"type": "string", "length": len(value),
                "example": SENSITIVE_VALUE.sub("[REDACTED]", value[:70])}
    if value is None:
        return {"type": "null"}
    return {"type": type(value).__name__}


def summarize_response(content_type: str, body: bytes, headers: dict | None = None) -> dict:
    """Evidence for comparing responses, without publishing secrets."""
    if not isinstance(body, bytes):
        raise ValueError("invalid_response_bytes")
    safe_headers = {
        str(k).lower()[:75]: SENSITIVE_VALUE.sub("[REDACTED]", str(v)[:400])
        for k, v in (headers or {}).items() if str(k).lower() in SAFE_HEADERS
    }
    summary = {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_size": len(body),
        "headers": safe_headers,
    }
    ctype = (content_type or "").lower()
    if len(body) > 400_000:
        summary["body_preview"] = "[response too large to preview]"
        return summary
    if "json" in ctype or body.lstrip().startswith((b"{", b"[")):
        try:
            data = json.loads(body.decode("utf-8", "replace"))
            summary["json_shape"] = _shape(data)
            summary["body_preview"] = "[JSON: compare schema, status and hash]"
            return summary
        except ValueError:
            pass
    if any(k in ctype for k in ("text/", "javascript", "xml", "html")):
        snippet = body.decode("utf-8", "replace")[:3200]
        summary["body_preview"] = SENSITIVE_VALUE.sub("[REDACTED]", snippet)
    else:
        summary["body_preview"] = "[binary content, hash only]"
    return summary


def _capture(url: str, allowed_hosts: set[str], *, runner=None) -> dict:
    # All configured domains use exact matches (no *.wildcards or subdomains).
    if not isinstance(url, str) or len(url) > 850:
        raise ValueError("invalid_capture_url")
    try:
        from .browser_tools import _url_parts
    except ImportError:
        from browser_tools import _url_parts
    parsed, host = _url_parts(url, allowed_hosts)
    # Fail closed on a potentially unsafe DNS answer. Don't silently bypass
    # IP pinning when only IPv6 addresses or invalid records are available.
    pin = _public_v4(host)
    if runner is not None:
        result = runner(url, {host: pin}, allowed_hosts)
    else:
        result = _playwright_run(url, {host: pin}, allowed_hosts)
    return {
        "ok": True, "url": "https://" + host + (parsed.path or "/"),
        "browser": "Chromium Playwright (isolated)",
        "collection": "DevTools-equivalent browser Network metadata",
        "capture": result,
        "limitations": [
            "Only approved public HTTPS host, read-only GET/HEAD requests",
            "Third-party resources and WebSockets blocked; site behavior may differ",
            "No request/response bodies, cookies, tokens, full query values or private IPs",
            "Only single page load and brief passive wait, no clicks or form submissions",
        ],
    }


def _playwright_run(url: str, pinned: dict[str, str], allowed_hosts: set[str]) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ValueError("playwright_python_not_installed") from None
    rows: list[dict] = []
    req_index: dict[object, dict] = {}
    blocked = Counter()

    def on_request(req):
        reason = _decision(req.url, req.method, allowed_hosts)
        if len(rows) >= MAX_EVENTS:
            return
        entry = {"method": req.method[:12], "resource_type": req.resource_type[:25],
                 "status": None, **_clean_url(req.url)}
        if reason:
            entry["blocked"] = reason
            blocked[reason] += 1
        rows.append(entry)
        req_index[req] = entry

    def on_response(resp):
        item = req_index.get(resp.request)
        if item is not None:
            item["status"] = int(resp.status)

    def on_failed(req):
        item = req_index.get(req)
        if item is not None and "blocked" not in item:
            item["error"] = "network_failed"

    def route_request(route):
        reason = _decision(route.request.url, route.request.method, allowed_hosts)
        if reason:
            route.abort("blockedbyclient")
        else:
            route.continue_()

    mappings = ", ".join(
        f"MAP {host} {ip}" for host, ip in pinned.items()
    )
    resolver = mappings + ", EXCLUDE localhost"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=[
                "--no-sandbox",
                "--no-proxy-server",
                "--disable-background-networking",
                "--disable-extensions",
                "--disable-sync",
                "--disable-default-apps",
                "--disable-features=MediaRouter",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--host-resolver-rules=" + resolver,
            ], timeout=10000)
            try:
                ctx = browser.new_context(
                    accept_downloads=False,
                    ignore_https_errors=False,
                    java_script_enabled=True,
                    service_workers="block",
                    permissions=[],
                    locale="ru-RU",
                    user_agent="CybernovaReadOnlyResearch/1.0",
                )
                try:
                    ctx.route("**/*", route_request)
                    # No server connection, no WebSocket data transmission.
                    ctx.route_web_socket("**/*", lambda ws: ws.close(code=1000))
                    ctx.on("request", on_request)
                    ctx.on("response", on_response)
                    ctx.on("requestfailed", on_failed)
                    page = ctx.new_page()
                    page.set_default_timeout(8000)
                    page.goto(url, wait_until="domcontentloaded", timeout=10000)
                    page.wait_for_timeout(1500)
                    title = page.title()[:160]
                    headings = page.locator("h1, h2").all_text_contents()[:12]
                    excerpt = page.locator("body").inner_text(timeout=4000)[:MAX_PAGE_TEXT]
                finally:
                    ctx.close()
            finally:
                browser.close()
    except Exception as exc:
        # Never expose secrets, raw URLs or browser-local file paths in errors.
        kind = type(exc).__name__
        if "Executable doesn't exist" in str(exc):
            raise ValueError("chromium_missing_run_playwright_install") from None
        raise ValueError("browser_capture_failed:" + kind[:70]) from None

    summary = Counter((r["resource_type"], str(r.get("status") or "blocked"))
                      for r in rows)
    return {
        "title": title,
        "headings": [" ".join(x.split())[:160] for x in headings],
        "visible_excerpt": excerpt[:MAX_PAGE_TEXT],
        "network_events": rows[:MAX_EVENTS],
        "total_events_observed": len(rows),
        "events_by_type_and_status": [
            {"resource_type": typ, "status": status, "count": count}
            for (typ, status), count in summary.most_common(25)
        ],
        "blocked_requests": dict(blocked),
        "event_limit": MAX_EVENTS,
        "source": "live_browser_requests",
        "raw_secrets_retained": False,
    }


def network_call(name: str, args: dict, upstream, *, extra_hosts=None, runner=None):
    if name not in NETWORK_NAMES:
        raise ValueError("unknown_network_tool")
    if not isinstance(args, dict) or set(args) != {"url"}:
        raise ValueError("invalid_network_arguments")
    scope, failed = upstream.call("gateway_status", {})
    if failed or not isinstance(scope, dict):
        raise ValueError("cannot_verify_gateway_scope")
    authorized = scope.get("authorized_hosts") or []
    if not isinstance(authorized, list):
        raise ValueError("invalid_gateway_scope")
    import os
    hosts = {h for h in authorized if isinstance(h, str)}
    hosts.update(h.strip() for h in os.environ.get("CYBERNOVA_BROWSER_HOSTS", "").split(",") if h.strip())
    hosts.update(extra_hosts or ())
    return _capture(args["url"], hosts, runner=runner)
