"""Cybernova's scoped read-only web browser (HTML mode).

One bounded HTTPS page load per tool call. Public DNS, pinned peer IP,
valid TLS, no credential forwarding, no proxies, no JS or file access.
Navigation is model-directed through links returned by the previous page.
This is not a port scanner or general network tunnel.
"""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import http.client
import ipaddress
import os
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit

MAX_HTML_BYTES = 700_000
MAX_EXCERPT = 9000
MAX_LINKS = 35
MAX_REDIRECTS = 2

BROWSER_TOOLS = [{
    "name": "browser_open",
    "description": (
        "Read ONE public HTTPS web page with a guarded HTML-only browser. "
        "Returns real HTTP status, title, headings, visible text excerpt, "
        "SHA256 and links for navigation. Requires exact hostname in "
        "Cybernova browser allowlist or authorized MCP gateway scope. "
        "No JavaScript, cookies, logins, scans or internal IPs."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Absolute https:// URL for one approved public website page"},
        },
        "required": ["url"],
        "additionalProperties": False,
    },
}]
BROWSER_NAMES = frozenset(t["name"] for t in BROWSER_TOOLS)


def _url_parts(value: str, allowed_hosts: set[str]):
    if not isinstance(value, str) or len(value) > 850 or not value.startswith("https://"):
        raise ValueError("https_url_required")
    if any(ord(c) < 32 for c in value) or "\\" in value:
        raise ValueError("invalid_url")
    u = urlsplit(value)
    host = u.hostname or ""
    if (u.scheme != "https" or u.username or u.password or u.fragment or
            u.port not in (None, 443) or not host or
            host != host.lower().rstrip(".") or
            not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", host) or
            ".." in host):
        raise ValueError("invalid_public_https_url")
    try:
        ipaddress.ip_address(host)
        raise ValueError("ip_literal_forbidden")
    except ValueError as exc:
        if str(exc) == "ip_literal_forbidden":
            raise
    if host not in allowed_hosts:
        raise ValueError("browser_host_not_allowed")
    return u, host


def _public_ip(host: str) -> str:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = []
    for family, kind, proto, canonical, address in infos:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global:
            raise ValueError("blocked_non_public_address")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise ValueError("dns_no_public_addresses")
    return ips[0]


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str):
        super().__init__(host, port=443, context=ssl.create_default_context(), timeout=8)
        self._destination_ip = ip

    def connect(self):
        raw = socket.create_connection((self._destination_ip, 443), timeout=8)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class _Visible(HTMLParser):
    SKIP = frozenset({"script", "style", "svg", "noscript", "template"})
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.skip_level = 0
        self.title_level = 0
        self.heading_level = 0
        self.title = []
        self.headings = []
        self.lines = []
        self.links = []
        self.seen_links = set()
        self.in_anchor = 0
        self.anchor_url = None
        self.anchor_label = []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip_level += 1
        if self.skip_level:
            return
        if tag == "title":
            self.title_level += 1
        if tag in {"h1", "h2", "h3"}:
            self.heading_level += 1
        if tag in {"p", "div", "li", "section", "article", "tr", "br"}:
            self.lines.append("\n")
        if tag == "a":
            self.in_anchor += 1
            attrs = dict(attrs)
            self.anchor_url = attrs.get("href")
            self.anchor_label = []

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            if self.skip_level:
                self.skip_level -= 1
            return
        if self.skip_level:
            return
        if tag == "title" and self.title_level:
            self.title_level -= 1
        if tag in {"h1", "h2", "h3"} and self.heading_level:
            self.heading_level -= 1
        if tag == "a" and self.in_anchor:
            if self.anchor_url:
                full = urljoin(self.base_url, self.anchor_url)
                u = urlsplit(full)
                if u.scheme == "https" and u.username is None and u.password is None and u.hostname and not u.fragment:
                    normalized = full[:450]
                    if normalized not in self.seen_links and len(self.links) < MAX_LINKS:
                        self.links.append({"title": " ".join(self.anchor_label)[:110] or "Ссылка",
                                           "url": normalized})
                        self.seen_links.add(normalized)
            self.in_anchor -= 1
            self.anchor_url = None
            self.anchor_label = []
        if tag in {"p", "div", "li", "section", "article", "tr"}:
            self.lines.append("\n")

    def handle_data(self, data):
        if self.skip_level or not data.strip():
            return
        if self.title_level:
            self.title.append(data)
        if self.heading_level and len(self.headings) < 25:
            clean = " ".join(data.split())
            if clean:
                self.headings.append(clean[:180])
        if self.in_anchor:
            self.anchor_label.append(data.strip())
        if sum(map(len, self.lines[-100:])) < MAX_EXCERPT * 2 and len(self.lines) < 3000:
            self.lines.append(data)

    def output(self) -> dict:
        text = "\n".join(" ".join(x.split()) for x in "".join(self.lines).splitlines())
        text = re.sub(r"\n{3,}", "\n\n", text).strip()[:MAX_EXCERPT]
        return {
            "title": " ".join("".join(self.title).split())[:220],
            "headings": self.headings[:25],
            "text_excerpt": text,
            "links": self.links[:MAX_LINKS],
        }


def _read_page(url: str, allowed_hosts: set[str], *, fetcher=None) -> dict:
    hops = 0
    while True:
        parsed, host = _url_parts(url, allowed_hosts)
        ip = _public_ip(host)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn = _PinnedTLS(host, ip) if fetcher is None else fetcher(host, ip)
        try:
            conn.request("GET", path, headers={
                "Host": host, "User-Agent": "CybernovaReadOnlyResearch/1.0",
                "Accept": "text/html", "Accept-Encoding": "identity",
                "Connection": "close",
            })
            resp = conn.getresponse()
            status = int(resp.status)
            location = resp.getheader("Location")
            if status in (301, 302, 303, 307, 308):
                if hops >= MAX_REDIRECTS or not location:
                    raise ValueError("redirect_budget_exceeded")
                next_url = urljoin(url, location)
                _url_parts(next_url, allowed_hosts)
                url = next_url
                hops += 1
                continue
            ctype = (resp.getheader("Content-Type") or "").lower()
            if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
                raise ValueError("non_html_content")
            encoded = resp.read(MAX_HTML_BYTES + 1)
            if len(encoded) > MAX_HTML_BYTES:
                raise ValueError("html_response_too_large")
            charset = "utf-8"
            match = re.search(r"charset\s*=\s*['\"]?([a-zA-Z0-9_-]+)", ctype)
            if match:
                charset = match.group(1)
            try:
                page = encoded.decode(charset, errors="replace")
            except LookupError:
                page = encoded.decode("utf-8", errors="replace")
            parser = _Visible(url)
            parser.feed(page)
            return {
                "ok": True,
                "url": url,
                "http_status": status,
                "source_sha256": hashlib.sha256(encoded).hexdigest(),
                "content_type": ctype.split(";")[0],
                "rendering": "html_only_no_javascript",
                "redirects": hops,
                **parser.output(),
            }
        finally:
            conn.close()


def browser_call(name: str, args: dict, upstream, *, extra_hosts=None, fetcher=None):
    if name not in BROWSER_NAMES:
        raise ValueError("unknown_browser_tool")
    if not isinstance(args, dict) or set(args) != {"url"}:
        raise ValueError("invalid_browser_arguments")
    gateway, failed = upstream.call("gateway_status", {})
    if failed or not isinstance(gateway, dict):
        raise ValueError("cannot_verify_gateway_scope")
    scoped = gateway.get("authorized_hosts") or []
    if not isinstance(scoped, list):
        raise ValueError("invalid_gateway_scope")
    authorized = {x for x in scoped if isinstance(x, str)}
    # Server owner controls passive browser scope via a deployment setting.
    # User/model supplied URLs cannot extend the allowlist themselves.
    config = os.environ.get("CYBERNOVA_BROWSER_HOSTS", "")
    authorized.update(x.strip() for x in config.split(",") if x.strip())
    authorized.update(extra_hosts or ())
    return _read_page(args["url"], authorized, fetcher=fetcher)
