"""Generic, bounded, read-only HTTP GET tool for approved public websites.

Authorization is configured in scope.json, not in the tool implementation.
One direct GET, no redirects, no proxies, no cookies, no credentials, no
arbitrary headers, no form submission, no script execution. DNS is pinned to
a validated public address to avoid changing to internal destinations.
"""
from __future__ import annotations

from html.parser import HTMLParser
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit

_SCOPE = Path(__file__).with_name("scope.json")
_MAX_URL = 2048
_MAX_BYTES = 32768
_lock = threading.Lock()
_next_allowed = 0.0


def _clean(v, n=220):
    return re.sub(r"\s+", " ", str(v)).strip()[:n]


def _load_scope():
    try:
        config = json.loads(_SCOPE.read_text(encoding="utf-8"))
        hosts = config.get("allowed_hosts", [])
        if not isinstance(hosts, list):
            return set()
        return {
            host.lower() for host in hosts
            if isinstance(host, str)
            and re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", host.lower())
        }
    except (ValueError, OSError, TypeError):
        return set()


def _validate_url(url):
    if not isinstance(url, str) or not 1 <= len(url.encode("utf-8")) <= _MAX_URL:
        return None, "invalid_url"
    if re.search(r"[\x00-\x20\x7f]", url) or "\\" in url:
        return None, "invalid_url"
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        return None, "invalid_url"
    if u.scheme not in {"http", "https"} or not host or not u.netloc:
        return None, "invalid_url"
    if u.username is not None or u.password is not None or u.fragment:
        return None, "invalid_url"
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", host):
        return None, "invalid_hostname"
    default_port = 443 if u.scheme == "https" else 80
    if port not in (None, default_port):
        return None, "disallowed_port"
    if host not in _load_scope():
        return None, "host_not_authorized"
    return (u, host, default_port), None


def _public_ip(host, port):
    """Resolve once; fail closed on *any* nonpublic address, pin the chosen IP."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = []
    for entry in infos:
        address = entry[4][0]
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError("nonpublic_dns_result")
        if address not in ips:
            ips.append(address)
    if not ips:
        raise ValueError("empty_dns_result")
    # Favor IPv4 when both families exist: common GPU hosting has IPv4 egress.
    return sorted(ips, key=lambda item: ipaddress.ip_address(item).version != 4)[0]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, address, port):
        super().__init__(host, port=port, timeout=8)
        self._pinned = address

    def connect(self):
        self.sock = socket.create_connection((self._pinned, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, port):
        super().__init__(host, port=port, timeout=8, context=ssl.create_default_context())
        self._pinned = address

    def connect(self):
        raw = socket.create_connection((self._pinned, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class _Page(HTMLParser):
    def __init__(self, base, host):
        super().__init__(convert_charrefs=True)
        self.base, self.host = base, host
        self._inside_title = False
        self.title_bits = []
        self.paths = []
        self.generators = []
        self.form_count = 0

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "title":
            self._inside_title = True
        if tag == "meta" and (data.get("name") or "").lower() == "generator":
            if len(self.generators) < 4:
                self.generators.append(_clean(data.get("content", ""), 120))
        if tag == "form":
            self.form_count += 1
        if tag == "a" and len(self.paths) < 20:
            href = data.get("href", "")
            if not href:
                return
            try:
                target = urlsplit(urljoin(self.base, href))
                if (target.hostname or "").lower() == self.host and target.scheme in {"http", "https"}:
                    path = target.path or "/"
                    if path not in self.paths:
                        self.paths.append(_clean(path, 180))
            except ValueError:
                return

    def handle_endtag(self, tag):
        if tag == "title":
            self._inside_title = False

    def handle_data(self, data):
        if self._inside_title and len(self.title_bits) < 10:
            self.title_bits.append(data)

    @property
    def title(self):
        return _clean("".join(self.title_bits), 180)


def http_get(url: str) -> dict:
    """Read one publicly accessible URL within the configured authorized scope."""
    global _next_allowed
    parsed, error = _validate_url(url)
    if error:
        return {"ok": False, "error": error}
    with _lock:
        now = time.monotonic()
        if now < _next_allowed:
            return {"ok": False, "error": "rate_limited",
                    "retry_after_seconds": round(_next_allowed - now, 1)}
        _next_allowed = now + 5.0

    u, host, port = parsed
    # URL is sanitized: query values are not returned in observations.
    visible = u.scheme + "://" + host + (u.path or "/")
    try:
        address = _public_ip(host, port)
        conn_class = _PinnedHTTPS if u.scheme == "https" else _PinnedHTTP
        conn = conn_class(host, address, port)
        try:
            target = (u.path or "/") + (("?" + u.query) if u.query else "")
            conn.request("GET", target, headers={
                "User-Agent": "Cybernova-Lab/0.2 (approved-public-read-only)",
                "Accept": "text/html,application/xhtml+xml",
                "Connection": "close",
            })
            response = conn.getresponse()
            headers = response.headers
            status = response.status
            content_type = headers.get("Content-Type", "")
            observed = {
                "ok": status == 200,
                "url": visible,
                "http_status": status,
                "method": "GET",
                "redirect_followed": False,
                "content_type": _clean(content_type, 130),
                "server_header": _clean(headers.get("Server", ""), 100),
                "security_headers": {
                    k.lower(): _clean(headers.get(k), 240)
                    for k in (
                        "Strict-Transport-Security", "Content-Security-Policy",
                        "X-Content-Type-Options", "X-Frame-Options",
                        "Referrer-Policy", "Permissions-Policy",
                    ) if headers.get(k) is not None
                },
                "set_cookie_header_count": len(headers.get_all("Set-Cookie", [])),
                "classification": "public_metadata_not_vulnerability_proof",
            }
            if status == 200 and "html" in content_type.lower():
                body = response.read(_MAX_BYTES + 1)
                page = _Page(visible, host)
                page.feed(body[:_MAX_BYTES].decode("utf-8", "replace"))
                observed.update({
                    "title": page.title,
                    "meta_generators": page.generators,
                    "sample_internal_paths": page.paths,
                    "form_count_in_sample": page.form_count,
                    "bytes_sampled": min(len(body), _MAX_BYTES),
                    "body_truncated": len(body) > _MAX_BYTES,
                })
            return observed
        finally:
            conn.close()
    except (socket.gaierror, OSError, TimeoutError, ssl.SSLError,
            http.client.HTTPException, ValueError) as exc:
        return {"ok": False, "url": visible, "error": type(exc).__name__,
                "note": "No retry or alternate destination attempted"}
