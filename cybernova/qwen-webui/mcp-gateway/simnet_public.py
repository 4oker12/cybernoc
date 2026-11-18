"""Rate-limited public page observation for SIMNET training only.

One GET per call, fixed host and fixed paths. No redirects, cookies, auth,
parameters, arbitrary methods, request bodies, or HTML execution.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
import ssl
from threading import Lock
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = "simnet.ua"
PAGES = {
    "home": "/",
    "support": "/support",
    "contacts": "/contacts",
    "internet": "/home/internet",
}
MAX_READ = 32768
_COOLDOWN = 5.0
_lock = Lock()
_next_allowed = 0.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _text(value, maximum=140):
    return re.sub(r"\s+", " ", str(value)).strip()[:maximum]


class _PageSummary(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._title_on = False
        self._title_parts = []
        self.links = []
        self.forms = []
        self.generators = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "title":
            self._title_on = True
        elif tag == "meta":
            if (data.get("name") or "").lower() == "generator":
                self.generators.append(_text(data.get("content", "")))
        elif tag == "a" and len(self.links) < 16:
            href = data.get("href", "")
            if href:
                target = urllib.parse.urlsplit(urllib.parse.urljoin("https://simnet.ua/", href))
                if (target.scheme == "https" and target.hostname == HOST
                        and target.username is None and target.password is None
                        and target.port in (None, 443)):
                    path = target.path or "/"
                    if path not in self.links:
                        self.links.append(_text(path, 200))
        elif tag == "form" and len(self.forms) < 8:
            self.forms.append({
                "method": _text(data.get("method", "GET").upper(), 12),
                "action": "[not examined]",
            })

    def handle_endtag(self, tag):
        if tag == "title":
            self._title_on = False

    def handle_data(self, data):
        if self._title_on and len(self._title_parts) < 10:
            self._title_parts.append(data)

    @property
    def title(self):
        return _text("".join(self._title_parts), 180)


def simnet_public_page(page: str = "home") -> dict:
    """Fetch exactly one publicly accessible page of simnet.ua as a training observation."""
    global _next_allowed
    if not isinstance(page, str) or page not in PAGES:
        return {"ok": False, "error": "page_not_allowed", "allowed_pages": sorted(PAGES)}
    with _lock:
        now = time.monotonic()
        if now < _next_allowed:
            return {
                "ok": False,
                "error": "rate_limited",
                "retry_after_seconds": round(_next_allowed - now, 1),
            }
        _next_allowed = now + _COOLDOWN

    url = "https://" + HOST + PAGES[page]
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Cybernova-Research-Lab/0.1 (+public-read-only)",
            "Accept": "text/html,application/xhtml+xml",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    try:
        try:
            response = opener.open(request, timeout=8)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            status = response.getcode()
            content_type = response.headers.get("Content-Type", "")
            security_names = [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Content-Type-Options", "X-Frame-Options",
                "Referrer-Policy", "Permissions-Policy",
            ]
            headers = {
                key.lower(): _text(response.headers.get(key), 250)
                for key in security_names if response.headers.get(key) is not None
            }
            observed = {
                "ok": status == 200,
                "target": "https://simnet.ua" + PAGES[page],
                "http_status": status,
                "redirect_followed": False,
                "content_type": _text(content_type, 120),
                "security_headers": headers,
                "server_header": _text(response.headers.get("Server", ""), 120),
                "set_cookie_header_count": len(response.headers.get_all("Set-Cookie", [])),
                "classification": "public_noninvasive_observation_not_vulnerability_confirmation",
            }
            if status != 200 or "html" not in content_type.lower():
                return observed
            body = response.read(MAX_READ + 1)
            parser = _PageSummary()
            parser.feed(body[:MAX_READ].decode("utf-8", "replace"))
            observed.update({
                "bytes_sampled": min(len(body), MAX_READ),
                "body_truncated": len(body) > MAX_READ,
                "title": parser.title,
                "meta_generators": parser.generators[:3],
                "sample_internal_link_paths": parser.links,
                "form_count_in_sample": len(parser.forms),
            })
            return observed
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "target": url, "error": type(exc).__name__,
                "note": "No additional network request was attempted"}
