"""Authenticated, loopback-only HTTP access bridge for Cybernova Chat.

Routes a strictly limited Web UI path set to the console on 127.0.0.1:18794.
It never proxies the Communication MCP, Ollama, or the Tool MCP. The intended
upstream is a Cloudflare Quick Tunnel, which provides TLS but not authentication.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .upload_limits import MAX_IMPORT_HTTP_BODY_BYTES, MAX_PROXY_RESPONSE_BYTES
    from .diagnostics import configure as configure_diagnostics, export_jsonl, failure as log_failure
except ImportError:
    from upload_limits import MAX_IMPORT_HTTP_BODY_BYTES, MAX_PROXY_RESPONSE_BYTES
    from diagnostics import configure as configure_diagnostics, export_jsonl, failure as log_failure

DEFAULT_PORT = 18795
DEFAULT_SECRET_FILE = "/workspace/cybernova-comm-private/web_access.txt"
ALLOWED_STATIC = frozenset({"/", "/static/styles.css", "/static/design-system.css",
    "/static/app.js", "/static/markdown.js", "/static/ux.css", "/static/ux.js",
    "/static/model-settings.js"})
ALLOWED_GET = frozenset({"/api/status", "/api/comm/tasks", "/api/comm/events",
    "/api/comm/review-packet", "/api/comm/evidence", "/api/siwc/status",
    "/api/siwc/models", "/api/siwc/chats", "/api/siwc/chat", "/api/research/scope", "/api/profile-settings", "/api/model-config",
    "/api/collab/runs", "/api/collab/run", "/auth/callback",
    "/api/diagnostics/export"})
ALLOWED_POST = frozenset({
    "/api/chat", "/api/import", "/api/approve", "/api/followups",
    "/api/reset", "/api/research/scope", "/api/comm/resume", "/api/comm/reviewer-feedback",
    "/api/siwc/start", "/api/siwc/disconnect", "/api/siwc/review", "/api/siwc/chat",
    "/api/profile-settings", "/api/model-config", "/api/collab/start", "/api/collab/step",
    "/api/collab/stop", "/api/collab/resume", "/api/collab/finish", "/api/tools/run",
})
HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "authorization", "host",
    "origin", "content-length", "accept-encoding",
})
MAX_NORMAL_REQUEST_BODY = 7_000_000


def read_credentials(path: str | Path) -> tuple[str, str]:
    raw = Path(path).read_text(encoding="utf-8").splitlines()
    if len(raw) != 2 or not raw[0] or len(raw[1]) < 24:
        raise ValueError("invalid_web_access_credential_file")
    return raw[0], raw[1]


def authorized(header: str | None, credentials: tuple[str, str]) -> bool:
    if not header or not header.startswith("Basic "):
        return False
    try:
        cleartext = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return False
    expected = credentials[0] + ":" + credentials[1]
    return hmac.compare_digest(cleartext, expected)


def allowed_path(path: str, method: str) -> bool:
    if path.startswith("//") or "\\" in path or "\x00" in path:
        return False
    route = urlsplit(path).path
    if method == "GET":
        return route in ALLOWED_STATIC or route in ALLOWED_GET
    if method == "POST":
        return route in ALLOWED_POST
    return False


def _normalized_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if (scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment):
            return None
        hostname = parsed.hostname.lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, hostname, port
    except (TypeError, ValueError):
        return None


def origin_allowed(origin: str | None, host: str | None) -> bool:
    if not origin:
        return True
    if not isinstance(host, str) or not host or any(c in host for c in "\r\n/@\\"):
        return False
    try:
        host_parts = urlsplit("//" + host)
        if (not host_parts.hostname or host_parts.username is not None
                or host_parts.password is not None or host_parts.path
                or host_parts.query or host_parts.fragment):
            return False
        hostname = host_parts.hostname.lower().rstrip(".")
        host_port = host_parts.port
    except ValueError:
        return False

    normalized = _normalized_origin(origin)
    if normalized is None:
        return False
    scheme, origin_host, origin_port = normalized
    if origin_host != hostname:
        return False
    expected_port = host_port or (443 if scheme == "https" else 80)
    if expected_port != origin_port:
        return False

    if hostname in {"127.0.0.1", "localhost"}:
        return host_port == 18795 and origin_port == 18795
    return (
        hostname.endswith(".trycloudflare.com")
        and scheme == "https"
        and origin_port == 443
        and host_port in {None, 443}
    )


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "CybernovaAccess/1"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def log_message(self, format, *args):
        # Do not log URLs or Authorization headers (including any query).
        pass

    def _send(self, code: int, content: bytes = b"", *,
              challenge: bool = False, content_type: str = "text/plain",
              download_name: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        if download_name:
            self.send_header("Content-Disposition", 'attachment; filename="' + download_name + '"')
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        if challenge:
            self.send_header("WWW-Authenticate", 'Basic realm="Cybernova Chat", charset="UTF-8"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def _handle(self):
        credentials = self.server.credentials
        if not authorized(self.headers.get("Authorization"), credentials):
            return self._send(401, b"Cybernova authentication required\n",
                              challenge=True)
        route = urlsplit(self.path).path
        if not allowed_path(self.path, self.command):
            return self._send(404, b"Not found\n")
        if not origin_allowed(self.headers.get("Origin"), self.headers.get("Host")):
            return self._send(403, b"Invalid origin\\n")
        if self.command == "GET" and route == "/api/diagnostics/export":
            try:
                journal = export_jsonl()
            except Exception as exc:
                log_failure("access-gateway", "diagnostics_export", exc)
                return self._send(503, b"Diagnostic journal unavailable\\n")
            return self._send(
                200, journal, content_type="application/x-ndjson; charset=utf-8",
                download_name="cybernova-diagnostics.jsonl",
            )
        length_str = self.headers.get("Content-Length")
        if self.command == "POST":
            if length_str is None or not length_str.isascii() or not length_str.isdigit():
                return self._send(411, b"Content-Length required\n")
            length = int(length_str)
            limit = (MAX_IMPORT_HTTP_BODY_BYTES if route == "/api/import"
                     else MAX_NORMAL_REQUEST_BODY)
            if length > limit:
                return self._send(413, b"Payload too large\n")
            body = self.rfile.read(length)
            if len(body) != length:
                return self._send(400, b"Incomplete body\n")
        else:
            body = None

        headers = {
            key: value for key, value in self.headers.items()
            if key.lower() not in HOP_HEADERS
        }
        headers["Host"] = "127.0.0.1:18794"
        headers["Accept-Encoding"] = "identity"
        if self.headers.get("Origin"):
            headers["Origin"] = "http://127.0.0.1:18794"
        if body is not None:
            headers["Content-Length"] = str(len(body))
        conn = http.client.HTTPConnection("127.0.0.1", 18794, timeout=240)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse()
            content = response.read(MAX_PROXY_RESPONSE_BYTES + 1)
            if len(content) > MAX_PROXY_RESPONSE_BYTES:
                return self._send(502, b"Upstream response too large\n")
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() in HOP_HEADERS or key.lower() in {
                    "server", "date", "content-security-policy-report-only",
                    "set-cookie", "content-length",
                }:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Robots-Tag", "noindex, nofollow")
            self.end_headers()
            self.wfile.write(content)
        except (OSError, TimeoutError, http.client.HTTPException):
            try:
                self._send(502, b"Cybernova backend unavailable\n")
            except OSError:
                pass
        finally:
            conn.close()

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_HEAD(self):
        self._send(405, b"Method not allowed\n")

    def do_OPTIONS(self):
        self._send(405, b"Method not allowed\n")


def serve(port: int = DEFAULT_PORT, secret_file: str = DEFAULT_SECRET_FILE):
    credentials = read_credentials(secret_file)
    bind_host = os.environ.get("CYBERNOVA_ACCESS_HOST", "127.0.0.1")
    if bind_host not in {"127.0.0.1", "0.0.0.0"}:
        raise ValueError("invalid_access_bind_host")
    server = ThreadingHTTPServer((bind_host, port), GatewayHandler)
    server.credentials = credentials
    print("CYBERNOVA_ACCESS_READY port=" + str(port), flush=True)
    server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    configure_diagnostics("access-gateway")
    serve(
        int(os.environ.get("CYBERNOVA_ACCESS_PORT", str(DEFAULT_PORT))),
        os.environ.get("CYBERNOVA_ACCESS_SECRET_FILE", DEFAULT_SECRET_FILE),
    )
