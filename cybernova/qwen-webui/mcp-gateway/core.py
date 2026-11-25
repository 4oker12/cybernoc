"""Pure, safe analysis functions. Never execute supplied code or arbitrary URLs."""
import ast
import ipaddress
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def _name(expr):
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        head = _name(expr.value)
        return (head + "." if head else "") + expr.attr
    return ""


def review_python_source(source: str) -> dict:
    if not isinstance(source, str) or len(source.encode("utf-8")) > 64000:
        return {"ok": False, "error": "invalid_source_or_too_large"}
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"ok": False, "error": "syntax_error", "line": exc.lineno}
    indicators = []
    named = {
        "eval": ("CWE-95", "Dynamic expression evaluation"),
        "exec": ("CWE-94", "Dynamic code execution"),
        "os.system": ("CWE-78", "Shell command call"),
        "pickle.load": ("CWE-502", "Deserialization from pickle"),
        "pickle.loads": ("CWE-502", "Deserialization from pickle"),
        "hashlib.md5": ("CWE-327", "Weak hash primitive; verify use"),
        "hashlib.sha1": ("CWE-327", "Weak hash primitive; verify use"),
    }
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        name = _name(n.func)
        rule = named.get(name)
        if name.startswith("subprocess.") and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in n.keywords
        ):
            rule = ("CWE-78", "subprocess shell=True; verify untrusted inputs")
        if name.startswith(("requests.", "httpx.")) and any(
            kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
            for kw in n.keywords
        ):
            rule = ("CWE-295", "TLS certificate verification disabled")
        if name == "yaml.load" and not any(
            kw.arg == "Loader" and "SafeLoader" in _name(kw.value) for kw in n.keywords
        ):
            rule = ("CWE-502", "YAML load without explicit SafeLoader")
        if rule:
            indicators.append({
                "line": n.lineno, "function": name, "cwe": rule[0],
                "signal": rule[1], "confidence": "heuristic_only",
            })
        if len(indicators) >= 100:
            break
    return {
        "ok": True, "parsed": True, "lines": len(source.splitlines()),
        "indicators": sorted(indicators, key=lambda i: i["line"]),
        "classification": "not_confirmed_vulnerabilities",
        "method": "ast_only_no_execution_or_imports",
    }


def review_http_headers(raw_headers: str, scheme: str = "https") -> dict:
    if not isinstance(raw_headers, str) or len(raw_headers.encode("utf-8")) > 16000:
        return {"ok": False, "error": "invalid_headers_or_too_large"}
    if scheme not in ("http", "https"):
        return {"ok": False, "error": "invalid_scheme"}
    headers = {}
    for line in raw_headers.splitlines():
        if not line or line.upper().startswith("HTTP/"):
            continue
        if line[0].isspace() or ":" not in line:
            return {"ok": False, "error": "invalid_header_line"}
        key, val = line.split(":", 1)
        key = key.strip().lower()
        if not re.fullmatch(r"[a-z0-9-]+", key):
            return {"ok": False, "error": "invalid_header_name"}
        headers.setdefault(key, []).append(val.strip())
    expected = ["x-content-type-options", "content-security-policy", "referrer-policy"]
    if scheme == "https":
        expected.append("strict-transport-security")
    missing = [key for key in expected if key not in headers]
    if "x-frame-options" not in headers and "frame-ancestors" not in " ".join(
        headers.get("content-security-policy", [])
    ).lower():
        missing.append("x-frame-options/frame-ancestors")
    cookies = []
    for raw in headers.get("set-cookie", [])[:20]:
        attrs = [v.strip().split("=", 1)[0].lower() for v in raw.split(";")[1:]]
        name = raw.split(";", 1)[0].split("=", 1)[0].strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            name = "[redacted]"
        cookies.append({
            "name": name, "secure": "secure" in attrs,
            "httponly": "httponly" in attrs, "samesite": "samesite" in attrs,
        })
    return {
        "ok": True, "scheme": scheme, "header_names": sorted(headers),
        "missing_review_candidates": missing, "cookie_flags": cookies,
        "classification": "configuration_hints_only",
        "note": "Values and cookie secrets are never returned. No network requests.",
    }


def summarize_network(cidr: str) -> dict:
    if not isinstance(cidr, str) or len(cidr) > 80:
        return {"ok": False, "error": "invalid_cidr"}
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {"ok": False, "error": "invalid_cidr"}
    return {
        "ok": True, "network": str(net), "ip_version": net.version,
        "addresses": str(net.num_addresses), "netmask": str(net.netmask),
        "is_private": net.is_private, "is_global": net.is_global,
        "network_requests": 0,
    }


def check_local_webui(url: str = "http://127.0.0.1:18794/api/status") -> dict:
    """Probe the local Console API without credentials, redirects or proxies.

    HTTP reachability and application/MCP readiness are reported separately.
    The access gateway on 18795 is intentionally not probed because it requires
    the owner's Basic-auth credential; the legacy Open WebUI port 18791 is gone.
    """
    base = {
        "ok": False, "checked_url": url, "listener": "unknown",
        "layer": "tcp", "http_status": None, "mcp_ready": None,
        "reason": "connection_error", "network_requests": 1,
    }
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}
                or parsed.username or parsed.password or parsed.fragment):
            return {**base, "reason": "invalid_local_url", "network_requests": 0}
    except (TypeError, ValueError):
        return {**base, "reason": "invalid_local_url", "network_requests": 0}

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    )
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with opener.open(req, timeout=4) as response:
            status = int(response.status)
            body = response.read(65537)
        if len(body) > 65536:
            return {**base, "listener": "up", "layer": "http",
                    "http_status": status, "reason": "response_too_large"}
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {**base, "listener": "up", "layer": "app",
                    "http_status": status, "reason": "invalid_status_payload"}
        if not isinstance(payload, dict):
            return {**base, "listener": "up", "layer": "app",
                    "http_status": status, "reason": "invalid_status_payload"}
        mcp_ready = payload.get("mcp_ready")
        if type(mcp_ready) is not bool:
            mcp_ready = None
        ready = status == 200 and mcp_ready is True
        return {
            **base, "ok": ready, "listener": "up",
            "layer": "app" if status == 200 else "http",
            "http_status": status, "mcp_ready": mcp_ready,
            "reason": "ok" if ready else "mcp_unavailable" if status == 200 else
                      "http_5xx" if status >= 500 else "http_status",
        }
    except urllib.error.HTTPError as exc:
        reason = "http_401" if exc.code == 401 else "http_5xx" if exc.code >= 500 else "http_status"
        return {**base, "listener": "up", "layer": "http",
                "http_status": exc.code, "reason": reason}
    except urllib.error.URLError as exc:
        cause = exc.reason
        if isinstance(cause, ConnectionRefusedError):
            return {**base, "listener": "absent", "layer": "tcp",
                    "reason": "connection_refused"}
        if isinstance(cause, (TimeoutError, OSError)) and "timed out" in str(cause).lower():
            return {**base, "listener": "unknown", "layer": "tcp", "reason": "timeout"}
        return {**base, "listener": "unknown", "layer": "tcp", "reason": "connection_error"}
    except ConnectionRefusedError:
        return {**base, "listener": "absent", "layer": "tcp",
                "reason": "connection_refused"}
    except TimeoutError:
        return {**base, "listener": "unknown", "layer": "tcp", "reason": "timeout"}
    except OSError:
        return {**base, "listener": "unknown", "layer": "tcp", "reason": "connection_error"}
