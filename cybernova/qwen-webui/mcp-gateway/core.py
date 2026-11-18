"""Pure, safe analysis functions. Never execute supplied code or arbitrary URLs."""
import ast
import ipaddress
import re
import urllib.error
import urllib.request


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


def check_local_webui() -> dict:
    """The ONLY network tool: fixed localhost:18791, no redirects or proxy."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    )
    req = urllib.request.Request("http://127.0.0.1:18791/", method="GET")
    try:
        with opener.open(req, timeout=4) as response:
            return {"ok": response.status == 200, "http_status": response.status}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "http_status": exc.code}
    except (urllib.error.URLError, OSError, TimeoutError):
        return {"ok": False, "error": "localhost_webui_unavailable"}
