"""Manual live E2E: configured DeepSeek must operate real isolated Patchright Chromium.

The test uses a temporary loopback-only fixture site and the already-running
Cybernova API. It does not visit public sites, use accounts, or submit forms.

Run from the research-platform directory:
    python tests/browser_agent_e2e.py

Optional API override:
    CYBERNOVA_E2E_API_URL=http://127.0.0.1:18794/api/chat
"""
from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener


LONG_TEXT = "Research context. " * 500
API_URL = os.environ.get(
    "CYBERNOVA_E2E_API_URL",
    "http://127.0.0.1:18794/api/chat",
)


class Fixture(BaseHTTPRequestHandler):
    requests: list[str] = []

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.requests.append(self.path)
        if self.path == "/":
            html = """<!doctype html><title>Atlas home</title><main>
                <h1>Atlas research portal</h1>
                <p>Choose the archive section.</p>
                <a href="/archive">Archive</a></main>"""
        elif self.path == "/archive":
            html = """<!doctype html><title>Atlas archive</title><main>
                <h1>Archive</h1><p>Old releases and technical records.</p>
                <a href="/archive/2026">2026 records</a></main>"""
        elif self.path == "/archive/2026":
            html = """<!doctype html><title>Atlas records</title><main>
                <h1>2026 records</h1><p>""" + LONG_TEXT + """</p>
                <p>FINAL_ARCHIVE_MARKER: orbital-cedar-71</p>
                <table><tr><th>Service</th><th>Region</th><th>Code</th></tr>
                <tr><td>Atlas</td><td>eu-central</td><td>AC-42</td></tr></table>
                <label for="q">Record search</label><input id="q">
                <button onclick="document.getElementById('result').textContent =
                  document.getElementById('q').value === 'status'
                  ? 'SEARCH_RESULT: active' : 'SEARCH_RESULT: none'">Search records</button>
                <p id="result"></p></main>"""
        else:
            self.send_error(404)
            return
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def _validate_local_api() -> None:
    parsed = urlsplit(API_URL)
    if parsed.scheme != "http" or parsed.hostname not in {
        "127.0.0.1", "localhost", "::1",
    } or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit(
            "Refusing non-loopback API URL. Set CYBERNOVA_E2E_API_URL to a local "
            "Cybernova /api/chat endpoint only."
        )


def main() -> None:
    _validate_local_api()
    Fixture.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    prompt = (
        f"Самостоятельно исследуй тестовый сайт {origin}/ в настоящем браузере. "
        "Начни с главной страницы, сам найди архив за 2026 год через ссылки. "
        "Прочитай страницу полностью, включая конец длинного текста. "
        "Найди маркер FINAL_ARCHIVE_MARKER и код Atlas в таблице. "
        "На странице архива введи status в поле Record search, нажми Search records "
        "и проверь появившийся результат. В ответе укажи маркер, код, результат "
        "поиска и конечный URL. Используй браузерные инструменты; не угадывай."
    )
    body = json.dumps({
        "message": prompt,
        "tool_groups": ["browser"],
    }).encode("utf-8")
    request = Request(
        API_URL,
        body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=300) as response:
            outcome = json.load(response)
        if not isinstance(outcome, dict):
            raise SystemExit("Cybernova API returned a non-object response.")
        events = outcome.get("events") or []
        tool_events = [
            event for event in events
            if isinstance(event, dict) and event.get("type") == "tool_result"
        ]
        tool_names = [
            event.get("name") or event.get("tool")
            for event in tool_events
        ]
        required = {
            "browser_navigate", "browser_snapshot", "browser_follow_link",
            "browser_read_page", "browser_read_table", "browser_fill",
            "browser_click_button",
        }
        answer = str(outcome.get("answer") or "")
        required_events = [
            event for event in tool_events
            if (event.get("name") or event.get("tool")) in required
        ]
        checks = {
            "navigated_archive": "/archive" in Fixture.requests,
            "navigated_2026": "/archive/2026" in Fixture.requests,
            "required_browser_tools": required.issubset(set(tool_names)),
            "required_browser_tools_succeeded": (
                len(required_events) >= len(required)
                and all(event.get("is_error") is False for event in required_events)
            ),
            "long_page_marker": "orbital-cedar-71" in answer,
            "table_code": "AC-42" in answer,
            "dynamic_search_result": "active" in answer.lower(),
            "final_url": origin + "/archive/2026" in answer,
        }
        report = {
            "passed": all(checks.values()),
            "checks": checks,
            "model": outcome.get("model"),
            "tool_calls": outcome.get("tool_calls"),
            "tools": tool_names,
            "fixture_gets": Fixture.requests,
            "usage": outcome.get("usage"),
            "answer_excerpt": answer[:1200],
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if not all(checks.values()):
            raise SystemExit(1)
    except HTTPError as exc:
        detail = exc.read(500).decode("utf-8", errors="replace")
        detail = re.sub(
            r"(?i)(api[_-]?key|token|password|authorization)([\"' :=]+)[^\"' ,}]+",
            r"\1\2[REDACTED]", detail,
        )
        print(json.dumps({
            "passed": False,
            "error": f"Cybernova API returned HTTP {exc.code}",
            "detail": detail[:500],
        }, ensure_ascii=False, indent=2))
        raise SystemExit(2) from None
    except URLError as exc:
        print(json.dumps({
            "passed": False,
            "error": "Cybernova API is unreachable",
            "reason": type(exc.reason).__name__,
        }, ensure_ascii=False, indent=2))
        raise SystemExit(3) from None
    finally:
        server.shutdown()
        worker.join(timeout=3)
        server.server_close()


if __name__ == "__main__":
    main()
