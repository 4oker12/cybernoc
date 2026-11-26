"""Manual end-to-end test: the configured model must drive real Patchright Chromium.

Run against a locally started CyberNova console. The fixture stays on loopback;
the prompt supplies its exact URL as the authorized browser target.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import urllib.error
import urllib.request


LONG_TEXT = "Research context. " * 500


class Fixture(BaseHTTPRequestHandler):
    requests: list[str] = []

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.requests.append(self.path)
        if self.path == "/":
            html = """<!doctype html><title>Atlas home</title><main>
                <h1>Atlas research portal</h1><p>Choose the archive section.</p>
                <a href='/archive'>Archive</a></main>"""
        elif self.path == "/archive":
            html = """<!doctype html><title>Atlas archive</title><main>
                <h1>Archive</h1><p>Old releases and technical records.</p>
                <a href='/archive/2026'>2026 records</a></main>"""
        elif self.path == "/archive/2026":
            html = """<!doctype html><title>Atlas records</title><main>
                <h1>2026 records</h1><p>""" + LONG_TEXT + """</p>
                <p>FINAL_ARCHIVE_MARKER: orbital-cedar-71</p>
                <table><tr><th>Service</th><th>Region</th><th>Code</th></tr>
                <tr><td>Atlas</td><td>eu-central</td><td>AC-42</td></tr></table>
                <label for='q'>Record search</label><input id='q'>
                <button onclick="document.getElementById('result').textContent =
                  document.getElementById('q').value === 'status'
                  ? 'SEARCH_RESULT: active' : 'SEARCH_RESULT: none'">Search records</button>
                <p id='result'></p></main>"""
        else:
            self.send_error(404)
            return
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    prompt = (
        f"Самостоятельно исследуй тестовый сайт {origin}/ в настоящем браузере. "
        "Начни с главной страницы, сам найди архив за 2026 год через ссылки. "
        "Прочитай страницу полностью, включая конец длинного текста. "
        "Найди маркер FINAL_ARCHIVE_MARKER и код Atlas в таблице. "
        "На странице архива введи status в поле Record search, нажми Search records "
        "и проверь появившийся результат. В ответе укажи маркер, код, результат "
        "поиска и конечный URL. Не угадывай: используй браузерные инструменты."
    )
    body = json.dumps({"message": prompt, "tool_groups": ["browser"]}).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:18794/api/chat", body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=240) as response:
            outcome = json.load(response)
        events = outcome.get("events") or []
        tool_names = [e.get("tool") or e.get("name") for e in events if isinstance(e, dict)]
        answer = str(outcome.get("answer", ""))
        checks = {
            "navigated_archive": "/archive" in Fixture.requests,
            "navigated_2026": "/archive/2026" in Fixture.requests,
            "browser_steps": all(name in tool_names for name in (
                "browser_navigate", "browser_follow_link", "browser_read_page",
                "browser_read_table", "browser_fill", "browser_click_button",
            )),
            "marker": "orbital-cedar-71" in answer,
            "table_code": "AC-42" in answer,
            "search_result": "active" in answer.lower(),
            "final_url": origin + "/archive/2026" in answer,
        }
        print(json.dumps({
            "checks": checks, "passed": all(checks.values()),
            "tool_calls": outcome.get("tool_calls"), "tools": tool_names,
            "fixture_gets": Fixture.requests,
            "answer_excerpt": answer[:1500],
            "session_id": outcome.get("session_id"),
        }, ensure_ascii=True, indent=2))
        if not all(checks.values()):
            raise SystemExit(1)
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read(600).decode(errors='replace')}")
        raise SystemExit(2) from None
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
