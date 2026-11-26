"""Manual Chromium smoke for the agent's page orientation and navigation tools."""
from __future__ import annotations

import os
from pathlib import Path
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console"))
from browser_control import BrowserSession  # noqa: E402


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/next":
            html = "<title>Second page</title><main><h1>Second page</h1><p>Pagination reached</p></main>"
        else:
            html = """<!doctype html><title>Orientation fixture</title>
            <nav aria-label="Site menu"><a href="/next">Next page</a></nav>
            <main><h1>Research title</h1><h2>Data</h2>
            <p>FIRST_MARKER</p><p>""" + ("Long visible paragraph. " * 400) + """</p>
            <p>LAST_MARKER</p>
            <table><tr><th>Item</th><th>Result</th></tr>
            <tr><td>Alpha</td><td>Verified</td></tr></table>
            <button onclick="document.getElementById('dynamic').textContent='DYNAMIC_MARKER'">Load more</button>
            <button onclick="if(confirm('Continue this local test?')) document.getElementById('confirmed').textContent='CONFIRMED_MARKER'">JS dialog</button>
            <label>Search <input id="query" aria-label="Search"></label>
            <label>Mode <select aria-label="Mode"><option>Alpha</option><option>Beta</option></select></label>
            <button onclick="document.getElementById('echo').textContent='FORM_'+document.getElementById('query').value+'_'+document.querySelector('select').value">Echo form</button>
            <p id="dynamic"></p><p id="confirmed"></p>
            <p id="echo"></p>
            <div contenteditable="true" role="textbox" aria-label="Draft">SECRET_CANARY_DO_NOT_RETURN</div>
            <input aria-label="Private draft" value="SECRET_INPUT_DO_NOT_RETURN">
            <input aria-label="Duplicate"><input aria-label="Duplicate"></main>"""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    os.environ["CYBERNOVA_GPT_BROWSER_EPHEMERAL"] = "1"
    session = BrowserSession(headless=True)
    session.set_authorized_hosts({"127.0.0.1"})
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        page = session.call("browser_navigate", {"url": origin + "/"})
        assert session._backend == "patchright", f"unexpected backend: {session._backend}"
        assert page["http_status"] == 200 and page["title"] == "Orientation fixture"
        assert page["headings"][0]["text"] == "Research title"
        assert page["content_stats"]["excerpt_truncated"]
        assert page["tables"][0]["headers"] == ["Item", "Result"]
        assert page["links"][0]["kind"] == "internal"
        assert "SECRET_CANARY" not in str(page) and "SECRET_INPUT" not in str(page)
        parts = []
        offset = 0
        while True:
            chunk = session.call("browser_read_page", {"offset": offset})
            parts.append(chunk["text"])
            if chunk["next_offset"] is None:
                assert chunk["complete"]
                break
            offset = chunk["next_offset"]
        assert "FIRST_MARKER" in "".join(parts) and "LAST_MARKER" in "".join(parts)
        assert "SECRET_CANARY" not in "".join(parts)
        table = session.call("browser_read_table", {"frame_index": 0, "table_index": 0, "row_offset": 0})
        assert table["complete"] and table["rows"][1] == ["Alpha", "Verified"]
        session.call("browser_click_button", {"name": "Load more"})
        dynamic = session.call("browser_find_text", {"query": "DYNAMIC_MARKER", "max_matches": 5})
        assert dynamic["matches"]
        dismissed = session.call("browser_click_button", {"name": "JS dialog"})
        assert dismissed["dialogs"][-1]["action"] == "dismiss"
        accepted = session.call("browser_click_button", {"name": "JS dialog", "dialog_action": "accept"})
        assert accepted["dialogs"][-1]["action"] == "accept"
        assert session.call("browser_find_text", {"query": "CONFIRMED_MARKER", "max_matches": 5})["matches"]
        fill_result = session.call("browser_fill", {"label": "Search", "value": "sample", "human_like": False})
        filled_value = session._executor.submit(lambda: session._page.locator("#query").input_value()).result()
        assert fill_result["ok"] and filled_value == "sample"
        try:
            session.call("browser_fill", {"label": "Duplicate", "value": "must-not-fill"})
            raise AssertionError("ambiguous field unexpectedly accepted")
        except ValueError as exc:
            assert "browser_field_not_unique" in str(exc)
        select_result = session.call("browser_select", {"label": "Mode", "value": "Beta"})
        click_result = session.call("browser_click_button", {"name": "Echo form"})
        found = session.call("browser_find_text", {"query": "FORM_sample_Beta", "max_matches": 5})
        assert select_result["ok"] and click_result["ok"]
        assert found["matches"]
        assert session.call("browser_scroll", {"direction": "down", "pixels": 500})["ok"]
        shot = session.call("browser_screenshot", {})
        assert shot["ok"] and shot["image_data_url"].startswith("data:image/jpeg;base64,")
        next_page = session.call("browser_follow_link", {"name": "Next page"})
        assert "Pagination reached" in next_page["visible_text"]
        back = session.call("browser_back", {})
        assert back["title"] == "Orientation fixture"
        assert session.call("browser_forward", {})["title"] == "Second page"
        assert session.call("browser_back", {})["title"] == "Orientation fixture"
        assert session.call("browser_reload", {})["title"] == "Orientation fixture"
        second_tab = session.call("browser_new_tab", {"url": origin + "/next"})
        assert second_tab["title"] == "Second page"
        tabs = session.call("browser_tabs", {})
        assert tabs["ok"] and len(tabs["tabs"]) == 2
        assert session.call("browser_switch_tab", {"index": 0})["title"] == "Orientation fixture"
        assert session.call("browser_close_tab", {"index": 1})["ok"]
        print("PASS Chromium: orientation, full text, table, forms, dynamic DOM, dialogs, redaction, screenshot, pagination, history, tabs")
    finally:
        session.close()
        os.environ["CYBERNOVA_GPT_BROWSER_EPHEMERAL"] = "0"
        with TemporaryDirectory(prefix="cybernova-visible-smoke-") as profile:
            visible = BrowserSession(headless=True, profile_dir=profile)
            visible.set_authorized_hosts({"127.0.0.1"})
            try:
                visible.call("browser_navigate", {"url": origin + "/"})
                handoff = visible.call("browser_show", {})
                assert handoff["visible_window"] and handoff["title"] == "Orientation fixture"
                print("PASS Chromium: persistent profile reopened in visible window for owner handoff")
            finally:
                visible.close()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
