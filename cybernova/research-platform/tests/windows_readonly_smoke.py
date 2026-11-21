"""Windows smoke probe for the shared Cybernova READ-ONLY tool runtime.

This only tests an ephemeral GitHub Actions Windows runner; it never accesses the
user's laptop. No scans, installs, moves, deletes or security changes are invoked.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console.gpt_tool_runtime import GPTToolRuntime
from console.agent import Agent

def summary(name, result, failed, *, detail=None):
    outcome = "PASS" if not failed and result.get("ok", False) else "WARN"
    text = {"test": name, "status": outcome}
    if detail:
        text.update(detail)
    if outcome == "WARN":
        text["error"] = str(result.get("error") or result.get("reason") or "tool_reported_failure")[:160]
    print(json.dumps(text, ensure_ascii=False, sort_keys=True), flush=True)
    return outcome == "PASS"

class StubMCP:
    def initialize(self):
        return []
    def call(self, *_):
        return {"ok": False, "error": "unexpected_external_mcp"}, True

class StubModel:
    model = "deepseek-tool-wiring-smoke"
    def __init__(self):
        self.round = 0
        self.advertised = []
    def chat(self, messages, tools=None, **_):
        self.advertised = tools or []
        self.round += 1
        if self.round == 1:
            return {"content": "", "tool_calls": [{
                "function": {"name": "terminal_status", "arguments": {}},
            }]}
        return {"content": "Tool result processed.", "tool_calls": []}

def run():
    assert platform.system() == "Windows", "This probe only supports Windows"
    runtime = GPTToolRuntime()
    catalog = {row["name"] for row in runtime.mcp_tools()}
    required = {
        "terminal_status", "terminal_run", "computer_system_overview",
        "computer_performance_snapshot", "computer_process_list",
        "computer_disk_overview", "computer_service_overview",
        "computer_installed_programs", "computer_startup_items",
        "computer_defender_status", "computer_defender_events",
        "computer_file_hash", "computer_list_directory",
        "computer_search_files", "computer_ui_windows",
        "browser_navigate", "browser_snapshot", "browser_follow_link",
        "browser_network", "google_search", "research_source_open",
    }
    assert required.issubset(catalog), sorted(required - catalog)
    print(json.dumps({"test": "shared_catalog", "status": "PASS", "count": len(catalog)}))
    failures = []
    warnings = []
    def call(name, args=None, *, important=False, detail=None):
        args = args or {}
        try:
            result, failed = runtime.call(name, args)
        except Exception as exc:
            result, failed = {"ok": False, "error": type(exc).__name__}, True
        passed = summary(name, result, failed, detail=detail(result) if detail else None)
        if not passed:
            (failures if important else warnings).append(name)
        return result

    try:
        status = call("terminal_status", important=True)
        assert status.get("cmd_exe"), "Windows CMD unavailable"
        assert status.get("computer_tool_dependencies", {}).get("psutil"), "psutil missing"
        for cmd in (
            "systeminfo", "tasklist /fo csv", "powercfg /getactivescheme",
        ):
            call("terminal_run", {"command": cmd}, important=True,
                 detail=lambda x: {"exit_code": x.get("exit_code")})

        system = call("computer_system_overview", important=True,
                      detail=lambda x: {
                          "cpu_logical": x.get("logical_cpu_count"),
                          "ram_gib": round((x.get("ram_total_bytes") or 0) / (1024 ** 3), 2),
                      })
        assert system.get("logical_cpu_count", 0) >= 1
        call("computer_performance_snapshot", important=True,
             detail=lambda x: {"cpu_percent": x.get("cpu_percent_sample")})
        call("computer_process_list", {"limit": 12}, important=True)
        call("computer_disk_overview", important=True)
        call("computer_service_overview")
        call("computer_startup_items")
        call("computer_installed_programs", {"limit": 30})
        call("computer_power_overview")
        call("computer_ui_windows")

        call("computer_defender_status", detail=lambda x: {
            "services_count": len(x.get("services", {})),
            "antivirus_inventory_available": x.get("security_center_antivirus_products", {}).get("available"),
        })
        call("computer_defender_events")
        call("computer_defender_scan_status")
        # Never invoke computer_defender_scan: user's instruction is read-only.

        home = Path.home()
        call("computer_list_directory", {"path": str(home), "limit": 20})
        call("computer_search_files", {
            "root": str(home), "pattern": "*.txt", "limit": 5,
        })
        windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
        known_file = windows_root / "win.ini"
        if known_file.is_file():
            call("computer_file_hash", {"path": str(known_file)}, important=True,
                 detail=lambda x: {"sha256_computed": bool(x.get("sha256"))})
        else:
            warnings.append("computer_file_hash_no_safe_fixture")
            print('{"test":"computer_file_hash","status":"SKIP","reason":"win_ini_missing"}')

        browser = call("browser_navigate", {"url": "https://example.com/"})
        if browser.get("ok"):
            snapshot = call("browser_snapshot")
            call("browser_network", detail=lambda x: {
                "events_recorded": len(x.get("events", x.get("network_events", []))),
            })
            links = snapshot.get("links", [])
            first = next((x for x in links if "iana.org" in str(x.get("url", ""))), None)
            if first and first.get("name"):
                call("browser_follow_link", {"name": first["name"]})
            else:
                warnings.append("browser_follow_link_no_matching_link")
                print('{"test":"browser_follow_link","status":"SKIP","reason":"link_unavailable"}')

            call("browser_new_tab", {"url": "https://example.org/"})
            tabs = call("browser_tabs", detail=lambda x: {
                "tab_count": len(x.get("tabs", [])),
                "active_index": x.get("active_index"),
            })
            if len(tabs.get("tabs", [])) >= 2:
                call("browser_switch_tab", {"index": 0})
                call("browser_switch_tab", {"index": 1})
                call("browser_navigate", {"url": "https://www.iana.org/domains/reserved"})
                call("browser_back")
                call("browser_forward")
                call("browser_reload")
            else:
                warnings.append("browser_multi_tab_not_available")
                print('{"test":"browser_switch_tab","status":"SKIP","reason":"second_tab_missing"}')
        search_pages = {}
        first_search_url = None
        for query, page in [
            ("Playwright Python official documentation", 1),
            ("Playwright Python official documentation", 2),
            ("Windows UI Automation Python examples", 1),
            ("Microsoft Defender Antivirus operational logs official", 1),
        ]:
            result = call("google_search", {"query": query, "page": page},
                 detail=lambda x: {"page": x.get("page"),
                                   "provider": x.get("provider"),
                                   "fallback_reason": x.get("fallback_reason"),
                                   "fallback_error": x.get("fallback_error"),
                                   "fallback_attempts": x.get("fallback_attempts"),
                                   "result_count": x.get("result_count"),
                                   "sample_result_domain": (x.get("results") or [{}])[0].get("domain"),
                                   "source_status": x.get("source_status")})
            if query == "Playwright Python official documentation":
                search_pages[page] = result
                if page == 1 and result.get("results"):
                    first_search_url = result["results"][0].get("url")
        if first_search_url:
            call("research_source_open", {"url": first_search_url},
                 detail=lambda x: {"http_status": x.get("http_status"),
                                   "title": x.get("title"),
                                   "content_chars": len(x.get("text_excerpt") or "")})
        page_one = {x.get("url") for x in search_pages.get(1, {}).get("results", [])}
        page_two = {x.get("url") for x in search_pages.get(2, {}).get("results", [])}
        overlap = len(page_one & page_two)
        pagination_ok = bool(page_one and page_two and len(page_two - page_one) > 0)
        print(json.dumps({
            "test": "search_pagination_and_open",
            "status": "PASS" if pagination_ok and first_search_url else "WARN",
            "page1_results": len(page_one), "page2_results": len(page_two),
            "overlap": overlap, "new_page2_results": len(page_two - page_one),
            "first_result_opened": bool(first_search_url),
        }, ensure_ascii=True))
        if not pagination_ok:
            warnings.append("search_pagination_not_distinct")
        # Probe alternative read-only public search providers if Google's
        # JavaScript shell returns no results; never attempt a challenge bypass.
        from console.browser_tools import _read_page
        from urllib.parse import urlencode, urlsplit
        for host, stem in (
            ("www.bing.com", "/search"),
            ("html.duckduckgo.com", "/html/"),
            ("search.brave.com", "/search"),
        ):
            url = "https://" + host + stem + "?" + urlencode({
                "q": "Playwright Python official documentation"
            })
            try:
                result = _read_page(url, {host})
                links = result.get("links", [])
                external = [
                    x for x in links
                    if urlsplit(str(x.get("url") or "")).hostname != host
                ]
                print(json.dumps({
                    "test": "public_search_provider_probe",
                    "provider": host, "status": "PASS",
                    "http_status": result.get("http_status"),
                    "link_count": len(links),
                    "external_link_count": len(external),
                    "heading_count": len(result.get("headings", [])),
                    "heading_sample": result.get("headings", [])[:8],
                    "link_sample": links[:8],
                    "excerpt_sample": str(result.get("text_excerpt") or "")[:180],
                }, ensure_ascii=False))
            except Exception as exc:
                print(json.dumps({
                    "test": "public_search_provider_probe",
                    "provider": host, "status": "WARN",
                    "error": type(exc).__name__,
                }, ensure_ascii=True))

        call("research_source_open", {"url": "https://playwright.dev/python/docs/intro"})
        call("research_source_open", {"url": "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows"})

        model = StubModel()
        agent = Agent(model, lambda: StubMCP(), local_tool_runtime=runtime)
        res = agent.run([], "Проверь свой терминал", force_tools=False)
        advertised = {item["function"]["name"] for item in model.advertised}
        if not {"terminal_status", "computer_system_overview", "browser_navigate"}.issubset(advertised) or res.get("tool_calls") != 1:
            failures.append("deepseek_shared_tool_dispatch")
            print('{"test":"deepseek_shared_tool_dispatch","status":"FAIL"}')
        else:
            print('{"test":"deepseek_shared_tool_dispatch","status":"PASS"}')
    finally:
        runtime.close()
    print(json.dumps({"summary": "windows_smoke", "hard_failures": failures,
                      "warnings": warnings}, ensure_ascii=False), flush=True)
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(run())
