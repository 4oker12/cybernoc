"""Tests for privacy-filtered Google research and public source reading."""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console import research_web
from console.research_web import (
    ResearchWebError, google_search, research_source_open,
    sanitize_search_query, _parse_bing_rss, _bing_html_fallback,
    _unwrap_result_url,
)
from console.traffic_tools import TrafficToolClient
from console.tool_policy import REVIEWED_TOOLS


class FakeUpstream:
    def initialize(self):
        return []
    def call(self, name, args):
        if name == "gateway_status":
            return {"authorized_hosts": []}, False
        return {"ok": True}, False


class ResearchWebTests(unittest.TestCase):
    def test_search_query_redacts_private_identifiers_and_secrets(self):
        value = sanitize_search_query(
            "CVE-2026-12345 Apache 2.4.25 10.9.55.44 "
            "admin@example.com token=abc123 aa:bb:cc:dd:ee:ff portal.example "
            "and admin.simnet.kiev.ua",
            blocked_hosts=["portal.example"],
        )
        self.assertIn("CVE-2026-12345", value)
        self.assertIn("Apache 2.4.25", value)
        for forbidden in ("10.9.55.44", "admin@example.com", "abc123",
                          "aa:bb:cc:dd:ee:ff", "portal.example",
                          "admin.simnet.kiev.ua"):
            self.assertNotIn(forbidden, value)

    def test_google_search_parses_external_result_and_uses_sanitized_query(self):
        page = {
            "http_status": 200,
            "headings": ["CVE-2026-12345 Vendor Security Advisory"],
            "text_excerpt": (
                "CVE-2026-12345 Vendor Security Advisory "
                "Affected versions are Apache 2.4.25. Fixed in the vendor update."
            ),
            "links": [{
                "title": "CVE-2026-12345 Vendor Security Advisory",
                "url": "https://www.google.com/url?q=https%3A%2F%2Fvendor.example%2Fsecurity%2FCVE-2026-12345",
            }],
        }
        calls = []
        def reader(url, hosts):
            calls.append((url, hosts))
            return page
        with patch.object(research_web, "_rate_limit"):
            result = google_search(
                "CVE-2026-12345 Apache 2.4.25 10.9.55.44",
                blocked_hosts=["internal.example"], reader=reader,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["provider"], "Google Search HTML")
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["results"][0]["domain"], "vendor.example")
        self.assertIn("Fixed in the vendor update", result["results"][0]["snippet"])
        query = parse_qs(urlsplit(calls[0][0]).query)["q"][0]
        self.assertNotIn("10.9.55.44", query)
        self.assertEqual(calls[0][1], {"www.google.com"})
        self.assertTrue(result["untrusted_web_content"])

    def test_google_search_supports_bounded_result_pages(self):
        page = {
            "http_status": 200, "headings": [], "text_excerpt": "", "links": [],
        }
        calls = []
        def reader(url, hosts):
            calls.append(url)
            return page
        with patch.object(research_web, "_rate_limit"):
            result = google_search("vendor advisory CVE-2026-12345", page=2, reader=reader)
        query = parse_qs(urlsplit(calls[0]).query)
        self.assertEqual(query["start"], ["10"])
        self.assertEqual(query["num"], ["10"])
        self.assertEqual(result["page"], 2)
        self.assertEqual(result["start_index"], 10)
        with self.assertRaisesRegex(ResearchWebError, "page_out_of_range"):
            google_search("vendor advisory", page=6, reader=reader)

    def test_bing_html_redirects_are_unwrapped_to_public_sources(self):
        target = "https://playwright.dev/python/docs/intro"
        encoded = "a1" + base64.urlsafe_b64encode(
            target.encode("utf-8")
        ).decode("ascii").rstrip("=")
        redirect = "https://www.bing.com/ck/a?" + urlencode({"u": encoded})
        self.assertEqual(_unwrap_result_url(redirect), target)
        self.assertIsNone(_unwrap_result_url("https://www.bing.com/search?q=internal"))

    def test_bing_html_fallback_uses_first_offset_and_extracts_external_results(self):
        target = "https://playwright.dev/python/docs/intro"
        encoded = "a1" + base64.urlsafe_b64encode(
            target.encode("utf-8")
        ).decode("ascii").rstrip("=")
        redirect = "https://www.bing.com/ck/a?" + urlencode({"u": encoded})
        requested = []
        def reader(url, hosts):
            requested.append((url, hosts))
            return {
                "http_status": 200, "source_sha256": "a" * 64,
                "headings": ["Fast and reliable end-to-end testing for modern web apps |", "Playwright"],
                "text_excerpt": "Fast and reliable end-to-end testing for modern web apps | Playwright Official documentation for browser automation.",
                "links": [{"title": "Fast and reliable end-to-end testing for modern web apps | Playwright", "url": redirect}],
            }
        result = _bing_html_fallback("Playwright Python docs", 2, reader=reader)
        page2 = parse_qs(urlsplit(requested[0][0]).query)
        self.assertEqual(page2["first"], ["11"])
        self.assertEqual(page2["FORM"], ["PERE"])
        self.assertEqual(page2["pq"], ["Playwright Python docs"])
        page1_url = []
        _bing_html_fallback("Playwright Python docs", 1, reader=lambda url, hosts: (
            page1_url.append(url) or {
                "http_status": 200, "source_sha256": "b" * 64,
                "headings": [], "text_excerpt": "",
                "links": [{"title": "Result", "url": redirect}],
            }
        ))
        page1 = parse_qs(urlsplit(page1_url[0]).query)
        self.assertNotIn("first", page1)
        self.assertNotIn("FORM", page1)
        self.assertEqual(result["provider"], "Bing Search HTML fallback")
        self.assertEqual(result["results"][0]["url"], target)
        self.assertEqual(result["results"][0]["domain"], "playwright.dev")
        self.assertIn("Fast and reliable", result["results"][0]["title"])

    def test_bing_rss_parses_normalized_public_https_results(self):
        blob = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<rss version="2.0"><channel><title>Search</title><item>'
            b'<title>Playwright Python Docs</title>'
            b'<link>https://playwright.dev/python/docs/intro</link>'
            b'<description>Official &lt;b&gt;Playwright&lt;/b&gt; docs.</description>'
            b'</item></channel></rss>'
        )
        result = _parse_bing_rss(blob)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["domain"], "playwright.dev")
        self.assertIn("Official Playwright docs", result[0]["snippet"])
        for attack in (
            b'<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss/>',
            b'<notrss><channel></channel></notrss>',
        ):
            with self.assertRaises(ResearchWebError):
                _parse_bing_rss(attack)

    def test_google_js_shell_falls_back_to_bing_rss_without_bypassing_challenges(self):
        page = {
            "http_status": 200,
            "headings": [], "links": [],
            "text_excerpt": (
                "Google Search\\nIf you're having trouble accessing Google Search, "
                "please click here, or send feedback."
            ),
        }
        fallback = {
            "provider": "Bing Search RSS fallback",
            "source_status": 200, "pagination_verified": False,
            "results": [{
                "title": "Playwright", "domain": "playwright.dev",
                "url": "https://playwright.dev/", "snippet": "Docs",
            }],
        }
        with (patch.object(research_web, "_read_page", return_value=page),
              patch.object(research_web, "_rate_limit"),
              patch.object(research_web, "_bing_rss_fallback", return_value=fallback) as called):
            result = google_search("Playwright Python docs", page=2)
        self.assertTrue(result["ok"])
        self.assertEqual(result["provider"], "Bing Search RSS fallback")
        self.assertEqual(result["fallback_reason"], "google_javascript_shell")
        self.assertFalse(result["pagination_verified"])
        called.assert_called_once_with("Playwright Python docs", 2)

    def test_google_challenge_is_not_bypassed(self):
        page = {
            "http_status": 200, "headings": [],
            "text_excerpt": "Our systems have detected unusual traffic",
            "links": [],
        }
        with patch.object(research_web, "_rate_limit"):
            with self.assertRaisesRegex(ResearchWebError, "challenge_or_consent"):
                google_search("Apache CVE research", reader=lambda url, hosts: page)

    def test_source_open_requires_public_https_and_same_host_reader_scope(self):
        page = {
            "url": "https://vendor.example/advisory",
            "http_status": 200, "title": "Vendor Advisory",
            "headings": ["Impact", "Mitigation"], "text_excerpt": "Patch available",
            "links": [], "source_sha256": "a" * 64,
            "content_type": "text/html", "redirects": 0,
        }
        calls = []
        def reader(url, hosts):
            calls.append((url, hosts))
            return page
        with patch.object(research_web, "_rate_limit"):
            result = research_source_open("https://vendor.example/advisory", reader=reader)
        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][1], {"vendor.example"})
        self.assertTrue(result["untrusted_web_content"])
        with self.assertRaisesRegex(ResearchWebError, "public_https"):
            research_source_open("http://vendor.example/advisory", reader=reader)
        with self.assertRaisesRegex(ResearchWebError, "ip_literal"):
            research_source_open("https://127.0.0.1/advisory", reader=reader)
        with self.assertRaisesRegex(ResearchWebError, "sensitive_query_parameter"):
            research_source_open("https://vendor.example/advisory?access_token=secret", reader=reader)

    def test_toolset_registers_search_and_source_reader_as_read_only(self):
        client = TrafficToolClient(FakeUpstream(), {}, scope={"hosts": ["private.example"]})
        names = {tool["name"] for tool in client.initialize()}
        self.assertIn("google_search", names)
        self.assertIn("research_source_open", names)
        self.assertIn("google_search", REVIEWED_TOOLS)
        self.assertIn("research_source_open", REVIEWED_TOOLS)
        self.assertNotIn("lab_zap_active", REVIEWED_TOOLS)

    def test_traffic_client_routes_search_to_research_adapter(self):
        client = TrafficToolClient(FakeUpstream(), {}, scope={"hosts": ["private.example"]})
        with patch("console.research_web.research_web_call",
                   return_value=({"ok": True, "provider": "Google Search HTML"}, False)) as call:
            result, failed = client.call("google_search", {"query": "CVE-2026-12345"})
        self.assertFalse(failed)
        self.assertEqual(result["provider"], "Google Search HTML")
        call.assert_called_once_with(
            "google_search", {"query": "CVE-2026-12345"},
            blocked_hosts=["private.example"],
        )


if __name__ == "__main__":
    unittest.main()
