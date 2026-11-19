"""Tests for privacy-filtered Google research and public source reading."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console import research_web
from console.research_web import (
    ResearchWebError, google_search, research_source_open,
    sanitize_search_query,
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
