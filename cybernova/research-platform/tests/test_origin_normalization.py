"""Origin normalization tests for the authenticated local access gateway."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console.tunnel_access import origin_allowed


class OriginNormalizationTests(unittest.TestCase):
    def test_cloudflare_default_https_port_matches_explicit_443(self):
        self.assertTrue(origin_allowed(
            "https://sample.trycloudflare.com",
            "sample.trycloudflare.com:443",
        ))
        self.assertTrue(origin_allowed(
            "https://sample.trycloudflare.com:443",
            "sample.trycloudflare.com",
        ))

    def test_localhost_origin_accepts_exact_loopback_port(self):
        self.assertTrue(origin_allowed(
            "http://127.0.0.1:18795", "127.0.0.1:18795",
        ))
        self.assertTrue(origin_allowed(
            "https://localhost:18795", "localhost:18795",
        ))

    def test_origin_host_and_nondefault_ports_must_match(self):
        self.assertFalse(origin_allowed(
            "https://other.trycloudflare.com", "sample.trycloudflare.com",
        ))
        self.assertFalse(origin_allowed(
            "https://sample.trycloudflare.com:444", "sample.trycloudflare.com:443",
        ))
        self.assertFalse(origin_allowed(
            "http://127.0.0.1:18794", "127.0.0.1:18795",
        ))

    def test_origin_rejects_paths_credentials_queries_and_fragments(self):
        for origin in (
            "https://sample.trycloudflare.com/path",
            "https://user:pass@sample.trycloudflare.com",
            "https://sample.trycloudflare.com/?x=1",
            "https://sample.trycloudflare.com/#fragment",
            "file:///tmp/test",
            "null",
        ):
            with self.subTest(origin=origin):
                self.assertFalse(origin_allowed(origin, "sample.trycloudflare.com"))

    def test_suffix_spoof_and_invalid_host_are_rejected(self):
        self.assertFalse(origin_allowed(
            "https://eviltrycloudflare.com", "eviltrycloudflare.com",
        ))
        self.assertFalse(origin_allowed(
            "https://sample.trycloudflare.com", "sample.trycloudflare.com/path",
        ))
        self.assertFalse(origin_allowed(
            "https://sample.trycloudflare.com", "sample.trycloudflare.com\r\nX: y",
        ))

    def test_missing_origin_is_allowed_for_nonbrowser_clients(self):
        self.assertTrue(origin_allowed(None, "127.0.0.1:18795"))


if __name__ == "__main__":
    unittest.main()
