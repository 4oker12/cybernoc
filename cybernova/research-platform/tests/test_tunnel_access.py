"""No-network checks of the authenticated Cloudflare Web UI bridge."""
from __future__ import annotations

import base64
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console.tunnel_access import authorized, origin_allowed, allowed_path, read_credentials


class TunnelAccessTests(unittest.TestCase):
    def setUp(self):
        self.credentials = ("cybernova", "strong-password-" + "x" * 30)

    def header(self, raw: str) -> str:
        return "Basic " + base64.b64encode(raw.encode()).decode()

    def test_strict_auth_and_wrong_credentials(self):
        self.assertTrue(authorized(
            self.header(self.credentials[0] + ":" + self.credentials[1]),
            self.credentials))
        for item in (None, "", "Bearer token", "Basic invalid!?",
                     self.header("cybernova:wrong"), self.header("other:" + self.credentials[1])):
            self.assertFalse(authorized(item, self.credentials))

    def test_route_allowlist(self):
        for path in ("/", "/static/app.js", "/static/styles.css",
                     "/api/status", "/api/comm/events?after_seq=2", "/api/comm/tasks",
                     "/api/comm/review-packet?session_id=test", "/api/comm/evidence"):
            self.assertTrue(allowed_path(path, "GET"), path)
        for path in ("/api/chat", "/api/import", "/api/approve", "/api/comm/resume",
                     "/api/comm/reviewer-feedback"):
            self.assertTrue(allowed_path(path, "POST"))
        for path in ("/mcp", "/api/tags", "/api/generate", "//mcp", "/api/admin",
                     "/api/chat/../../mcp", "/static/../../etc/passwd"):
            self.assertFalse(allowed_path(path, "GET"), path)
        self.assertFalse(allowed_path("/api/status", "POST"))
        self.assertFalse(allowed_path("/", "DELETE"))

    def test_cross_origin_submission_denied(self):
        host = "example-one.trycloudflare.com"
        self.assertTrue(origin_allowed("https://" + host, host))
        self.assertFalse(origin_allowed("https://attacker.example", host))
        self.assertFalse(origin_allowed("http://" + host, host))
        self.assertFalse(origin_allowed("https://" + host, "evil.example"))
        self.assertTrue(origin_allowed("http://127.0.0.1:18795", "127.0.0.1:18795"))

    def test_password_file_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.txt"
            path.write_text("cybernova\n" + "x" * 32 + "\n")
            self.assertEqual(read_credentials(path)[0], "cybernova")
            path.write_text("cybernova\nweak\n")
            with self.assertRaises(ValueError):
                read_credentials(path)


if __name__ == "__main__":
    unittest.main()
