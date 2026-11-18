import unittest
from core import review_python_source, review_http_headers, summarize_network


class SafetyTests(unittest.TestCase):
    def test_python_code_does_not_run(self):
        self.assertEqual(review_python_source("x = 1")["indicators"], [])

    def test_python_flags(self):
        source = "import os\nos.system('echo test')\neval('1')\n"
        obj = review_python_source(source)
        self.assertEqual([x["line"] for x in obj["indicators"]], [2, 3])
        self.assertTrue(all(x["confidence"] == "heuristic_only" for x in obj["indicators"]))

    def test_syntax_error(self):
        self.assertFalse(review_python_source("def a(:")["ok"])

    def test_source_limit(self):
        self.assertFalse(review_python_source("a" * 65000)["ok"])

    def test_headers_redacted(self):
        obj = review_http_headers("HTTP/1.1 200 OK\nSet-Cookie: sid=TOPSECRET; Secure; HttpOnly")
        self.assertTrue(obj["ok"])
        self.assertNotIn("TOPSECRET", repr(obj))
        self.assertEqual(obj["cookie_flags"][0]["name"], "sid")

    def test_http_no_hsts_check(self):
        obj = review_http_headers("X-Frame-Options: DENY", "http")
        self.assertNotIn("strict-transport-security", obj["missing_review_candidates"])

    def test_reject_invalid_header(self):
        self.assertFalse(review_http_headers("invalid")["ok"])

    def test_cidr(self):
        obj = summarize_network("192.0.2.5/24")
        self.assertEqual(obj["network"], "192.0.2.0/24")
        self.assertEqual(obj["network_requests"], 0)

    def test_invalid_cidr(self):
        self.assertFalse(summarize_network("https://example.com")["ok"])


if __name__ == "__main__":
    unittest.main()
