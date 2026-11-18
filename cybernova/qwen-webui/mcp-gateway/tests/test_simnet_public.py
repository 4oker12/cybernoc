import unittest
from unittest.mock import patch
from email.message import Message
import simnet_public


class FakeResponse:
    def __init__(self):
        self.headers = Message()
        self.headers["Content-Type"] = "text/html; charset=UTF-8"
        self.headers["Strict-Transport-Security"] = "max-age=3600"
        self.headers["Set-Cookie"] = "test=SECRET; Secure"
    def getcode(self):
        return 200
    def read(self, n):
        return b'<title>Test Homepage</title><a href="/ok">ok</a><a href="https://other.example.net/a">external</a>'
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class SimnetPublicTests(unittest.TestCase):
    def setUp(self):
        simnet_public._next_allowed = 0.0

    def test_unknown_page_denied_without_network(self):
        with patch.object(simnet_public.urllib.request, "build_opener", side_effect=AssertionError("NETWORK")):
            for value in ["https://evil.example/", "../internal", "http://127.0.0.1:18791", ""]:
                r = simnet_public.simnet_public_page(value)
                self.assertEqual(r["error"], "page_not_allowed")

    def test_single_fixed_get_and_redaction(self):
        class FakeOpener:
            def open(self, req, timeout):
                self_request = req
                self.assert_url = self_request.full_url
                assert timeout == 8
                assert req.get_method() == "GET"
                assert req.full_url == "https://simnet.ua/"
                return FakeResponse()
        with patch.object(simnet_public.urllib.request, "build_opener", return_value=FakeOpener()):
            r = simnet_public.simnet_public_page("home")
        self.assertTrue(r["ok"])
        self.assertEqual(r["title"], "Test Homepage")
        self.assertEqual(r["sample_internal_link_paths"], ["/ok"])
        self.assertNotIn("SECRET", str(r))
        self.assertEqual(r["set_cookie_header_count"], 1)

    def test_cooldown(self):
        with patch.object(simnet_public.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = FakeResponse()
            self.assertTrue(simnet_public.simnet_public_page("home")["ok"])
            r = simnet_public.simnet_public_page("home")
            self.assertFalse(r["ok"])
            self.assertEqual(r["error"], "rate_limited")
            self.assertEqual(opener.return_value.open.call_count, 1)


if __name__ == "__main__":
    unittest.main()
