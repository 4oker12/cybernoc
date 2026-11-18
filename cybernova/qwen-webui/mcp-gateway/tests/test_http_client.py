import unittest
from unittest.mock import patch
import socket
from email.message import Message
import http_client


class FakeResponse:
    def __init__(self, code=200):
        self.status = code
        self.headers = Message()
        self.headers["Content-Type"] = "text/html; charset=utf-8"
        self.headers["Strict-Transport-Security"] = "max-age=300"
        self.headers["Set-Cookie"] = "id=SECRET; Secure"
    def read(self, n):
        return b'<title>Example</title><a href="/status">S</a><a href="https://evil.example/foo">E</a>'


class FakeConnection:
    requests = []
    def __init__(self, host, address, port):
        assert host == "simnet.ua"
        assert address == "93.184.216.34"
        assert port == 443
    def request(self, method, target, headers):
        self.requests.append((method, target, headers))
    def getresponse(self):
        return FakeResponse()
    def close(self):
        pass


class Tests(unittest.TestCase):
    def setUp(self):
        http_client._next_allowed = 0.0
        FakeConnection.requests.clear()

    def test_denied_unknown_site(self):
        with patch.object(http_client, "_public_ip", side_effect=AssertionError("network")):
            self.assertEqual(http_client.http_get("https://other.example/")["error"], "host_not_authorized")

    def test_denied_local_and_bad_urls(self):
        for value in ("http://127.0.0.1/", "file:///etc/passwd", "https://simnet.ua:444/",
                      "https://admin:pw@simnet.ua/", "https://simnet.ua/#frag",
                      "https://simnet.ua\\@evil.example/", "https://simnet.ua/\nheader"):
            self.assertFalse(http_client.http_get(value)["ok"])

    def test_public_ip_validation(self):
        with patch.object(socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ]):
            with self.assertRaises(ValueError):
                http_client._public_ip("simnet.ua", 443)

    def test_mixed_public_and_private_dns_denied(self):
        with patch.object(socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))
        ]):
            with self.assertRaises(ValueError):
                http_client._public_ip("simnet.ua", 443)

    def test_valid_get_metadata_and_rate_limit(self):
        with patch.object(http_client, "_public_ip", return_value="93.184.216.34"):
            with patch.object(http_client, "_PinnedHTTPS", FakeConnection):
                result = http_client.http_get("https://simnet.ua/")
                later = http_client.http_get("https://simnet.ua/")
        self.assertTrue(result["ok"])
        self.assertEqual(result["title"], "Example")
        self.assertEqual(result["sample_internal_paths"], ["/status"])
        self.assertNotIn("SECRET", str(result))
        self.assertEqual(FakeConnection.requests[0][0], "GET")
        self.assertEqual(FakeConnection.requests[0][1], "/")
        self.assertEqual(later["error"], "rate_limited")
        self.assertEqual(len(FakeConnection.requests), 1)

    def test_future_scope_without_code_change(self):
        with patch.object(http_client, "_load_scope", return_value={"future.example"}):
            parsed, error = http_client._validate_url("https://future.example/docs?a=1")
            self.assertIsNone(error)
            self.assertEqual(parsed[1], "future.example")


if __name__ == "__main__":
    unittest.main()
