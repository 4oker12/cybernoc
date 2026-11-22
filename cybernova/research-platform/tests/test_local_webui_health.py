"""Local-only regression tests for the portable gateway health probe."""
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import sys
from threading import Thread
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT.parent / "qwen-webui" / "mcp-gateway" / "core.py"
spec = importlib.util.spec_from_file_location("cybernova_gateway_core", CORE_PATH)
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


class LocalWebUIHealthTests(unittest.TestCase):
    def serve(self, status, body):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        return f"http://127.0.0.1:{server.server_port}/api/status"

    def test_live_console_status_and_mcp_ready(self):
        url = self.serve(200, b'{"mcp_ready":true,"model_provider":"openai_compatible"}')
        result = core.check_local_webui(url)
        self.assertTrue(result["ok"])
        self.assertEqual(result["listener"], "up")
        self.assertEqual(result["layer"], "app")
        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["mcp_ready"])
        self.assertEqual(result["reason"], "ok")
        self.assertEqual(result["network_requests"], 1)

    def test_closed_port_reports_connection_refused(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        result = core.check_local_webui(f"http://127.0.0.1:{port}/api/status")
        self.assertFalse(result["ok"])
        self.assertEqual(result["listener"], "absent")
        self.assertEqual(result["layer"], "tcp")
        self.assertEqual(result["reason"], "connection_refused")

    def test_http_401_is_reachable_but_not_application_ready(self):
        url = self.serve(401, b'{"detail":"unauthorized"}')
        result = core.check_local_webui(url)
        self.assertFalse(result["ok"])
        self.assertEqual(result["listener"], "up")
        self.assertEqual(result["layer"], "http")
        self.assertEqual(result["http_status"], 401)
        self.assertEqual(result["mcp_ready"], None)
        self.assertEqual(result["reason"], "http_401")

    def test_probe_rejects_non_loopback_urls_without_network_access(self):
        result = core.check_local_webui("https://example.org/api/status")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "invalid_local_url")
        self.assertEqual(result["network_requests"], 0)


if __name__ == "__main__":
    unittest.main()
