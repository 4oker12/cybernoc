"""Offline acceptance for larger Cybernova HAR/PCAP/config attachments."""
import base64
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import upload_limits
from console import domain_intelligence, traffic_intelligence, tunnel_access
from console.server import ImportRequest


class ArtifactSizeTests(unittest.TestCase):
    def test_50_mib_limit_and_base64_transport_budget(self):
        raw = upload_limits.MAX_UPLOAD_FILE_BYTES
        self.assertEqual(raw, 50 * 1024 * 1024)
        self.assertEqual(upload_limits.MAX_PCAP_BASE64_CHARS, 4 * ((raw + 2) // 3))
        self.assertGreater(
            upload_limits.MAX_IMPORT_HTTP_BODY_BYTES,
            upload_limits.MAX_PCAP_BASE64_CHARS + 1024,
        )
        self.assertLess(upload_limits.MAX_PROXY_RESPONSE_BYTES,
                        upload_limits.MAX_IMPORT_HTTP_BODY_BYTES)
        self.assertEqual(domain_intelligence.MAX_TEXT, raw)
        self.assertEqual(domain_intelligence.MAX_PCAP, raw)
        self.assertEqual(traffic_intelligence.MAX_SOURCE_BYTES, raw)
        self.assertEqual(tunnel_access.MAX_NORMAL_REQUEST_BODY, 7_000_000)

    def test_pydantic_accepts_base64_pcap_over_former_four_mb(self):
        encoded = base64.b64encode(b"x" * (5 * 1024 * 1024)).decode("ascii")
        obj = ImportRequest(kind="pcap", content=encoded)
        self.assertEqual(obj.content, encoded)
        self.assertGreater(len(encoded), 6_000_000)

    def test_pcap_parser_accepts_five_mib_capture_and_drops_payload(self):
        # Little endian classic PCAP with a single oversized, untrusted test frame.
        frame = bytearray(5 * 1024 * 1024)
        frame[12:14] = b"\x08\x06"
        header = struct.pack("<IHHiiii", 0xa1b2c3d4, 2, 4, 0, 0,
                             6 * 1024 * 1024, 1)
        row = struct.pack("<IIII", 0, 0, len(frame), len(frame))
        report = domain_intelligence.analyze_pcap(
            base64.b64encode(header + row + frame).decode("ascii")
        )
        self.assertGreater(len(frame), 4_000_000)
        self.assertEqual(report["packet_count"], 1)
        self.assertEqual(report["protocol_counts"]["ARP"], 1)
        self.assertFalse(report["raw_data_retained"])
        self.assertNotIn("payload", report)

    def test_har_analyzes_above_former_six_mb_limit(self):
        blob = {"log": {"entries": [{"request": {"method": "GET",
                "url": "https://example.test/health", "headers": []},
                "response": {"status": 200, "headers": []}, "time": 3.0}],
                "ignored_padding": "a" * (7 * 1024 * 1024)}}
        report = traffic_intelligence.analyze_har(json.dumps(blob))
        self.assertEqual(report["requests_analyzed"], 1)
        self.assertFalse(report["raw_data_retained"])

    def test_openapi_parser_accepts_large_text_file(self):
        raw = json.dumps({"openapi": "3.0.0", "paths": {},
                          "ignored_padding": "x" * (5 * 1024 * 1024)})
        report = domain_intelligence.analyze_openapi(raw)
        self.assertEqual(report["kind"], "openapi")
        self.assertFalse(report["raw_data_retained"])

    def test_pcap_parser_rejects_invalid_size_before_processing(self):
        with patch.object(domain_intelligence, "MAX_PCAP", 1):
            with self.assertRaises(domain_intelligence.DomainError):
                domain_intelligence.analyze_pcap(base64.b64encode(b"abc").decode())

    def test_browser_limit_matches_shared_backend_limit(self):
        js = (ROOT / "console/static/app.js").read_text(encoding="utf-8")
        self.assertIn("const MAX_UPLOAD_BYTES = 50 * 1024 * 1024", js)
        self.assertIn("upload_limit_bytes", js)
        self.assertIn("file.size>state.uploadLimit", js)

    def test_gateway_uses_large_cap_only_for_imports(self):
        source = (ROOT / "console/tunnel_access.py").read_text(encoding="utf-8")
        self.assertIn('route == "/api/import"', source)
        self.assertIn("MAX_NORMAL_REQUEST_BODY", source)
        self.assertIn("MAX_PROXY_RESPONSE_BYTES", source)


if __name__ == "__main__":
    unittest.main()
