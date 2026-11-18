import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.evidence import sha256_hex, redact_headers, redact_text, evidence_metadata


class EvidenceTests(unittest.TestCase):
    def test_sha256_is_deterministic(self):
        self.assertEqual(sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_sensitive_headers_are_dropped(self):
        result = redact_headers({"Set-Cookie": "sid=secret", "Authorization": "Bearer abc",
                                  "Content-Type": "text/html", "X-API-Key": "very-secret"})
        self.assertEqual(result, {"content-type": "text/html"})
        self.assertNotIn("secret", str(result))

    def test_sensitive_output_masks(self):
        t = redact_text("Authorization: Bearer abc123 password=abc test@example.com")
        self.assertNotIn("abc123", t)
        self.assertNotIn("password=abc", t)
        self.assertNotIn("test@example.com", t)

    def test_metadata_excludes_query_and_raw(self):
        x = evidence_metadata(run_id="r-1", tool_name="http_get",
            target_url="https://simnet.ua/path?token=never-print",
            raw_bytes=b"private body", response_headers={"Set-Cookie": "sid=secret",
            "Server": "nginx"})
        self.assertEqual(x["target"], "https://simnet.ua/path")
        self.assertEqual(x["response_headers"], {"server": "nginx"})
        self.assertTrue(x["redacted"])
        self.assertFalse(x["raw_payload_saved"])
        self.assertNotIn("never-print", str(x))
        self.assertNotIn("private body", str(x))

    def test_invalid_run_id_rejected(self):
        with self.assertRaises(ValueError):
            evidence_metadata(run_id="../../oops",tool_name="http_get",
                target_url="https://simnet.ua/", raw_bytes=b"ok", response_headers={})


if __name__ == "__main__":
    unittest.main()
