"""Offline acceptance for official ChatGPT sign-in and account-gated inference."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from console import siwc, siwc_inference
from console.tunnel_access import allowed_path


class SignInTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.app = siwc.Connection(self.root / "siwc")

    def _begin(self):
        with patch.dict(os.environ, {"CYBERNOVA_SIWC_CALLBACK_PORT": "18795"}):
            data = self.app.start()
        url = urlsplit(data["authorization_url"])
        values = parse_qs(url.query)
        return data, values

    def _finish(self, state: str, *, client="oaiapp_test123"):
        params = {"state": state, "client_id": client, "code": "abcdef1234567890"}
        tokens = {"id_token": "jwt-test", "access_token": "access-123",
                  "refresh_token": "refresh-123", "expires_in": 3600,
                  "scope": siwc.SCOPES}
        identity = {"sub": "subject-A", "email": "test@example.test",
                    "email_verified": True}
        with patch.object(siwc, "_post", return_value=tokens) as post, \
             patch.object(siwc, "_verify", return_value=identity) as verify:
            result = self.app.finish(params)
        self.assertEqual(post.call_args.args[0], siwc.TOKEN)
        self.assertEqual(verify.call_args.args[1], client)
        return result

    def test_pkce_state_nonce_and_official_endpoints(self):
        result, query = self._begin()
        self.assertEqual(urlsplit(result["authorization_url"]).netloc, "auth.openai.com")
        self.assertEqual(query["client_id"], ["dynamic_agent_client"])
        self.assertEqual(query["scope"], [siwc.SCOPES])
        self.assertEqual(query["resource"], [siwc.RESOURCE])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["redirect_uri"],
                         ["http://127.0.0.1:18795/auth/callback"])
        self.assertTrue(query["ext_agent_host_id"][0].startswith("urn:uuid:"))
        self.assertNotIn("code_verifier", query)
        self.assertNotIn("id_token", result["authorization_url"])

    def test_first_signin_persists_protected_credential_and_hides_tokens(self):
        _, values = self._begin()
        status = self._finish(values["state"][0])
        self.assertTrue(status["connected"])
        self.assertTrue(status["plan_usage"])
        self.assertEqual(status["email"], "test@example.test")
        self.assertNotIn("access_token", str(status))
        stored = self.root / "siwc" / "connection.json"
        data = json.loads(stored.read_text())
        self.assertEqual(data["client_id"], "oaiapp_test123")
        self.assertEqual(data["refresh_token"], "refresh-123")
        if os.name != "nt":
            self.assertEqual(stored.stat().st_mode & 0o077, 0)
        self.assertNotIn("refresh-123", str(status))

    def test_state_is_single_use_and_cannot_be_swapped(self):
        _, values = self._begin()
        with self.assertRaises(siwc.SIWCError):
            self.app.finish({"state": "bad", "code": "abcdef1234567890",
                             "client_id": "oaiapp_test123"})
        with self.assertRaises(siwc.SIWCError):
            self.app.finish({"state": values["state"][0],
                             "code": "abcdef1234567890", "client_id": "oaiapp_test123"})

    def test_callback_rejects_identity_or_unknown_client(self):
        _, v = self._begin()
        with self.assertRaises(siwc.SIWCError):
            self.app.finish({"state": v["state"][0], "code": "abcdef1234567890",
                             "client_id": "wrong"})
        self.assertFalse(self.app.status()["connected"])

    def test_returning_client_and_stable_host_id(self):
        _, initial = self._begin()
        host1 = initial["ext_agent_host_id"][0]
        self._finish(initial["state"][0])
        _, returned = self._begin()
        self.assertEqual(returned["client_id"], ["oaiapp_test123"])
        self.assertNotIn("agent_name_hint", returned)
        self.assertEqual(returned["ext_agent_host_id"][0], host1)

    def test_expired_access_refreshes_and_rotates(self):
        _, v = self._begin()
        self._finish(v["state"][0])
        data = self.app._load()
        data["expires_at"] = 1
        self.app._save(data)
        fresh = {"access_token": "access-NEW", "refresh_token": "refresh-NEW",
                 "scope": siwc.SCOPES, "expires_in": 3600}
        with patch.object(siwc, "_post", return_value=fresh) as post:
            self.assertEqual(self.app.access(), "access-NEW")
        self.assertEqual(post.call_args.args[1]["grant_type"], "refresh_token")
        self.assertEqual(self.app._load()["refresh_token"], "refresh-NEW")

    def test_disconnect_clears_credential_even_if_remote_revocation_fails(self):
        _, v = self._begin()
        self._finish(v["state"][0])
        with patch.object(siwc, "_post", side_effect=siwc.SIWCError("offline")):
            result = self.app.disconnect()
        self.assertFalse(result["connected"])
        self.assertTrue(result["remote_revocation_warning"])
        self.assertFalse(self.app.status()["connected"])
        self.assertTrue((self.root / "siwc" / "host-id.txt").exists())

    def test_signature_nonce_audience_issuer_checked(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        payload = {"sub": "user123", "nonce": "test-nonce",
                   "iss": siwc.ISSUER, "aud": "oaiapp_test123",
                   "iat": int(time.time()), "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, key, algorithm="RS256")
        class FakeKeys:
            def __init__(self, *args, **kwargs): pass
            def get_signing_key_from_jwt(self, *_):
                return SimpleNamespace(key=key.public_key())
        with patch.object(siwc.jwt, "PyJWKClient", FakeKeys):
            self.assertEqual(siwc._verify(token, "oaiapp_test123", "test-nonce")["sub"],
                             "user123")
            for wrong_client, wrong_nonce in (("oaiapp_wrong", "test-nonce"),
                                              ("oaiapp_test123", "wrong")):
                with self.assertRaises(siwc.SIWCError):
                    siwc._verify(token, wrong_client, wrong_nonce)

    def test_gateway_exposes_only_expected_oauth_paths(self):
        for url in ("/api/siwc/status", "/api/siwc/models",
                    "/auth/callback?code=not-logged"):
            self.assertTrue(allowed_path(url, "GET"))
        for url in ("/api/siwc/start", "/api/siwc/review",
                    "/api/siwc/disconnect"):
            self.assertTrue(allowed_path(url, "POST"))
        self.assertFalse(allowed_path("/api/siwc/tokens", "GET"))
        self.assertFalse(allowed_path("/auth/callback", "POST"))

    def test_browser_wiring_and_explicit_upload_only(self):
        html = (ROOT / "console/static/index.html").read_text()
        js = (ROOT / "console/static/app.js").read_text()
        self.assertIn('data-oai-siwc-button', html)
        self.assertIn('id="chatgptModel"', html)
        self.assertIn("connectChatGPT", js)
        self.assertIn("reviewWithChatGPT", js)
        self.assertIn("/api/siwc/review", js)
        self.assertIn('window.location.hostname', js)
        self.assertIn('host!=="127.0.0.1"', js)


class InferenceTests(unittest.TestCase):
    def test_models_filter_uses_server_catalog(self):
        class Stream:
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def read(self, *_):
                return json.dumps({"models": [
                    {"visibility": "list", "slug": "gpt-6.2-sol",
                     "display_name": "GPT 6.2"},
                    {"visibility": "hidden", "slug": "not-allowed"},
                ]}).encode()
        class Opener:
            def open(self, *_, **__): return Stream()
        with patch.object(siwc_inference.connection, "access", return_value="token"), \
             patch.object(siwc_inference.request, "build_opener", return_value=Opener()):
            data = siwc_inference.models()
        self.assertEqual([x["slug"] for x in data], ["gpt-6.2-sol"])

    def test_review_requires_account_model_and_stream_completion(self):
        class Stream:
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def __iter__(self):
                return iter([b'data: {"type":"response.output_text.delta","delta":"Reviewed"}\n',
                             b'data: {"type":"response.completed"}\n'])
        class Opener:
            def open(self, req, **_):
                data = json.loads(req.data)
                self.last = data
                return Stream()
        opener = Opener()
        with patch.object(siwc_inference, "models", return_value=[
                 {"slug": "gpt-6.2-sol", "display_name": "GPT 6.2"}]), \
             patch.object(siwc_inference.connection, "access", return_value="token"), \
             patch.object(siwc_inference.request, "build_opener", return_value=opener):
            output = siwc_inference.review("gpt-6.2-sol", "Review evidence")
        self.assertEqual(output["answer"], "Reviewed")
        self.assertFalse(opener.last["store"])
        self.assertTrue(opener.last["stream"])
        self.assertNotIn("temperature", opener.last)
        with patch.object(siwc_inference, "models", return_value=[]):
            with self.assertRaises(siwc.SIWCError):
                siwc_inference.review("gpt-6.2-sol", "Review evidence")


if __name__ == "__main__":
    unittest.main()
