import asyncio
import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import events_core as ev

SECRET = "whsec_" + base64.b64encode(b"s" * 32).decode()
URL = "https://hooks.example.com/mcp-events/notify"

class EventCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base
        paths = (("WORK",base),("STORE",base/"events"),("STATE",base/"events"/"subscriptions.json"),
                 ("REPORTS",base/"reports"))
        for name,val in paths:
            patcher=patch.object(ev,name,val)
            patcher.start()
            self.addCleanup(patcher.stop)
        (base/"reports").mkdir()

    def params(self,status="any"):
        return {"name":ev.EVENT,"arguments":{"status":status},
                "delivery":{"mode":"webhook","url":URL,"secret":SECRET},"ttlMs":60000}

    def test_catalog(self):
        e=ev.event_catalog()["events"][0]
        self.assertEqual(e["name"],ev.EVENT)
        self.assertEqual(e["delivery"],["webhook"])
        self.assertEqual(e["payloadSchema"]["required"],["commit","status","report","source"])

    def test_requires_strong_secret(self):
        for secret in ("","whsec_invalid","whsec_"+base64.b64encode(b"short").decode()):
            with self.assertRaises(ValueError):
                ev._secret(secret)
        self.assertEqual(ev._secret(SECRET),b"s"*32)

    def test_block_local_callbacks_and_non_https(self):
        for url in ("http://hooks.example.com/abc",
                    "https://127.0.0.1/a",
                    "https://localhost/mcp",
                    "https://a.internal/mcp",
                    "https://127.0.0.1.nip.io:8443/a",
                    "https://user:pass@hooks.example.com/a"):
            with self.assertRaises(ev.CallbackError):
                ev._callback_parts(url)

    def test_dns_rejects_private_and_mixed_addresses(self):
        v=[(2,1,6,"",("8.8.8.8",443)),
           (2,1,6,"",("127.0.0.1",443))]
        with patch.object(ev.socket,"getaddrinfo",return_value=v):
            with self.assertRaisesRegex(ev.CallbackError,"non-public"):
                ev._resolve_public("hooks.example.com")

    def test_standard_webhooks_signing(self):
        b=b'{"eventId":"evt_x"}'
        h=ev.signed_headers(SECRET,"sub_demo","evt_x",b,signed_at=1700000000)
        mac=hmac.new(b"s"*32,b"evt_x.1700000000."+b,hashlib.sha256).digest()
        expected="v1,"+base64.b64encode(mac).decode()
        self.assertEqual(h["webhook-signature"],expected)
        self.assertEqual(h["X-MCP-Subscription-Id"],"sub_demo")

    def test_verification_rejects_mismatched_challenge(self):
        def fake(url,body,headers):
            self.assertIn(b'"type":"verification"',body)
            self.assertEqual(headers["X-MCP-Subscription-Id"],"sub_demo")
            return 200,b'{"challenge":"wrong"}'
        with patch.object(ev,"_post_json",fake):
            with self.assertRaises(ev.CallbackError):
                ev.verify_callback(URL,SECRET,"sub_demo")

    def test_verification_accepts_exact_echo(self):
        def fake(url,body,headers):
            return 200,json.dumps({"challenge":json.loads(body)["challenge"]}).encode()
        with patch.object(ev,"_post_json",fake):
            ev.verify_callback(URL,SECRET,"sub_demo")

    def test_idempotent_subscription_and_unsubscribe(self):
        p=self.params()
        r1=ev.subscribe(p,verifier=lambda url,secret,sub:None)
        r2=ev.subscribe(p,verifier=lambda url,secret,sub:None)
        self.assertEqual(r1["id"],r2["id"])
        with ev._locked():
            self.assertEqual(len(ev._read()["subscriptions"]),1)
        payload={"name":ev.EVENT,"arguments":{"status":"any"},
                 "delivery":{"mode":"webhook","url":URL}}
        self.assertEqual(ev.unsubscribe(payload),{})
        self.assertEqual(ev.unsubscribe(payload),{})
        with ev._locked():
            self.assertFalse(ev._read()["subscriptions"])

    def test_reports_after_subscribe_filtered_and_deduplicated(self):
        sha="a"*40
        now=ev.time.time()
        (ev.REPORTS/"old.json").write_text(json.dumps({
            "commit":sha,"status":"success","timestamp":now-1000}))
        (ev.REPORTS/"new.json").write_text(json.dumps({
            "commit":sha,"status":"failed","timestamp":now+0.02}))
        ev.subscribe(self.params("failed"),verifier=lambda *args:None)
        sends=[]
        def sender(url,body,headers):
            sends.append((json.loads(body),headers))
            return 200,b""
        r=ev.poll_once(sender=sender,now=now+0.2)
        self.assertEqual((r["attempted"],r["accepted"]),(1,1))
        self.assertEqual(sends[0][0]["data"]["status"],"failed")
        self.assertEqual(ev.poll_once(sender=sender,now=now+1)["attempted"],0)
        self.assertEqual(len(sends),1)

    def test_failed_webhook_is_bounded(self):
        sha="b"*40
        now=ev.time.time()
        (ev.REPORTS/"fail.json").write_text(json.dumps({
            "commit":sha,"status":"failed","timestamp":now+0.01}))
        ev.subscribe(self.params(),verifier=lambda *args:None)
        count=0
        def sender(url,body,headers):
            nonlocal count
            count+=1
            return 410,b""
        ev.poll_once(sender=sender,now=now+0.2)
        ev.poll_once(sender=sender,now=now+0.3)
        self.assertEqual(count,1)

class MCPWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_discover_includes_events_only_on_modern_protocol(self):
        from mcp import types
        from events_bridge import register
        class FakeLL:
            def __init__(self): self.handlers={}
            async def _handle_discover(self,ctx,p):
                return types.DiscoverResult(
                    supported_versions=["2026-07-28"],
                    capabilities=types.ServerCapabilities(tools=types.ToolsCapability()))
            def add_request_handler(self,m,p,h): self.handlers[m]=h
        ll=FakeLL()
        register(SimpleNamespace(_lowlevel_server=ll))
        modern=await ll.handlers["server/discover"](SimpleNamespace(protocol_version="2026-07-28"),None)
        legacy=await ll.handlers["server/discover"](SimpleNamespace(protocol_version="2025-11-25"),None)
        self.assertIn("events",modern["capabilities"])
        self.assertNotIn("events",legacy["capabilities"])
        self.assertTrue(all(m in ll.handlers for m in
                     ["events/list","events/subscribe","events/unsubscribe"]))

if __name__=="__main__":
    unittest.main()
