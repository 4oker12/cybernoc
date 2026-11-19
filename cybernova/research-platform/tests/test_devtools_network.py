"""Unit and integration checks for scoped Chromium Network capture.

No external internet is contacted in these tests. A fake capture runner is
injected, so CI does not require installing a Chromium binary.
"""
from pathlib import Path
from unittest.mock import patch
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console import devtools_network
from console.agent import Agent


class Gateway:
    def __init__(self, scope=None):
        self.scope = scope or ["simnet.ua"]
        self.calls = []
    def call(self, name, args):
        self.calls.append((name, args))
        if name == "gateway_status":
            return {"authorized_hosts": self.scope}, False
        return {}, True


class NetworkTests(unittest.TestCase):
    def test_host_method_scheme_port_and_external_hosts_are_blocked(self):
        approve = {"simnet.ua"}
        good = "https://simnet.ua/support?token=SECRET"
        self.assertIsNone(devtools_network._decision(good, "GET", approve))
        self.assertIsNone(devtools_network._decision(good, "HEAD", approve))
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            self.assertEqual(devtools_network._decision(good, method, approve),
                             "blocked_non_read_method")
        self.assertEqual(devtools_network._decision("https://evil.test/", "GET", approve),
                         "blocked_external_host")
        self.assertEqual(devtools_network._decision("http://simnet.ua/", "GET", approve),
                         "blocked_non_https_or_port")
        self.assertEqual(devtools_network._decision("https://simnet.ua:8080/", "GET", approve),
                         "blocked_non_https_or_port")
        self.assertEqual(devtools_network._decision("https://127.0.0.1/", "GET", approve),
                         "blocked_external_host")
        self.assertEqual(devtools_network._decision("https://simnet.ua@127.0.0.1/", "GET", approve),
                         "blocked_non_https_or_port")

    def test_query_values_and_long_identifiers_never_leave_sanitizer(self):
        data=devtools_network._clean_url(
            "https://simnet.ua/api/customer/123456789/abcdefabcdefabcdefabcdefabcdefab"
            "?token=secretVALUE&password=123&account=435543")
        self.assertEqual(data["host"],"simnet.ua")
        self.assertIn("{id}",data["path"])
        self.assertEqual(data["query_keys"],["account","password","token"])
        self.assertNotIn("secretVALUE",str(data))
        self.assertNotIn("435543",str(data))
        self.assertNotIn("123456789",str(data))

    def test_capture_uses_dns_pinning_and_scope(self):
        seen=[]
        def fake(url, pinned, allowed):
            seen.append((url,pinned,allowed))
            return {"network_events":[{"method":"GET","status":200}]}
        with patch.object(devtools_network,"_public_v4",return_value="93.184.215.14"), \
             patch.dict("os.environ",{"CYBERNOVA_BROWSER_HOSTS":"simnet.ua"}):
            result=devtools_network.network_call("browser_network",{
                "url":"https://simnet.ua/support"
            },Gateway(scope=[]),runner=fake)
            self.assertTrue(result["ok"])
            self.assertEqual(seen[0][1],{"simnet.ua":"93.184.215.14"})
            self.assertEqual(len(result["capture"]["network_events"]),1)
        with patch.object(devtools_network,"_public_v4") as resolver:
            with patch.dict("os.environ",{"CYBERNOVA_BROWSER_HOSTS":"simnet.ua"}):
                with self.assertRaisesRegex(ValueError,"browser_host_not_allowed"):
                    devtools_network.network_call("browser_network",{
                        "url":"https://localhost:443/"
                    },Gateway(),runner=fake)
                resolver.assert_not_called()

    def test_refuses_unapproved_hosts_before_dns(self):
        with patch.object(devtools_network,"_public_v4") as resolver:
            with patch.dict("os.environ",{"CYBERNOVA_BROWSER_HOSTS":""}):
                with self.assertRaisesRegex(ValueError,"browser_host_not_allowed"):
                    devtools_network.network_call("browser_network",{
                        "url":"https://different-site.test/"
                    },Gateway(),runner=lambda *_: {})
                resolver.assert_not_called()

    def test_discovered_by_qwen_composite(self):
        from console.traffic_tools import TrafficToolClient
        class Remote:
            def initialize(self):return []
            def call(self, *args):return Gateway().call(*args)
        names={x["name"] for x in TrafficToolClient(Remote(),{}).initialize()}
        self.assertIn("browser_open",names)
        self.assertIn("browser_network",names)

    def test_agent_forces_one_real_browser_result_when_model_ignores_tools(self):
        class Model:
            model = "offline-qwen"
            def __init__(self):self.messages=[]
            def chat(self,messages,tools=None,**kwargs):
                self.messages.append(messages)
                if kwargs.get("json_mode"):
                    return {"role":"assistant","content":'{"calls":[]}'}
                if any(m.get("role")=="tool" and m.get("tool_name")=="browser_network"
                       for m in messages):
                    return {"role":"assistant","content":"Network получен: HTTP 200"}
                return {"role":"assistant","content":"Могу объяснить как открыть Network"}
        class MCP:
            def __init__(self):self.calls=[]
            def initialize(self):
                return list(devtools_network.NETWORK_TOOLS)
            def call(self,name,args):
                self.calls.append((name,args))
                return {"ok":True,"capture":{"network_events":[{"status":200}]}},False
        mcp=MCP(); model=Model()
        outcome=Agent(model,lambda:mcp).run([],
            "Проверь Network DevTools https://simnet.ua/",force_tools=True)
        self.assertEqual(outcome["tool_calls"],1)
        self.assertEqual(outcome["selected_by"],"evidence_first_fallback")
        self.assertEqual(mcp.calls[0][0],"browser_network")
        self.assertIn("Network получен",outcome["answer"])
        self.assertTrue(any(x["name"]=="browser_network" for x in outcome["events"]))


if __name__ == "__main__":
    unittest.main()
