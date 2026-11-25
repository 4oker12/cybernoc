"""Offline mock tests for the two scope-aware DNS/TLS metadata adapters."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from console.scoped_network_tools import SCOPED_TOOLS, scoped_call
from console.traffic_tools import TrafficToolClient

class ScopeMCP:
    def __init__(self, hosts=None):self.hosts=hosts or ["simnet.ua"];self.calls=[]
    def initialize(self):return [{"name":"gateway_status","inputSchema":{"type":"object","properties":{}}}]
    def call(self, name,args):
        self.calls.append((name,args))
        return {"authorized_hosts":self.hosts,"ok":True},False

class ScopedTests(unittest.TestCase):
    def test_two_real_tools_are_in_qwen_catalog(self):
        names=[t["name"] for t in TrafficToolClient(ScopeMCP(),{}).initialize()]
        self.assertIn("scoped_dns_resolve", names)
        self.assertIn("scoped_tls_inspect", names)

    def test_outside_scope_refused_without_any_dns(self):
        upstream=ScopeMCP()
        with patch("console.scoped_network_tools.socket.getaddrinfo") as resolver:
            with self.assertRaisesRegex(ValueError,"hostname_not_in_mcp_scope"):
                scoped_call("scoped_dns_resolve",{"host":"evil.example"},upstream)
            resolver.assert_not_called()

    def test_public_dns_resolves_single_approved_hostname(self):
        upstream=ScopeMCP()
        with patch("console.scoped_network_tools.socket.getaddrinfo",
                   return_value=[(2,1,6,"",("93.184.216.34",443))]):
            result=scoped_call("scoped_dns_resolve",{"host":"simnet.ua"},upstream)
        self.assertEqual(result["addresses"],["93.184.216.34"])
        self.assertTrue(result["scope_confirmed"])

    def test_local_ip_dns_rebinding_blocked(self):
        upstream=ScopeMCP()
        with patch("console.scoped_network_tools.socket.getaddrinfo",
                   return_value=[(2,1,6,"",("127.0.0.1",443))]):
            with self.assertRaisesRegex(ValueError,"non_public_dns_answer"):
                scoped_call("scoped_tls_inspect",{"host":"simnet.ua"},upstream)

    def test_untrusted_scope_does_not_allow_dns(self):
        class NoScope:
            def call(self,name,args):return {"ok":False},True
        with patch("console.scoped_network_tools.socket.getaddrinfo") as resolver:
            with self.assertRaisesRegex(ValueError,"cannot_confirm_current_scope"):
                scoped_call("scoped_dns_resolve",{"host":"simnet.ua"},NoScope())
            resolver.assert_not_called()

    def test_unrelated_scoped_function_denied(self):
        with self.assertRaisesRegex(ValueError,"unknown_scoped_tool"):
            scoped_call("scoped_port_scan",{"host":"simnet.ua"},ScopeMCP())

if __name__=="__main__":
    unittest.main()
