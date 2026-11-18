"""End-to-end offline parser tests for Cybernova cross-domain research tools."""
from __future__ import annotations

import base64
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from console.traffic_intelligence import analyze_har, analyze_js, TrafficError
from console.domain_intelligence import (
    analyze_openapi, analyze_log, analyze_config, analyze_python,
    analyze_dependencies, analyze_tls, analyze_pcap, DomainError
)
from console.traffic_tools import TrafficToolClient
from console.domain_tools import DOMAIN_TOOLS


def fixture_har():
    return json.dumps({"log":{"version":"1.2","creator":{"name":"test","version":"1"},
    "entries":[{"time":18,"request":{
        "method":"GET",
        "url":"https://cabinet.example.test/api/contracts/123456?token=ULTRA_SECRET&contract_id=44",
        "headers":[{"name":"Authorization","value":"Bearer ULTRA_SECRET"}]},
        "response":{"status":200,"headers":[
            {"name":"Set-Cookie","value":"session=ULTRA_SECRET; HttpOnly; Secure; SameSite=Lax"},
            {"name":"Cache-Control","value":"private"}],
            "content":{"mimeType":"application/json",
                       "text":'{"balance":100, "role":"subscriber", "token":"ULTRA_SECRET","contract":{"id":44}}'}}}]}})


class FakeUpstream:
    def initialize(self):return [{"name":"gateway_status","inputSchema":{"type":"object","properties":{}}}]
    def call(self,name,args):
        if name=="gateway_status":return {"ok":True},False
        raise AssertionError("Unknown forwarded tool")


class MultiDomainTests(unittest.TestCase):
    def test_har_never_retains_secret_values_or_instance_ids(self):
        result=analyze_har(fixture_har())
        dump=json.dumps(result)
        self.assertNotIn("ULTRA_SECRET",dump)
        self.assertNotIn("/123456",dump)
        self.assertIn("token",dump)
        self.assertEqual(result["endpoints"][0]["path"],"/api/contracts/{object}")
        self.assertEqual(result["requests_analyzed"],1)
        self.assertEqual(result["cookies"][0]["samesite"],"lax")

    def test_openapi_analysis_security_and_methods(self):
        report=analyze_openapi(json.dumps({
            "openapi":"3.0.1","paths":{
              "/api/accounts/{id}":{
                "get":{"parameters":[{"name":"id","in":"path"}],"responses":{"200":{}}},
                "post":{"security":[{"apiKey":[]}],"responses":{"201":{}}},
              }},"components":{"securitySchemes":{"apiKey":{"type":"apiKey"}}}
        }))
        self.assertEqual(report["operation_count"],2)
        self.assertEqual(len(report["observations"]),2)
        self.assertIn("apiKey",report["security_scheme_names"])
        self.assertFalse(any(x["verified"] for x in report["observations"]))

    def test_logs_count_transport_dns_radius_and_pon(self):
        report=analyze_log("ERROR SEC_E_MESSAGE_ALTERED password=SECRET\n"
                           "WARN NXDOMAIN resolver\n"
                           "INFO RADIUS Access-Reject subscriber=42\n"
                           "LOS ONU OLT port 3\n")
        self.assertEqual(report["signal_counts"]["tls_integrity"],1)
        self.assertEqual(report["signal_counts"]["dns"],1)
        self.assertEqual(report["signal_counts"]["radius"],1)
        self.assertEqual(report["signal_counts"]["pon"],1)
        self.assertNotIn("SECRET",json.dumps(report))

    def test_config_finds_root_login_and_debug_without_secret(self):
        report=analyze_config("PermitRootLogin yes\nAPP_DEBUG=true\n"
                              "password=TOP_SECRET\n")
        types={x["type"] for x in report["observations"]}
        self.assertIn("ssh_root_login",types)
        self.assertIn("app_debug",types)
        self.assertNotIn("TOP_SECRET",json.dumps(report))

    def test_python_ast_flags_shell_without_execution(self):
        report=analyze_python("import subprocess\n"
                              "def run(user_input):\n"
                              "    return subprocess.run(user_input,shell=True)\n")
        kinds={x["type"] for x in report["observations"]}
        self.assertIn("python_shell_subprocess",kinds)
        self.assertIn("python_shell_true",kinds)

    def test_javascript_source_sink_only_hypothesis(self):
        report=analyze_js('let x=location.search; document.body.innerHTML=x; '
                          'fetch("/api/accounts/list");')
        self.assertIn("source_sink_candidate",{x["type"] for x in report["observations"]})
        self.assertFalse(any(x["verified_vulnerability"] for x in report["observations"]))

    def test_dependencies_cyclonedx_and_requirements(self):
        req=analyze_dependencies("requests==2.32.3\nhttpx>=0.26.0\n")
        self.assertEqual(req["package_count"],2)
        sbom=analyze_dependencies(json.dumps({"bomFormat":"CycloneDX",
                   "components":[{"name":"example","version":"1.0.0"}]}))
        self.assertEqual(sbom["packages"],[{"name":"example","version":"1.0.0"}])
        self.assertNotIn("CVE",json.dumps(req))

    def test_tls_transcript_offline(self):
        report=analyze_tls("Protocol  : TLSv1.2\n"
                           "Cipher    : ECDHE-RSA-AES128-GCM-SHA256\nbad mac\n")
        self.assertEqual(report["cipher_mentions"]["ECDHE-RSA-AES128-GCM-SHA256"],1)
        self.assertEqual(report["protocol_mentions"]["TLSv1.2"],1)
        self.assertEqual(report["observations"][0]["type"],"tls_handshake_error")

    def test_vlan_3000_tcp_syn_pcap_sanitized(self):
        # classic little-endian Ethernet capture, one QinQ/802.1q frame
        ip=b"\x45\x00"+b"\x00\x28"+b"\x00\x01\x00\x00\x40\x06\x00\x00"+bytes([192,0,2,1])+bytes([198,51,100,2])
        tcp=struct.pack("!HHII",12345,443,1,0)+b"\x50\x02\x20\x00\x00\x00\x00\x00"
        ethernet=b"\xaa"*6+b"\xbb"*6+struct.pack("!H",0x8100)+struct.pack("!HH",3000,0x0800)
        frame=ethernet+ip+tcp
        header=b"\xd4\xc3\xb2\xa1"+struct.pack("<HHiiii",2,4,0,0,65535,1)
        pkt=struct.pack("<IIII",1,0,len(frame),len(frame))+frame
        report=analyze_pcap(base64.b64encode(header+pkt).decode())
        self.assertEqual(report["packet_count"],1)
        self.assertEqual(report["vlan_ids"][3000],1)
        self.assertEqual(report["tcp_flag_counts"]["SYN"],1)
        self.assertEqual(report["top_destination_ports"][443],1)
        self.assertNotIn("192.0.2.1",json.dumps(report))
        self.assertNotIn("198.51.100.2",json.dumps(report))

    def test_multi_domain_tools_registered_and_operational(self):
        har=analyze_har(fixture_har())
        log=analyze_log("ERROR SEC_E_MESSAGE_ALTERED")
        pcap=analyze_openapi('{"openapi":"3.0.0","paths":{"/api/users":{"get":{"responses":{"200":{}}}}}}')
        artifacts={"abc":har,"def":log,"xyz":pcap}
        bridge=TrafficToolClient(FakeUpstream(),artifacts)
        tools=[x["name"] for x in bridge.initialize()]
        self.assertEqual(len(DOMAIN_TOOLS),13)
        self.assertIn("research_network_logs",tools)
        self.assertIn("research_openapi_routes",tools)
        self.assertIn("traffic_hypotheses",tools)
        for name,args in (("research_capabilities",{}),
                          ("research_artifacts",{}),
                          ("research_network_logs",{}),
                          ("research_openapi_routes",{}),
                          ("research_authorization_matrix",{}),
                          ("research_findings",{}),
                          ("research_next_steps",{}),
                          ("research_full_report",{})):
            data,failed=bridge.call(name,args)
            self.assertFalse(failed,(name,data))
            self.assertTrue(data["ok"],name)
            self.assertNotIn("ULTRA_SECRET",json.dumps(data))
        self.assertEqual(bridge.call("gateway_status",{})[0]["ok"],True)

    def test_reject_unsupported_pcapng_and_invalid_artifacts(self):
        with self.assertRaises(DomainError):analyze_pcap(base64.b64encode(b"BADCAP").decode())
        with self.assertRaises(DomainError):analyze_openapi('{"paths":{}}')
        with self.assertRaises(TrafficError):analyze_har("not json")

if __name__=="__main__":
    unittest.main()
