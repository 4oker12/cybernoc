"""End-to-end tests for the actual local UI controller and offline tool executions.

Uses loopback ephemeral port and synthetic local data. No SIMNET requests or
external scanning. Fails if unknown tools, CSRF bypasses or scope escapes work.
"""
from __future__ import annotations
import json
import sys
import tempfile
import threading
from pathlib import Path
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app import build_state, make_handler
from core.offline_tools import SPECS, ToolError, dispatch_tool

class OfflineToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.state=build_state(db_path=Path(self.temp.name)/"test.db")

    def tearDown(self):
        self.temp.cleanup()

    def run_tool(self,name,arguments=None):
        return dispatch_tool(name,arguments or {},self.state)["result"]

    def test_offline_tools_have_generic_names(self):
        self.assertGreaterEqual(len(SPECS),18)
        self.assertFalse(any("simnet" in name or "cybernova" in name for name in SPECS))

    def test_engagement_is_draft_and_not_authorized(self):
        out=self.run_tool("engagement_validate")
        self.assertEqual(out["status"],"draft")
        self.assertFalse(out["network_authorized"])

    def test_scope_checker_does_not_authorize(self):
        out=self.run_tool("scope_check",{"url":"https://simnet.ua/"})
        self.assertFalse(out["in_listed_scope"])
        self.assertFalse(out["can_execute_network"])

    def test_planner_is_non_executing(self):
        out=self.run_tool("plan_build")
        self.assertEqual(out["execution"],"planning_only")
        self.assertGreaterEqual(out["stage_count"],10)

    def test_plan_blocks_remote_or_unknown_tools(self):
        plan=json.dumps([{"tool":"python_static_review"},
              {"tool":"http_get","url":"https://simnet.ua/"},
              {"tool":"totally_unregistered_tool"}])
        result=self.run_tool("plan_validate",{"steps":plan})
        self.assertFalse(result["ok"])
        self.assertTrue(result["steps"][0]["allowed"])
        self.assertFalse(result["steps"][1]["allowed"])
        self.assertFalse(result["steps"][2]["allowed"])

    def test_ip_offline(self):
        v=self.run_tool("ip_network_summary",{"cidr":"192.0.2.134/24"})
        self.assertEqual(v["network"],"192.0.2.0/24")
        self.assertEqual(v["total_addresses"],256)

    def test_headers_drop_sensitive_information(self):
        result=self.run_tool("http_header_review",{"raw_headers":
                 "HTTP/1.1 200 OK\nServer: nginx\nSet-Cookie: sid=secret\nAuthorization: Bearer abc\n"
                 "Strict-Transport-Security: max-age=300"})
        self.assertEqual(result["safe_headers"]["server"],"nginx")
        self.assertNotIn("secret",str(result))
        self.assertNotIn("Bearer",str(result))

    def test_python_source_is_never_executed(self):
        source="import os\nos.system('should-never-run')\n"
        result=self.run_tool("python_static_review",{"source":source})
        self.assertTrue(result["parse_ok"])
        self.assertEqual(result["observations"][0]["symbol"],"os.system")
        self.assertEqual(result["classification"],"static_heuristic_not_confirmed_vulnerability")

    def test_dynamic_sql_observation(self):
        result=self.run_tool("python_static_review",{"source":
            'cursor.execute("SELECT * FROM users WHERE name="+name)'})
        self.assertTrue(any(x["kind"]=="dynamic_sql_candidate"
                            for x in result["observations"]))

    def test_api_schema_import_never_contacts_target(self):
        value={"openapi":"3.1.0","servers":[{"url":"https://thirdparty.example"}],
               "paths":{"/users/{id}":{"get":{"operationId":"getUser"},
                                      "patch":{"operationId":"updateUser"}}}}
        result=self.run_tool("api_schema_import",{"schema":json.dumps(value)})
        self.assertEqual(result["endpoint_count"],2)
        self.assertEqual(result["path_count"],1)
        self.assertIn("no endpoint was contacted",result["note"])

    def test_findings_require_human_review_and_digest(self):
        finding=self.run_tool("finding_create",{"title":"Synthetic role hypothesis",
            "asset":"example.invalid","summary":"Role B might see role A objects in test fixture",
            "state":"hypothesis","confidence":"low"})
        fid=finding["id"]
        self.assertTrue(fid.startswith("F-"))
        with self.assertRaises(ValueError):
            self.run_tool("finding_verify",{"finding_id":fid,"state":"verified",
                                            "reviewer":"Test Reviewer"})
        r=self.run_tool("finding_verify",{"finding_id":fid,"state":"verified",
                  "reviewer":"Test Reviewer","evidence_sha256":"a"*64})
        self.assertEqual(r["state"],"verified")
        report=self.run_tool("report_generate")
        self.assertEqual(report["verified"],1)
        self.assertIn("Synthetic role hypothesis",report["markdown"])
        with self.assertRaises(ValueError):
            self.run_tool("finding_verify",{"finding_id":fid,"state":"rejected",
                                            "reviewer":"Test Reviewer"})

    def test_cannot_store_secret_text(self):
        with self.assertRaises(ToolError):
            self.run_tool("finding_create",{"title":"Synthetic token leakage",
                "asset":"example.invalid",
                "summary":"Authorization: Bearer secret",
                "state":"hypothesis"})

    def test_hash_never_exposes_raw(self):
        out=self.run_tool("evidence_hash",{"content":"canary-only"})
        self.assertEqual(out["bytes_hashed"],11)
        self.assertNotIn("canary-only",str(out))

    def test_unknown_tool_cannot_be_executed(self):
        with self.assertRaises(ToolError):
            self.run_tool("http_get",{"url":"https://simnet.ua/"})

    def test_tools_catalog_explicitly_marks_planned(self):
        t=self.run_tool("tool_catalog")
        self.assertGreaterEqual(t["registered_capabilities"],80)
        self.assertIn("http_get",t["not_executable_here"])


class ConsoleHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.state=build_state(db_path=Path(cls.temp.name)/"http-test.db")
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),
                  make_handler(cls.state,port=0))
        cls.port=cls.server.server_port
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        cls.temp.cleanup()

    def url(self,path):
        return f"http://127.0.0.1:{self.port}"+path

    def get(self,path):
        return urlopen(self.url(path),timeout=3)

    def post(self,payload,headers=None):
        standard={"Content-Type":"application/json",
                  "X-Cybernova-CSRF":self.state["csrf_token"]}
        if headers:
            standard.update(headers)
        request=Request(self.url("/api/run"),data=json.dumps(payload).encode(),
                        headers=standard,method="POST")
        return urlopen(request,timeout=3)

    def test_status_lists_ready_offline_capabilities(self):
        with self.get("/api/status") as r:
            data=json.load(r)
        self.assertTrue(data["ok"])
        self.assertFalse(data["result"]["network_scanning_available"])

    def test_tools_endpoint_separates_planned(self):
        with self.get("/api/tools") as r:
            data=json.load(r)
        self.assertIn("plan_build",data["available"])
        self.assertNotIn("http_get",data["available"])
        self.assertGreaterEqual(data["registered_total"],80)

    def test_assets_not_authorized_in_ui(self):
        with self.get("/api/project") as r:
            data=json.load(r)
        self.assertEqual(data["status"],"draft")
        self.assertTrue(all(not a["in_scope"] for a in data["assets"]))

    def test_ui_static_assets_load(self):
        for path,mime in [("/","text/html"),("/assets/style.css","text/css"),
                          ("/assets/app.js","text/javascript")]:
            with self.get(path) as r:
                self.assertIn(mime,r.headers["Content-Type"])
                self.assertIn("no-store",r.headers["Cache-Control"])
                body=r.read()
                self.assertGreater(len(body),500)
                if path=="/":
                    self.assertNotIn(b"__CSRF_TOKEN__",body)

    def test_real_tool_execution_over_http(self):
        with self.post({"tool":"ip_network_summary",
                        "arguments":{"cidr":"198.51.100.56/24"}}) as r:
            data=json.load(r)
        self.assertEqual(data["result"]["network"],"198.51.100.0/24")

    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(HTTPError) as caught:
            self.post({"tool":"http_get","arguments":{"url":"https://simnet.ua/"}})
        self.assertEqual(caught.exception.code,400)

    def test_no_csrf_rejected(self):
        with self.assertRaises(HTTPError) as caught:
            self.post({"tool":"plan_build"},headers={"X-Cybernova-CSRF":"bad"})
        self.assertEqual(caught.exception.code,403)

    def test_cross_site_origin_rejected(self):
        with self.assertRaises(HTTPError) as caught:
            self.post({"tool":"plan_build"},headers={"Origin":"https://evil.example"})
        self.assertEqual(caught.exception.code,403)

    def test_malformed_json_rejected(self):
        request=Request(self.url("/api/run"),data=b"{unclosed",
                        headers={"Content-Type":"application/json",
                                 "X-Cybernova-CSRF":self.state["csrf_token"]},method="POST")
        with self.assertRaises(HTTPError) as caught:
            urlopen(request,timeout=3)
        self.assertEqual(caught.exception.code,400)

    def test_host_header_rejected(self):
        request=Request(self.url("/api/status"),headers={"Host":"evil.example"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request,timeout=3)
        self.assertEqual(caught.exception.code,403)


if __name__=="__main__":
    unittest.main()
