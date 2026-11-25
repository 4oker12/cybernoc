"""Real owner-selected target profiles, persistence and detailed Network evidence."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from fastapi.testclient import TestClient
from console import server, research_scope, devtools_network
from console.tunnel_access import allowed_path
from console.agent import Agent


class ResearchScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db=Path(self.temp.name)/"communications.sqlite3"
        self.store=research_scope.ResearchScopeStore(self.db)

    def test_valid_target_profiles_for_any_owner_selected_domain(self):
        a=research_scope.scope_profile(["EXAMPLE.ORG","service.example.net"],"evidence")
        self.assertEqual(a["hosts"],["example.org","service.example.net"])
        self.assertEqual(a["active_actions"],"propose_and_confirm")
        self.assertEqual(research_scope.scope_profile(["198.51.100.10"])["hosts"],
                         ["198.51.100.10"])
        for invalid in ("http://example.org","*.example.org","localhost",
                        "http://127.0.0.1","https://other.site/path","-bad.net"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    research_scope.scope_profile([invalid])

    def test_scope_isolation_and_sqlite_persistence(self):
        a=research_scope.scope_profile(["one.example.org"],"metadata")
        b=research_scope.scope_profile(["two.example.net"],"evidence")
        self.store.save("task_one",a)
        self.store.save("task_two",b)
        again=research_scope.ResearchScopeStore(self.db)
        self.assertEqual(again.load("task_one")["hosts"],["one.example.org"])
        self.assertEqual(again.load("task_two")["hosts"],["two.example.net"])
        self.assertEqual(again.load("task_one")["capture_detail"],"metadata")
        self.assertEqual(again.load("task_other")["hosts"],[])

    def test_owner_controls_scope_via_explicit_web_ui(self):
        with patch.object(server,"research_scope_store",return_value=self.store):
            api=TestClient(server.app,base_url="http://127.0.0.1:18794")
            r=api.post("/api/research/scope",json={
                "hosts":["example.org","another.example.net"],
                "capture_detail":"evidence"
            })
            self.assertEqual(r.status_code,200,r.text)
            sid=r.json()["session_id"]
            scope=api.get("/api/research/scope",params={"session_id":sid}).json()["scope"]
            self.assertEqual(scope["hosts"],["example.org","another.example.net"])
            self.assertEqual(scope["capture_detail"],"evidence")
            bad=api.post("/api/research/scope",json={"session_id":sid,
                "hosts":["127.0.0.1:443"],"capture_detail":"evidence"})
            self.assertEqual(bad.status_code,422)
        self.assertTrue(allowed_path("/api/research/scope","GET"))
        self.assertTrue(allowed_path("/api/research/scope","POST"))

    def test_no_fixed_domain_in_upgrader(self):
        deploy=(ROOT/"console/upgrade_communication.py").read_text(encoding="utf-8")
        self.assertNotIn("CYBERNOVA_BROWSER_HOSTS=simnet.ua",deploy)
        html=(ROOT/"console/static/index.html").read_text(encoding="utf-8")
        js=(ROOT/"console/static/app.js").read_text(encoding="utf-8")
        for key in ('id="researchTargets"','id="captureDetail"',
                    'id="applyResearchScope"','id="scopeStatus"'):
            self.assertIn(key,html)
        self.assertIn('async function applyResearchScope()',js)
        self.assertIn('"/api/research/scope"',js)

    def test_model_receives_target_and_can_use_it_without_explicit_url(self):
        class Model:
            model="offline"
            def __init__(self):self.system=[]
            def chat(self,messages,tools=None,**kwargs):
                self.system=[m.get("content","") for m in messages if m["role"]=="system"]
                if kwargs.get("json_mode"):
                    return {"role":"assistant","content":'{"calls":[]}'}
                if any(x.get("role")=="tool" for x in messages):
                    return {"role":"assistant","content":"Проверено: результат получен"}
                return {"role":"assistant","content":"Нужны инструменты"}
        class MCP:
            def __init__(self):self.called=[]
            def initialize(self):
                from console.browser_tools import BROWSER_TOOLS
                return BROWSER_TOOLS
            def call(self,name,args):
                self.called.append((name,args))
                return {"ok":True,"http_status":200},False
        m=MCP();model=Model()
        result=Agent(model,lambda:m).run([],"Исследуй сайт",scope={
            "hosts":["example.org"],"capture_detail":"evidence"
        })
        self.assertEqual(result["tool_calls"],1)
        self.assertEqual(m.called[0],("browser_open",{"url":"https://example.org/"}))
        self.assertEqual(result["selected_by"],"evidence_first_fallback")
        self.assertTrue(any("example.org" in x for x in model.system))


class EvidenceTests(unittest.TestCase):
    def test_json_shape_preserves_keys_and_masks_sensitive_fields(self):
        payload=json.dumps({
            "customer":{"email":"person@example.org","token":"aaa",
                        "name":"public_label","active":True},
            "rows":[{"status":"ok","count":3}],
        }).encode()
        evidence=devtools_network.summarize_response(
            "application/json",payload,
            {"Content-Type":"application/json","Set-Cookie":"session=SECRET",
             "Cache-Control":"max-age=60","Server":"nginx"})
        self.assertEqual(evidence["body_size"],len(payload))
        self.assertEqual(len(evidence["body_sha256"]),64)
        self.assertNotIn("set-cookie",evidence["headers"])
        self.assertEqual(evidence["json_shape"]["customer"]["email"],"[REDACTED FIELD]")
        self.assertEqual(evidence["json_shape"]["customer"]["token"],"[REDACTED FIELD]")
        self.assertIn("rows",evidence["json_shape"])
        self.assertEqual(evidence["headers"]["server"],"nginx")

    def test_safe_text_excerpt_and_hash_for_comparison(self):
        a=devtools_network.summarize_response("text/plain",
            b"Result OK; contact person@example.org")
        b=devtools_network.summarize_response("text/plain",
            b"Result FAIL; contact person@example.org")
        self.assertNotEqual(a["body_sha256"],b["body_sha256"])
        self.assertIn("[REDACTED]",a["body_preview"])
        self.assertIn("Result OK",a["body_preview"])


if __name__=="__main__":
    unittest.main()
