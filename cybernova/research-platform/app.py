#!/usr/bin/env python3
"""Cybernova local, offline-first Research Console.

Binds to loopback only, no public listener and no arbitrary command execution.
All POST operations use fixed offline capability handlers and deny-by-default
dispatch. Neither the UI nor the API can launch scanners or change engagement.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import time
from urllib.parse import urlsplit

from core.offline_tools import SPECS, GROUPS, ToolError, dispatch_tool
from core.policy import read_json
from core.storage import CaseStore

ROOT = Path(__file__).resolve().parent
MAX_POST_BYTES = 65536
MAX_OUTPUT_BYTES = 120000
STATIC = {"/":("ui/index.html","text/html; charset=utf-8"),
          "/assets/app.js":("ui/app.js","text/javascript; charset=utf-8"),
          "/assets/style.css":("ui/style.css","text/css; charset=utf-8")}

def build_state(*, project_path=None, catalog_path=None, db_path=None):
    project=read_json(project_path or ROOT/"profiles/simnet.example.json")
    catalog=read_json(catalog_path or ROOT/"tools/catalog.json")
    store=CaseStore(db_path or ROOT/"state/cybernova.db")
    return {"engagement":project,"catalog":catalog,"store":store,
            "csrf_token":secrets.token_urlsafe(32),"boot_time":time.time()}

def make_handler(state, *, port):
    allowed_hosts={f"127.0.0.1:{port}",f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version="Cybernova-Research/0.1"
        sys_version=""
        protocol_version="HTTP/1.1"

        def log_message(self,fmt,*args):
            # Never log raw URLs, secrets or request bodies.
            pass

        def headers_out(self, mime, length, code=200):
            self.send_response(code)
            self.send_header("Content-Type",mime)
            self.send_header("Content-Length",str(length))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("X-Frame-Options","DENY")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.end_headers()

        def send_json(self, obj, code=200):
            try:
                data=json.dumps(obj,ensure_ascii=False).encode("utf-8")
            except (TypeError,ValueError):
                data=b'{"ok":false,"error":"serialization_error"}'
                code=500
            if len(data)>MAX_OUTPUT_BYTES:
                data=b'{"ok":false,"error":"response_too_large"}'
                code=413
            self.headers_out("application/json; charset=utf-8",len(data),code)
            self.wfile.write(data)

        def _safe_host(self):
            return self.headers.get("Host","").lower() in allowed_hosts

        def do_GET(self):
            if not self._safe_host():
                return self.send_json({"ok":False,"error":"invalid_host"},403)
            path=urlsplit(self.path).path
            if path in STATIC:
                filename,mime=STATIC[path]
                content=(ROOT/filename).read_bytes()
                if path=="/":
                    content=content.replace(b"__CSRF_TOKEN__",
                       state["csrf_token"].encode("ascii"))
                self.headers_out(mime,len(content))
                self.wfile.write(content)
                return
            if path=="/api/status":
                return self.send_json(dispatch_tool("gateway_status",{},state))
            if path=="/api/tools":
                full={t["name"]:t for t in state["catalog"].get("tools",[])
                      if isinstance(t,dict) and "name" in t}
                return self.send_json({
                    "ok":True,"groups":GROUPS,
                    "available":{k:{"name":k,**v} for k,v in SPECS.items()},
                    "registered_total":len(full),
                    "planned":[{"name":t["name"],"description":t.get("description",""),
                                "mode":t.get("mode",""),"group":t.get("family","Other"),
                                "status":t.get("status","planned")}
                               for t in full.values() if t["name"] not in SPECS]
                })
            if path=="/api/project":
                e=state["engagement"]
                return self.send_json({"ok":True,"name":e.get("project"),
                    "status":e.get("status"),"max_mode":e.get("max_mode"),
                    "assets":[{"hostname":x.get("hostname"),"label":x.get("label"),
                               "in_scope":x.get("in_scope") is True}
                              for x in e.get("assets",[]) if isinstance(x,dict)],
                    "note":"Draft status is not authorization for network tests"})
            if path=="/api/findings":
                return self.send_json({"ok":True,"items":state["store"].list_findings(100)})
            if path=="/api/events":
                return self.send_json({"ok":True,"items":state["store"].list_events(70)})
            if path=="/api/report":
                return self.send_json(dispatch_tool("report_generate",{},state))
            return self.send_json({"ok":False,"error":"not_found"},404)

        def do_POST(self):
            if not self._safe_host():
                return self.send_json({"ok":False,"error":"invalid_host"},403)
            if urlsplit(self.path).path!="/api/run":
                return self.send_json({"ok":False,"error":"not_found"},404)
            origin=self.headers.get("Origin")
            if origin and origin not in {f"http://{x}" for x in allowed_hosts}:
                return self.send_json({"ok":False,"error":"cross_origin_denied"},403)
            if not secrets.compare_digest(
                self.headers.get("X-Cybernova-CSRF",""),state["csrf_token"]):
                return self.send_json({"ok":False,"error":"csrf_denied"},403)
            if self.headers.get("Content-Type","").split(";")[0].strip().lower()!="application/json":
                return self.send_json({"ok":False,"error":"content_type_required"},415)
            try:
                n=int(self.headers.get("Content-Length","-1"))
            except ValueError:
                n=-1
            if n<=0 or n>MAX_POST_BYTES:
                return self.send_json({"ok":False,"error":"invalid_body_size"},413)
            try:
                payload=json.loads(self.rfile.read(n))
                if not isinstance(payload,dict):
                    raise ValueError("object required")
                name=payload.get("tool")
                args=payload.get("arguments",{})
                result=dispatch_tool(name,args,state)
            except (ValueError,ToolError) as ex:
                if isinstance(payload if "payload" in locals() else None,dict):
                    name=payload.get("tool")
                else:
                    name=None
                if isinstance(name,str) and name in SPECS:
                    state["store"].log(name,"rejected")
                return self.send_json({"ok":False,"error":str(ex)[:180]},400)
            except Exception:
                return self.send_json({"ok":False,"error":"internal_error"},500)
            state["store"].log(name,"completed")
            return self.send_json(result)

    return Handler


def main():
    parser=argparse.ArgumentParser(description="Cybernova standalone local Research Console")
    parser.add_argument("--port",type=int,default=18794)
    parser.add_argument("--project",type=Path,default=ROOT/"profiles/simnet.example.json")
    parser.add_argument("--catalog",type=Path,default=ROOT/"tools/catalog.json")
    parser.add_argument("--db",type=Path,default=ROOT/"state/cybernova.db")
    parser.add_argument("--check",action="store_true",help="Load project and catalog without starting server")
    args=parser.parse_args()
    if not 1024<=args.port<=65535:
        parser.error("Port must be 1024..65535")
    args.db.parent.mkdir(parents=True,exist_ok=True)
    state=build_state(project_path=args.project,catalog_path=args.catalog,db_path=args.db)
    if args.check:
        print(json.dumps({"ok":True,"ready_offline":len(SPECS),
          "manifest_capabilities":len(state["catalog"].get("tools",[])),
          "project_status":state["engagement"].get("status")},ensure_ascii=False))
        return
    server=ThreadingHTTPServer(("127.0.0.1",args.port),make_handler(state,port=args.port))
    server.daemon_threads=True
    print(f"CYBERNOVA_RESEARCH_CONSOLE=http://127.0.0.1:{args.port}/",flush=True)
    server.serve_forever(poll_interval=0.5)


if __name__=="__main__":
    main()
