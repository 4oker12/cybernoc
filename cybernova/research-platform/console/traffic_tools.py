"""Per-session, offline Traffic Intelligence functions presented as MCP-style tools.

In-memory artifacts are already sanitized by traffic_intelligence.py. No tool
can access arbitrary filesystem paths, open sockets, replay a HAR, execute JS,
or receive raw captured secret values.
"""
from __future__ import annotations

from collections import Counter
try:
    from .traffic_intelligence import api_graph, hypotheses, audit_report
except ImportError:
    from traffic_intelligence import api_graph, hypotheses, audit_report

MAX_ARTIFACTS = 12
MAX_PAGE = 30


def _definition(name, description, properties=None, required=None):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties or {},
                            "required": required or [], "additionalProperties": False}}


ID = {"artifact_id": {"type": "string", "description": "ID from traffic_inventory or uploaded artifact."}}
PAGING = {"offset": {"type": "integer"}, "limit": {"type": "integer"}}
LOCAL_TOOLS = [
    _definition("traffic_inventory",
        "List sanitized HAR and JavaScript artifacts uploaded in this chat. No raw source values."),
    _definition("traffic_api_map",
        "Inspect observed HTTP endpoints, methods, status codes, query/JSON field NAMES and evidence IDs; no values, no network.",
        {**PAGING}),
    _definition("traffic_js_review",
        "Inspect uploaded JavaScript URL strings and potential DOM sinks/sources as hypotheses; no JS execution.",
        {**ID}, ["artifact_id"]),
    _definition("traffic_session_review",
        "Inspect cookie attribute flags, authentication-header presence, methods and status codes observed in user HAR, not cookie values."),
    _definition("traffic_graph",
        "Inspect a passive graph of observed API routes, host relations and shared field names. No relationship is an authorization proof.",
        {**PAGING}),
    _definition("traffic_hypotheses",
        "Prioritize BOLA/IDOR, excessive data exposure, session control, race/business logic and XSS hypotheses with evidence IDs."),
    _definition("traffic_report",
        "Generate a structured, evidence-linked OFFLINE audit summary. No unverified issue is reported as an exploit."),
    _definition("traffic_compare",
        "Compare two sanitized HAR artifacts from the same chat (endpoint/method/status changes only, no raw data).",
        {"left_id": {"type": "string"}, "right_id": {"type": "string"}},
        ["left_id", "right_id"]),
]
LOCAL_NAMES = frozenset(t["name"] for t in LOCAL_TOOLS)


class TrafficToolClient:
    """Composite client delegating existing real MCP calls and 8 local analyzers."""
    def __init__(self, upstream, artifacts: dict):
        self.upstream = upstream
        self.artifacts = artifacts

    def initialize(self) -> list[dict]:
        try:
            from .domain_tools import DOMAIN_TOOLS
            from .scoped_network_tools import SCOPED_TOOLS
            from .lab_scanners import SCANNER_TOOLS
            from .browser_tools import BROWSER_TOOLS
            from .devtools_network import NETWORK_TOOLS
        except ImportError:
            from domain_tools import DOMAIN_TOOLS
            from scoped_network_tools import SCOPED_TOOLS
            from lab_scanners import SCANNER_TOOLS
            from browser_tools import BROWSER_TOOLS
            from devtools_network import NETWORK_TOOLS
        try:
            remote = self.upstream.initialize()
        except Exception:
            # Offline artifact reasoning remains possible if remote MCP is down.
            remote = []
        return remote + LOCAL_TOOLS + DOMAIN_TOOLS + SCOPED_TOOLS + SCANNER_TOOLS + BROWSER_TOOLS + NETWORK_TOOLS

    def _reports(self) -> list[dict]:
        return list(self.artifacts.values())[:MAX_ARTIFACTS]

    def _find(self, artifact_id: str) -> dict:
        if not isinstance(artifact_id, str) or len(artifact_id) > 100:
            raise ValueError("invalid_artifact_id")
        if artifact_id not in self.artifacts:
            raise ValueError("artifact_not_found_in_this_session")
        return self.artifacts[artifact_id]

    def call(self, name: str, args: dict) -> tuple[dict, bool]:
        try:
            from .domain_tools import DOMAIN_NAMES, domain_call
            from .scoped_network_tools import SCOPED_NAMES, scoped_call
            from .lab_scanners import SCANNER_TOOL_NAMES, dispatch_scanner
            from .browser_tools import BROWSER_NAMES, browser_call
            from .devtools_network import NETWORK_NAMES, network_call
        except ImportError:
            from domain_tools import DOMAIN_NAMES, domain_call
            from scoped_network_tools import SCOPED_NAMES, scoped_call
            from lab_scanners import SCANNER_TOOL_NAMES, dispatch_scanner
            from browser_tools import BROWSER_NAMES, browser_call
            from devtools_network import NETWORK_NAMES, network_call
        if name in NETWORK_NAMES:
            try:
                return network_call(name, args, self.upstream), False
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": type(exc).__name__+":"+str(exc)[:170]}, True
        if name in BROWSER_NAMES:
            try:
                return browser_call(name, args, self.upstream), False
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": type(exc).__name__+":"+str(exc)[:180]}, True
        if name in SCANNER_TOOL_NAMES:
            return dispatch_scanner(name, args)
        if name in SCOPED_NAMES:
            try:
                return {"ok": True, **scoped_call(name,args,self.upstream)}, False
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": type(exc).__name__+":"+str(exc)[:140]}, True
        if name in DOMAIN_NAMES:
            try:
                return {"ok": True, **domain_call(name, args, self.artifacts)}, False
            except (ValueError, TypeError, KeyError) as exc:
                return {"ok": False, "error": str(exc)[:180]}, True
        if name not in LOCAL_NAMES:
            return self.upstream.call(name, args)
        try:
            result = self._offline_call(name, args)
            return {"ok": True, **result}, False
        except (ValueError, TypeError, KeyError) as exc:
            return {"ok": False, "error": str(exc)[:180]}, True

    def _offline_call(self, name: str, args: dict) -> dict:
        if not isinstance(args, dict):
            raise ValueError("invalid_arguments")
        reports = self._reports()
        if name == "traffic_inventory":
            return {
                "artifacts": [{
                    "artifact_id": key, "kind": report["kind"],
                    "sha256": report["source_sha256"][:16],
                    "requests": report.get("requests_analyzed", 0),
                    "endpoints": len(report.get("endpoints", [])),
                    "js_paths": len(report.get("api_paths", [])),
                    "observations": len(report.get("observations", [])),
                } for key, report in list(self.artifacts.items())[:MAX_ARTIFACTS]],
                "raw_values_retained": False,
            }
        if name == "traffic_api_map":
            rows = []
            for report in reports:
                if report["kind"] == "har":
                    rows.extend(report.get("endpoints", []))
            off, limit = _paging(args, len(rows))
            return {"total": len(rows), "offset": off, "endpoints": rows[off:off + limit],
                    "note": "Observed requests only, not proof of authorization weakness"}
        if name == "traffic_js_review":
            report = self._find(args["artifact_id"])
            if report["kind"] != "javascript":
                raise ValueError("artifact_is_not_javascript")
            return {
                "artifact_id": args["artifact_id"],
                "api_paths": report.get("api_paths", [])[:100],
                "patterns": report.get("patterns", {}),
                "observations": report.get("observations", []),
                "limitations": report.get("limitations", []),
            }
        if name == "traffic_session_review":
            return {
                "captures": [{
                    "status_codes": report.get("status_codes", {}),
                    "methods": report.get("methods", {}),
                    "cookie_flags": report.get("cookies", [])[:40],
                    "auth_header_presence": sum(
                        bool(x.get("auth_header_present"))
                        for x in report.get("endpoints", [])),
                    "artifact_id": key,
                } for key, report in list(self.artifacts.items()) if report["kind"] == "har"],
                "note": "Cookie values, request bodies, tokens and PII were discarded",
            }
        if name == "traffic_graph":
            graph = api_graph(reports)
            off, limit = _paging(args, len(graph["edges"]))
            return {"node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]),
                    "nodes": graph["nodes"][:80], "edges": graph["edges"][off:off + limit],
                    "limitations": graph["limitations"]}
        if name == "traffic_hypotheses":
            return hypotheses(reports)
        if name == "traffic_report":
            return audit_report(reports)
        if name == "traffic_compare":
            left = self._find(args["left_id"])
            right = self._find(args["right_id"])
            if left["kind"] != "har" or right["kind"] != "har":
                raise ValueError("traffic_compare_requires_two_har_files")
            key = lambda e: (e["host"], e["method"], e["path"])
            a = {key(e): e for e in left["endpoints"]}
            b = {key(e): e for e in right["endpoints"]}
            return {
                "added_endpoints": [{"host": h, "method": m, "path": p} for h, m, p in sorted(b.keys()-a.keys())[:80]],
                "removed_endpoints": [{"host": h, "method": m, "path": p} for h, m, p in sorted(a.keys()-b.keys())[:80]],
                "changed_statuses": [{
                    "host": h, "method": m, "path": p,
                    "before": dict(a[(h,m,p)]["statuses"]), "after": dict(b[(h,m,p)]["statuses"]),
                } for h, m, p in sorted(a.keys()&b.keys()) if a[(h,m,p)]["statuses"] != b[(h,m,p)]["statuses"]][:80],
                "limitations": ["Passive comparison is not proof of a server-side bug"],
            }
        raise ValueError("unknown_offline_tool")


def _paging(args: dict, size: int) -> tuple[int, int]:
    offset, limit = args.get("offset", 0), args.get("limit", 15)
    if type(offset) is not int or type(limit) is not int:
        raise ValueError("paging_must_be_integer")
    if offset < 0 or limit < 1 or limit > MAX_PAGE:
        raise ValueError("paging_out_of_bounds")
    return min(size, offset), limit
