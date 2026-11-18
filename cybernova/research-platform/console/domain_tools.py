"""Research-domain tools: real offline analyzers with evidence-linked results.

All tools operate solely on previously sanitized in-memory artifacts. Any
unknown or not imported evidence is reported explicitly; no live target I/O.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from .traffic_tools import _definition, _paging
from .traffic_intelligence import api_graph, hypotheses

DOMAIN_TOOLS = [
    _definition("research_capabilities",
        "Enumerate actually implemented analysis domains, artifact parsers, limitations and next possible actions."),
    _definition("research_artifacts",
        "List all imported sanitized evidence by domain, source hash, counts, and parsing limitations."),
    _definition("research_openapi_routes",
        "Inspect OpenAPI route/method/parameter names, response status codes and declared security metadata.",
        {"offset": {"type": "integer"}, "limit": {"type": "integer"}}),
    _definition("research_authorization_matrix",
        "Build an evidence-backed API method/object authorization review table. Shows UNKNOWN permissions; never probes other accounts.",
        {"offset": {"type": "integer"}, "limit": {"type": "integer"}}),
    _definition("research_network_packets",
        "Inspect PCAP metadata: IPv4/TCP/UDP/ARP, VLAN/QinQ, TCP flags, anonymized flows and port counts."),
    _definition("research_network_logs",
        "Inspect parsed logs for TLS, DNS, DHCP, RADIUS, PON, routing and application signal classes; no raw log lines."),
    _definition("research_server_config",
        "Review uploaded server, reverse proxy, SSH, Kubernetes and Docker configs for configuration risks with line evidence."),
    _definition("research_code_review",
        "Review uploaded Python AST and JavaScript source/sink and endpoint evidence; no code execution."),
    _definition("research_dependencies",
        "Inspect uploaded npm, requirements, SPDX or CycloneDX inventory. No fabricated vulnerability matching."),
    _definition("research_tls_review",
        "Review provided TLS diagnostic transcript metadata and handshake error signals offline."),
    _definition("research_findings",
        "Aggregate all domain observations and evidence refs, keeping hypothesis distinct from verified finding.",
        {"offset": {"type": "integer"}, "limit": {"type": "integer"}}),
    _definition("research_next_steps",
        "Produce domain-specific evidence gaps and safe next investigative tasks, without automatic target requests."),
    _definition("research_full_report",
        "Generate cross-domain audit report, methodology, coverage, limitations and evidence index without unverified CVEs."),
]
DOMAIN_NAMES = frozenset(x["name"] for x in DOMAIN_TOOLS)

DOMAIN_LABELS={
    "har":"Web transaction capture",
    "javascript":"Frontend security and API routes",
    "openapi":"API contract and authentication",
    "log":"Network, server and application logs",
    "config":"Infrastructure configuration",
    "python":"Python source AST review",
    "dependencies":"Software supply chain",
    "tls":"TLS diagnostics",
    "pcap":"Packet metadata and L2-L4 flows",
}
DOMAIN_STEPS={
    "har":[
        "Review query and object ID names in the API map; infer no cross-account access",
        "Compare recorded methods with expected role and session restrictions",
        "Use synthetic test users for any authorization or business logic validation",
    ],
    "javascript":[
        "Correlate referenced client API routes with observed HAR endpoints",
        "Trace source-to-sink reachability in an authorized code copy",
        "Check for dependencies and script origin trust issues",
    ],
    "openapi":[
        "Review actual authentication/authorization policies for each route",
        "Compare OpenAPI contract to observed HAR behavior",
        "Use test identities and synthetic objects for BOLA/BFLA checks",
    ],
    "log":[
        "Align error timestamps with interface, host and transport path context",
        "Correlate event classes with limited packet captures and configuration snapshots",
    ],
    "config":[
        "Confirm whether reported directives are active in effective configuration",
        "Review reverse proxy, application and firewall trust boundaries",
    ],
    "python":[
        "Trace origins of data into identified sensitive Python calls",
        "Check dependency advisories and reachable code paths",
    ],
    "dependencies":[
        "Match package/version against signed, current advisories in an approved process",
        "Confirm actual dependency reachability before assigning exploitability",
    ],
    "tls":[
        "Compare independent TLS transcripts for the same endpoint and time window",
        "Separate transport integrity failures from certificate trust failures",
    ],
    "pcap":[
        "Correlate pseudonymous flows, VLANs, TCP RST/SYN and port classes with logs",
        "Do not infer packet loss or TLS interception without sequence-accurate evidence",
    ],
}


def _reports(artifacts: dict) -> list[tuple[str,dict]]:
    return [(key, row) for key,row in list(artifacts.items())[:16]
            if isinstance(row,dict) and row.get("kind") in DOMAIN_LABELS]


def _observations(artifacts: dict) -> list[dict]:
    out=[]
    for aid,report in _reports(artifacts):
        for observation in report.get("observations",[])[:120]:
            if isinstance(observation,dict):
                out.append({
                    "artifact_id":aid,"source_kind":report.get("kind"),
                    "type":observation.get("type"),"description":observation.get("description"),
                    "state":observation.get("state","hypothesis"),
                    "confidence":observation.get("confidence","unknown"),
                    "verified":bool(observation.get("verified",False)),
                    "evidence_ids":observation.get("evidence_ids",[])[:8],
                })
    return out


def _api_rows(artifacts: dict):
    routes=[]
    for aid,report in _reports(artifacts):
        if report.get("kind")=="openapi":
            for row in report.get("operations",[])[:1200]:
                routes.append({"source":aid,"path":row["path"],
                    "method":row["method"],
                    "security_declared":row["security_declared"],
                    "parameter_names":row["parameter_names"][:40],
                    "response_codes":row["response_codes"][:12],
                    "evidence_ids":row["evidence_ids"]})
        elif report.get("kind")=="har":
            for row in report.get("endpoints",[])[:400]:
                routes.append({"source":aid,"path":row["path"],
                    "method":row["method"],
                    "security_declared":"unknown_from_har",
                    "parameter_names":(row["query_keys"]+row["request_keys"])[:50],
                    "response_codes":list(row["statuses"])[:12],
                    "evidence_ids":row["evidence_ids"]})
    return routes


def domain_call(name: str,args: dict,artifacts: dict) -> dict:
    if name not in DOMAIN_NAMES:
        raise ValueError("unregistered_domain_tool")
    rows = _reports(artifacts)
    if name=="research_capabilities":
        return {"implemented_tools":[x["name"] for x in DOMAIN_TOOLS],
                "accepted_artifact_kinds":DOMAIN_LABELS,
                "execution":"all import and analysis operations are offline",
                "active_scanners":"not_connected_by_these_adapters",
                "evidence_policy":"never equate a pattern match with exploitation"}
    if name=="research_artifacts":
        return {"items":[{
            "artifact_id":aid,"domain":DOMAIN_LABELS[report["kind"]],
            "kind":report["kind"],
            "source_hash_prefix":report.get("source_sha256","")[:16],
            "observations":len(report.get("observations",[])),
            "limitations":report.get("limitations",[])[:5],
        } for aid,report in rows],"total":len(rows)}
    if name in {"research_openapi_routes","research_authorization_matrix"}:
        routes=_api_rows(artifacts)
        offset,limit=_paging(args,len(routes))
        if name=="research_openapi_routes":
            return {"count":len(routes),"rows":routes[offset:offset+limit],
                    "scope":"offline_capture_or_documentation"}
        matrix=[]
        for route in routes[offset:offset+limit]:
            method=route["method"]
            path=route["path"].lower()
            obj=any(x in path for x in ("client","contract","subscriber","account","payment",
                                        "balance","user","invoice","ticket","order"))
            matrix.append({"source":route["source"],"method":method,"path":route["path"],
                           "object_sensitive_candidate":obj,
                           "declared_auth":route["security_declared"],
                           "anonymous":"unknown","subscriber":"unknown",
                           "staff":"unknown","admin":"unknown",
                           "expected_validation":"role/object authorization" if obj else
                            "server-side method authorization",
                           "evidence_ids":route["evidence_ids"][:3]})
        return {"count":len(routes),"authorization_matrix":matrix,
                "note":"No role difference proven; all permissions unknown until independently verified"}
    if name=="research_network_packets":
        return {"captures":[{
            "artifact_id":aid,"packet_count":r["packet_count"],
            "protocol_counts":r["protocol_counts"],
            "vlan_ids":r["vlan_ids"],"tcp_flag_counts":r["tcp_flag_counts"],
            "top_destination_ports":r["top_destination_ports"],
            "flow_count":r["flow_count"],"flows":r["flows"][:30],
            "observations":r.get("observations",[])[:12],
            "limitations":r["limitations"],
        } for aid,r in rows if r["kind"]=="pcap"]}
    if name=="research_network_logs":
        return {"logs":[{
            "artifact_id":aid,"line_count":r["line_count"],
            "signal_counts":r["signal_counts"],
            "severity_counts":r["severity_counts"],
            "observations":r["observations"][:35],
        } for aid,r in rows if r["kind"]=="log"]}
    if name=="research_server_config":
        return {"configuration_reviews":[{
            "artifact_id":aid,"line_count":r["line_count"],
            "observations":r["observations"][:60],
        } for aid,r in rows if r["kind"]=="config"]}
    if name=="research_code_review":
        return {"code_reviews":[{
            "artifact_id":aid,"kind":r["kind"],
            "functions":r.get("functions",[])[:75],
            "imports":r.get("imports",{}),
            "call_names":r.get("call_names",[])[:50],
            "api_paths":r.get("api_paths",[])[:90],
            "patterns":r.get("patterns",{}),
            "observations":r.get("observations",[])[:35],
        } for aid,r in rows if r["kind"] in {"python","javascript"}]}
    if name=="research_dependencies":
        return {"manifests":[{
            "artifact_id":aid,"package_count":r["package_count"],
            "packages":r["packages"][:200],
            "advisory_status":"not_checked",
        } for aid,r in rows if r["kind"]=="dependencies"]}
    if name=="research_tls_review":
        return {"transcripts":[{
            "artifact_id":aid,"protocol_mentions":r["protocol_mentions"],
            "cipher_mentions":r["cipher_mentions"],
            "observations":r["observations"][:30],
        } for aid,r in rows if r["kind"]=="tls"]}
    if name=="research_findings":
        obs=_observations(artifacts)
        offset,limit=_paging(args,len(obs))
        return {"total_observations":len(obs),"items":obs[offset:offset+limit],
                "verified_findings":sum(bool(o["verified"]) for o in obs),
                "summary_by_class":dict(Counter(o["type"] for o in obs))}
    if name=="research_next_steps":
        return {"domains":[{"kind":k,"label":DOMAIN_LABELS[k],
                            "observed":any(r["kind"]==k for _,r in rows),
                            "next_steps":DOMAIN_STEPS[k][:4]} for k in DOMAIN_LABELS],
                "missing_artifacts":[k for k in DOMAIN_LABELS
                                     if not any(r["kind"]==k for _,r in rows)],
                "execution":"planning_only"}
    if name=="research_full_report":
        obs=_observations(artifacts)
        graph=api_graph([r for _,r in rows])
        signal=Counter(o["type"] for o in obs)
        return {
            "kind":"research_report","status":"preliminary_offline",
            "artifacts":len(rows),
            "source_sha256_prefixes":[r.get("source_sha256","")[:20] for _,r in rows],
            "domains_covered":sorted(set(r["kind"] for _,r in rows)),
            "observations_count":len(obs),
            "observations_by_type":dict(signal),
            "confirmed_vulnerabilities":sum(bool(o["verified"]) for o in obs),
            "api_routes":len(_api_rows(artifacts)),
            "api_graph":{"nodes":len(graph["nodes"]),"edges":len(graph["edges"])},
            "hypotheses":hypotheses([r for _,r in rows]),
            "next_step_domains":[x for x in DOMAIN_STEPS
                                 if any(r["kind"]==x for _,r in rows)],
            "limitations":[
                "No live target access, exploitation or unauthorized account access",
                "Source metadata was sanitized and raw content discarded",
                "Observations are hypotheses without independent test evidence",
                "Network captures omit original IP addresses, packet payload and IPv6",
                "Dependency CVEs not matched to current advisories",
            ],
        }
    raise ValueError("domain_tool_unhandled")
