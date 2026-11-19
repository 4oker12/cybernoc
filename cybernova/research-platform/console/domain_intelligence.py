"""Cybernova Research Intelligence: offline evidence parsers across domains.

Every analyzer accepts USER-PROVIDED data only, does no network I/O, no
subprocess calls and never returns raw captured bodies, credentials or secrets.
Outputs are observations and candidates; no analyzer asserts exploitation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import ast
import base64
import hashlib
import io
import ipaddress
import json
import re
import struct
from urllib.parse import urlsplit

try:
    from .upload_limits import MAX_UPLOAD_FILE_BYTES, MAX_PCAP_BASE64_CHARS
except ImportError:
    from upload_limits import MAX_UPLOAD_FILE_BYTES, MAX_PCAP_BASE64_CHARS

MAX_TEXT = MAX_UPLOAD_FILE_BYTES
MAX_PCAP = MAX_UPLOAD_FILE_BYTES
MAX_ITEMS = 1200
SAFE_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.\-]{0,75}$")
DANGER_NAME = re.compile(r"(?i)(password|secret|token|key|auth|cookie|session|credential|ssn|card|iban|client|account)")
SENSITIVE_DATA = re.compile(r"(?i)(bearer\s+[a-z0-9._-]+|password\s*[=:]|token\s*[=:]|authorization\s*:)")
URI_PATH = re.compile(r"^[a-zA-Z0-9_./{}:~\-]{1,180}$")
ERROR_SIGNALS = {
    "tls_integrity": re.compile(r"SEC_E_MESSAGE_ALTERED|DECRYPT_FAILURE|bad record mac|bad mac|wrong version number|TLS alert|SSL_ERROR", re.I),
    "connectivity": re.compile(r"connection refused|connection reset|unreachable|timed out|timeout|no route", re.I),
    "dns": re.compile(r"(?:NXDOMAIN|SERVFAIL|DNS_PROBE|resolv(?:e|ing)|getaddrinfo|DNS query|rcode)", re.I),
    "dhcp": re.compile(r"\b(?:DHCPDISCOVER|DHCPOFFER|DHCPREQUEST|DHCPACK|DHCPNAK|lease expired|snooping)\b", re.I),
    "radius": re.compile(r"\b(?:RADIUS|Access-Reject|Access-Accept|CoA|Accounting-Stop)\b", re.I),
    "pon": re.compile(r"\b(?:ONU|ONT|OLT|LOS|LOFi|OAM|EPON|GPON)\b", re.I),
    "routing": re.compile(r"\b(?:BGP|OSPF|ARP|MAC flapp|STP|VLAN|route change)\b", re.I),
    "web_http": re.compile(r"\bHTTP/[12](?:\.\d)?\s+(?:4\d\d|5\d\d)\b|\bHTTP\s+(?:4\d\d|5\d\d)\b", re.I),
    "application_error": re.compile(r"\b(?:traceback|exception|fatal|segmentation fault|panic:)\b", re.I),
    "authentication": re.compile(r"\b(?:unauthoriz|forbidden|login failed|access denied|invalid session)\b", re.I),
}
CONFIG_RULES = [
    ("nginx_server_tokens", re.compile(r"(?im)^\s*server_tokens\s+on\s*;"), "nginx discloses version; assess exposure"),
    ("nginx_autoindex", re.compile(r"(?im)^\s*autoindex\s+on\s*;"), "directory listing explicitly enabled"),
    ("nginx_tls_legacy", re.compile(r"(?im)^\s*ssl_protocols\s+[^;\n]*(?:TLSv1(?:\s|;)|TLSv1\.1)"), "legacy TLS protocol mentioned"),
    ("ssh_root_login", re.compile(r"(?im)^\s*PermitRootLogin\s+yes\s*$"), "SSH root login enabled"),
    ("ssh_password_auth", re.compile(r"(?im)^\s*PasswordAuthentication\s+yes\s*$"), "SSH password authentication enabled"),
    ("docker_privileged", re.compile(r"(?im)\bprivileged\s*:\s*true\b"), "container privileged mode"),
    ("k8s_hostnetwork", re.compile(r"(?im)\bhostNetwork\s*:\s*true\b"), "pod hostNetwork enabled"),
    ("app_debug", re.compile(r"(?im)^\s*(?:DEBUG|APP_DEBUG)\s*[=:]\s*(?:true|1|yes)\b"), "debug mode enabled"),
    ("cors_wildcard", re.compile(r"(?im)^\s*(?:Access-Control-Allow-Origin)\s*[:=]\s*\*"), "CORS wildcard; assess credential behavior"),
    ("public_binding", re.compile(r"(?im)\b(?:host|listen|bind)\s*[=:]\s*(?:0\.0\.0\.0|::)(?:\b|$)"), "wildcard network bind"),
]
PY_CALLS = {
    "dynamic_eval": {"eval", "exec", "compile"},
    "shell_subprocess": {"os.system", "os.popen", "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output"},
    "unsafe_deserialization": {"pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "marshal.load"},
    "weak_hash": {"hashlib.md5", "hashlib.sha1"},
}
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


class DomainError(ValueError):
    pass


def _load_text(text: str) -> tuple[str, str]:
    if not isinstance(text, str):
        raise DomainError("source_must_be_text")
    size = len(text.encode("utf-8"))
    if size < 1 or size > MAX_TEXT:
        raise DomainError("invalid_source_size")
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def _finding(kind: str, description: str, refs: list[str], *, confidence="low") -> dict:
    return {"type": kind, "description": description,
            "state": "hypothesis", "confidence": confidence,
            "evidence_ids": refs[:8], "verified": False}


def _sanitize_field_names(keys) -> list[str]:
    return sorted({str(k) for k in keys if isinstance(k, str) and SAFE_NAME.fullmatch(k)})[:100]


def analyze_openapi(text: str) -> dict:
    raw, sha = _load_text(text)
    try:
        root = json.loads(raw)
    except ValueError as exc:
        raise DomainError("openapi_requires_json_export") from exc
    if not isinstance(root, dict) or not ("openapi" in root or "swagger" in root):
        raise DomainError("invalid_openapi_root")
    paths = root.get("paths", {})
    if not isinstance(paths, dict) or len(paths) > MAX_ITEMS:
        raise DomainError("invalid_openapi_paths")
    ops, notes = [], []
    for path, value in list(paths.items()):
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(value, dict):
            continue
        # Suppress instance IDs or personal path segments.
        segments = ["{object}" if len(x) > 65 or x.isdecimal() else x
                    for x in path.split("/") if x]
        safe_path = "/" + "/".join(segments)
        if not URI_PATH.fullmatch(safe_path):
            continue
        for method, detail in value.items():
            if method.lower() not in METHODS or not isinstance(detail, dict):
                continue
            evidence = f"openapi:{sha[:14]}:{len(ops)}"
            security = detail.get("security", root.get("security", []))
            security_declared = bool(security)
            parameters = detail.get("parameters", [])
            if not isinstance(parameters, list):
                parameters = []
            params = [v["name"] for v in parameters[:50] if isinstance(v, dict)
                      and isinstance(v.get("name"), str)]
            responses = detail.get("responses", {})
            codes = sorted(str(x)[:5] for x in responses.keys())[:12] if isinstance(responses, dict) else []
            item = {"path": safe_path, "method": method.upper(),
                    "security_declared": security_declared,
                    "parameter_names": _sanitize_field_names(params),
                    "response_codes": codes, "evidence_ids": [evidence]}
            ops.append(item)
            if not security_declared:
                notes.append(_finding("openapi_no_security_declaration",
                    "Operation has no declared OpenAPI security requirement; "
                    "runtime access control cannot be inferred from the spec.", [evidence]))
            if method.lower() in {"post", "put", "patch", "delete"}:
                notes.append(_finding("state_change_operation",
                    "Declared state-changing API operation; consider authorization, "
                    "CSRF/idempotency and transaction consistency in staging.", [evidence]))
            if len(ops) >= MAX_ITEMS:
                break
    schemes = (root.get("components", {}).get("securitySchemes", {})
               if isinstance(root.get("components"), dict) else {})
    if not isinstance(schemes, dict):
        schemes = {}
    return {"kind": "openapi", "schema_version": 1, "source_sha256": sha,
            "raw_data_retained": False, "api_version": str(root.get("openapi") or root.get("swagger"))[:14],
            "operation_count": len(ops), "operations": ops[:MAX_ITEMS],
            "security_scheme_names": _sanitize_field_names(schemes),
            "observations": notes[:140],
            "limitations": ["Specification only; real access controls and endpoint availability not validated",
                            "OpenAPI schema bodies and example values intentionally discarded"]}


def analyze_log(text: str) -> dict:
    raw, sha = _load_text(text)
    lines = raw.splitlines()
    if len(lines) > 100_000:
        raise DomainError("log_too_many_lines")
    counter = Counter()
    positions = defaultdict(list)
    severities = Counter()
    for idx, line in enumerate(lines):
        for level in ("CRITICAL", "ERROR", "WARN", "INFO", "DEBUG"):
            if re.search(r"\b" + level + r"\b", line, re.I):
                severities[level] += 1
                break
        for name, rgx in ERROR_SIGNALS.items():
            if rgx.search(line):
                counter[name] += 1
                if len(positions[name]) < 12:
                    positions[name].append("log:" + sha[:12] + ":L" + str(idx+1))
    observed = [ _finding("event_" + name,
                "Found " + str(count) + " matching log lines for " + name +
                "; requires timestamp and infrastructure context.", positions[name])
                for name, count in counter.most_common()]
    return {"kind": "log", "source_sha256": sha, "raw_data_retained": False,
            "line_count": len(lines), "severity_counts": dict(severities),
            "signal_counts": dict(counter), "observations": observed,
            "limitations": ["Line-level patterns only, not root-cause proof",
                            "Raw log lines, IPs, usernames and values not retained"]}


def analyze_config(text: str) -> dict:
    raw, sha = _load_text(text)
    items = []
    for kind, expression, description in CONFIG_RULES:
        for m in list(expression.finditer(raw))[:40]:
            items.append(_finding(kind, description,
                                  ["config:"+sha[:12]+":L"+str(raw.count("\n",0,m.start())+1)]))
    return {"kind": "config", "source_sha256": sha,
            "raw_data_retained": False, "line_count": raw.count("\n")+1,
            "observations": items[:130],
            "limitations": ["Patterns depend on actual config context and applied overrides",
                            "Matched configuration lines and secrets are never returned"]}


def _static_call_name(node) -> str | None:
    """Only dotted identifiers; never unparse literals or secret source text."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    parts.reverse()
    name = ".".join(parts)
    return name if len(name) <= 100 and all(SAFE_NAME.fullmatch(x) for x in parts) else None


def analyze_python(text: str) -> dict:
    raw, sha = _load_text(text)
    try:
        tree = ast.parse(raw)
    except (SyntaxError, RecursionError) as exc:
        raise DomainError("python_syntax_error") from exc
    imports = Counter()
    funcs = []
    calls = Counter()
    observations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports[node.module.split(".")[0] if node.module else "relative"] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append({"name": node.name[:80] if SAFE_NAME.fullmatch(node.name) else "[function]",
                          "line": node.lineno, "async": isinstance(node, ast.AsyncFunctionDef),
                          "arguments": len(node.args.args)})
        elif isinstance(node, ast.Call):
            name = _static_call_name(node.func)
            if not name:
                continue
            calls[name] += 1
            for kind, candidates in PY_CALLS.items():
                if name in candidates:
                    observations.append(_finding("python_" + kind,
                        "Potentially sensitive API call " + name +
                        "; assess reachability, input provenance and controls.",
                        [f"python:{sha[:12]}:L{node.lineno}"]))
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    observations.append(_finding("python_shell_true",
                        "shell=True literal used at subprocess call site.",
                        [f"python:{sha[:12]}:L{node.lineno}"]))
    return {"kind": "python", "source_sha256": sha, "raw_data_retained": False,
            "functions": funcs[:150], "imports": dict(imports.most_common(70)),
            "call_names": [{"name": k, "count": n} for k, n in calls.most_common(80)
                           if len(k) < 80 and not DANGER_NAME.search(k)],
            "observations": observations[:120],
            "limitations": ["AST only, no execution or taint/data-flow verification",
                            "Source text, function bodies and argument values not retained"]}


def analyze_dependencies(text: str) -> dict:
    raw, sha = _load_text(text)
    packages = {}
    try:
        obj = json.loads(raw)
    except ValueError:
        obj = None
    if isinstance(obj, dict):
        if isinstance(obj.get("packages"), dict):  # npm lock v2/3
            rows = [(k.removeprefix("node_modules/"), v.get("version"))
                    for k,v in obj["packages"].items() if k and isinstance(v, dict)]
        elif isinstance(obj.get("dependencies"), dict):
            rows = [(k, (v.get("version") if isinstance(v, dict) else v))
                    for k,v in obj["dependencies"].items()]
        elif isinstance(obj.get("components"), list):  # CycloneDX
            rows = [(v.get("name"), v.get("version")) for v in obj["components"]
                    if isinstance(v, dict)]
        elif isinstance(obj.get("packages"), list):  # SPDX
            rows = [(v.get("name"), v.get("versionInfo")) for v in obj["packages"]
                    if isinstance(v, dict)]
        else:
            raise DomainError("unsupported_dependency_json_format")
    else:
        rows = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "//")):
                continue
            m = re.match(r"^([A-Za-z][A-Za-z0-9_.-]{0,75})\s*(?:==|@|>=|~=)\s*([A-Za-z0-9_.+\-]{1,70})",line)
            if m:
                rows.append((m.group(1), m.group(2)))
    for name, version in rows[:MAX_ITEMS]:
        if not isinstance(name, str) or not re.fullmatch(r"[@A-Za-z0-9_.\-/]{1,110}", name):
            continue
        if not isinstance(version, (str, int, float)):
            continue
        v = str(version)[:70]
        if not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,70}",v):
            continue
        packages[name] = v
    if not packages:
        raise DomainError("no_supported_dependencies")
    return {"kind": "dependencies", "source_sha256": sha, "raw_data_retained": False,
            "package_count": len(packages),
            "packages": [{"name": k, "version": v} for k,v in list(packages.items())[:MAX_ITEMS]],
            "observations": [],
            "limitations": ["No live advisory lookup; CVE status and exploitability unknown",
                            "Package versions alone do not prove vulnerabilities"]}


def analyze_tls(text: str) -> dict:
    raw, sha = _load_text(text)
    versions = Counter()
    for version in re.findall(r"\b(?:TLSv1(?:\.[0-3])?|SSLv3)\b",raw):
        versions[version] += 1
    ciphers = Counter()
    for cipher in re.findall(r"(?im)^\s*(?:Cipher|Ciphersuite)\s*:\s*([A-Za-z0-9_-]{3,90})\s*$",raw):
        ciphers[cipher] += 1
    alerts = []
    for key, regex in ERROR_SIGNALS.items():
        if key=="tls_integrity" and regex.search(raw):
            alerts.append(_finding("tls_handshake_error",
                                   "TLS diagnostic output includes integrity/handshake error text.",
                                   ["tls:"+sha[:12]]))
    return {"kind":"tls","source_sha256":sha,"raw_data_retained":False,
            "protocol_mentions":dict(versions),
            "cipher_mentions":dict(ciphers.most_common(30)),
            "observations":alerts,
            "limitations":["Provided diagnostic text only; no server contacted",
                           "Single transcript does not establish server TLS capabilities"]}


def _pcap_ip4(frame: bytes, pos: int):
    if len(frame)<pos+20 or frame[pos]>>4 !=4:
        return None
    ihl=(frame[pos]&15)*4
    if ihl<20 or len(frame)<pos+ihl:
        return None
    return frame[pos+9], frame[pos+12:pos+16], frame[pos+16:pos+20],pos+ihl


def analyze_pcap(b64: str) -> dict:
    if not isinstance(b64,str) or len(b64)>MAX_PCAP_BASE64_CHARS:
        raise DomainError("pcap_input_too_large")
    try:
        raw=base64.b64decode(b64,validate=True)
    except (ValueError,base64.binascii.Error) as exc:
        raise DomainError("pcap_invalid_base64") from exc
    if len(raw)>MAX_PCAP or len(raw)<24:
        raise DomainError("pcap_invalid_size")
    magic=raw[:4]
    endian={b"\xd4\xc3\xb2\xa1":"<",b"\xa1\xb2\xc3\xd4":">",
            b"\x4d\x3c\xb2\xa1":"<",b"\xa1\xb2\x3c\x4d":">"}.get(magic)
    if endian is None:
        raise DomainError("unsupported_capture_format_requires_classic_pcap")
    major,minor,zone,sig,snap,link=struct.unpack(endian+"HHiiii",raw[4:24])
    if major!=2 or link not in (1,101):
        raise DomainError("unsupported_pcap_linktype")
    sha=hashlib.sha256(raw).hexdigest()
    protocol=Counter()
    ports=Counter()
    vlan=Counter()
    tcp=Counter()
    flows=Counter()
    packets=0
    truncated=0
    i=24
    while i+16<=len(raw) and packets<100_000:
        ts_sec,ts_usec,inc,orig=struct.unpack(endian+"IIII",raw[i:i+16])
        i+=16
        if inc>MAX_PCAP or i+inc>len(raw):
            truncated+=1
            break
        frame=raw[i:i+inc];i+=inc;packets+=1
        pos=0
        etype=0x0800 if link==101 else None
        if link==1:
            if len(frame)<14:
                truncated+=1;continue
            etype=struct.unpack("!H",frame[12:14])[0]
            pos=14
            for _ in range(2):
                if etype in (0x8100,0x88a8,0x9100) and pos+4<=len(frame):
                    tag,nexttype=struct.unpack("!HH",frame[pos:pos+4])
                    vlan[tag&0x0fff]+=1
                    etype=nexttype
                    pos+=4
        if etype==0x0806:
            protocol["ARP"]+=1
            continue
        if etype!=0x0800:
            protocol["other_ethertype"]+=1;continue
        ip=_pcap_ip4(frame,pos)
        if ip is None:
            truncated+=1;continue
        proto,src,dst,start=ip
        label={6:"TCP",17:"UDP",1:"ICMP"}.get(proto,"IP_other")
        protocol[label]+=1
        if proto in (6,17) and start+4<=len(frame):
            sport,dport=struct.unpack("!HH",frame[start:start+4])
            ports[dport]+=1
            # Do not retain actual IPs; deterministic non-reversible per file
            # pseudonyms allow within-artifact flow correlation.
            flow_key=(hashlib.sha256(sha.encode()+src).hexdigest()[:10],
                      hashlib.sha256(sha.encode()+dst).hexdigest()[:10],
                      sport,dport,label)
            flows[flow_key]+=1
            if proto==6 and start+14<=len(frame):
                flags=frame[start+13]
                for name,bit in (("SYN",2),("ACK",16),("RST",4),("FIN",1)):
                    if flags&bit:
                        tcp[name]+=1
    return {"kind":"pcap","source_sha256":sha,"raw_data_retained":False,
            "packet_count":packets,"truncated_packets":truncated,
            "link_type":link,"protocol_counts":dict(protocol),
            "vlan_ids":dict(vlan.most_common(40)),
            "tcp_flag_counts":dict(tcp),
            "top_destination_ports":dict(ports.most_common(35)),
            "flow_count":len(flows),
            "flows":[{"src":a,"dst":b,"sport":p,"dport":q,"proto":r,"packets":n}
                     for (a,b,p,q,r),n in flows.most_common(70)],
            "observations":[_finding("tcp_resets_seen",
                "TCP RST flags were observed; root cause cannot be inferred without sequence and context.",
                ["pcap:"+sha[:14]],confidence="low")] if tcp["RST"] else [],
            "limitations":["Classic PCAP Ethernet/IPv4 and raw IPv4 only; no pcapng/IPv6 parsing",
                           "No payload retained, no credentials, no original IP addresses",
                           "TCP retransmissions and packet loss not inferred from flag counts"]}


PARSERS={
    "openapi":analyze_openapi,
    "log":analyze_log,
    "config":analyze_config,
    "python":analyze_python,
    "dependencies":analyze_dependencies,
    "tls":analyze_tls,
    "pcap":analyze_pcap,
}
