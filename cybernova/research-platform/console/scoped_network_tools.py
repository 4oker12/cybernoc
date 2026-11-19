"""Scoped live DNS/TLS metadata checks for explicitly allowed public hosts.

Not scanners: one DNS lookup or one TLS handshake per call. No arbitrary port,
request body, HTTP headers, proxies, credentials, redirect, or private IP use.
Allowed hosts come only from the existing MCP gateway's scope config.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

try:
    from .traffic_tools import _definition
except ImportError:
    from traffic_tools import _definition

SCOPED_TOOLS = [
    _definition("scoped_dns_resolve",
       "Resolve A/AAAA records for EXACTLY one public hostname already approved by MCP scope; no enumeration.",
       {"host": {"type":"string"}}, ["host"]),
    _definition("scoped_tls_inspect",
       "Perform one TLS 443 handshake for an EXACT public hostname already approved by MCP scope, with certificate validation. No HTTP.",
       {"host": {"type":"string"}}, ["host"]),
]
SCOPED_NAMES=frozenset(x["name"] for x in SCOPED_TOOLS)


def _public_addresses(host):
    if not isinstance(host,str) or len(host)>150 or not host or "/" in host or ":" in host:
        raise ValueError("invalid_hostname")
    if host!=host.lower().rstrip("."):
        raise ValueError("hostname_must_be_normalized")
    try:
        import re
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]",host) or ".." in host:
            raise ValueError("invalid_hostname")
        ipaddress.ip_address(host)
        raise ValueError("ip_literal_forbidden")
    except ValueError as exc:
        if str(exc)=="ip_literal_forbidden" or str(exc)=="invalid_hostname":
            raise
    records=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
    addresses=[]
    for family,kind,proto,canon,address in records:
        ip=ipaddress.ip_address(address[0])
        if not ip.is_global:
            raise ValueError("non_public_dns_answer")
        value=str(ip)
        if value not in addresses:
            addresses.append(value)
    if not addresses:
        raise ValueError("dns_no_public_answers")
    return addresses[:12]


def scoped_call(name,args,upstream):
    if name not in SCOPED_NAMES:
        raise ValueError("unknown_scoped_tool")
    host=args.get("host")
    scope,failed=upstream.call("gateway_status",{})
    if failed or not isinstance(scope,dict):
        raise ValueError("cannot_confirm_current_scope")
    allowed=scope.get("authorized_hosts",[])
    if not isinstance(allowed,list) or host not in allowed:
        raise ValueError("hostname_not_in_mcp_scope")
    addresses=_public_addresses(host)
    if name=="scoped_dns_resolve":
        return {"host":host,"addresses":addresses,"public_only":True,
                "record_type":"resolved A/AAAA","scope_confirmed":True}
    # Pin to one validated public destination IP and retain original hostname
    # for SNI and certificate verification, avoiding a second DNS lookup.
    chosen=addresses[0]
    family=socket.AF_INET6 if ":" in chosen else socket.AF_INET
    context=ssl.create_default_context()
    sock=socket.socket(family,socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((chosen,443))
        with context.wrap_socket(sock,server_hostname=host) as tls:
            cert=tls.getpeercert()
            version=tls.version()
            cipher=tls.cipher()
            return {"host":host,"connected_ip":chosen,"port":443,
                    "tls_version":version,
                    "cipher":cipher[0] if cipher else None,
                    "certificate_validated":True,
                    "certificate_expiry":cert.get("notAfter"),
                    "san_count":len(cert.get("subjectAltName",[])),
                    "scope_confirmed":True}
    finally:
        sock.close()
