#!/usr/bin/env python3
"""Cybernova: bounded, generic Streamable HTTP MCP tools."""
from mcp.server.mcpserver import MCPServer
from core import check_local_webui, review_http_headers, review_python_source, summarize_network
from http_client import http_get as _http_get, _load_scope

mcp = MCPServer(
    "Cybernova Lab Tools",
    instructions=(
        "Use tool names from tools/list. For approved public sites use http_get(url='https://host/path'). "
        "Targets are configured separately via scope.json. Never invent web_get or target-specific tool names. "
        "HTTP tool: one GET, rate-limited, authorized hostnames only, no auth, redirects, proxies, "
        "arbitrary ports, cookie values, scanning, form submission, or shell. "
        "Other analysis is offline except fixed local Open WebUI health. "
        "Observations and missing headers are not proven vulnerabilities."
    ),
)


@mcp.tool()
def gateway_status() -> dict:
    """Show the exact tools and currently authorized website hostnames."""
    return {
        "version": "0.3",
        "mode": "SCOPED_PUBLIC_HTTP_LAB",
        "authorized_hosts": sorted(_load_scope()),
        "arbitrary_commands": False,
        "arbitrary_file_access": False,
        "http_methods": ["GET"],
        "http_limits": "one direct HTTP(S) GET per call; 5-second cooldown; 8-second timeout; first 32768 HTML bytes; no redirects",
        "tools": ["gateway_status", "python_static_review", "http_header_review",
                  "ip_network_summary", "local_webui_health", "http_get"],
    }


@mcp.tool()
def python_static_review(source: str) -> dict:
    """Analyze user-supplied Python source using AST only, without executing it."""
    return review_python_source(source)


@mcp.tool()
def http_header_review(raw_headers: str, scheme: str = "https") -> dict:
    """Inspect pasted response headers offline; no origin contact."""
    return review_http_headers(raw_headers, scheme)


@mcp.tool()
def ip_network_summary(cidr: str) -> dict:
    """Offline IPv4 and IPv6 CIDR calculations."""
    return summarize_network(cidr)


@mcp.tool()
def local_webui_health() -> dict:
    """Check only the fixed localhost 127.0.0.1:18791 WebUI service."""
    return check_local_webui()


@mcp.tool()
def http_get(url: str) -> dict:
    """Fetch one URL on an explicitly approved public hostname. Example: http_get(url='https://simnet.ua/'). Generic for future sites: update scope.json allowed_hosts, not the tool code. Never follows redirects or sends credentials."""
    return _http_get(url)


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="127.0.0.1", port=18792,
            stateless_http=True, json_response=True)
