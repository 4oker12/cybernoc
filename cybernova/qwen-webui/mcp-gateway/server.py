#!/usr/bin/env python3
"""Cybernova: bounded Streamable HTTP MCP tools for local Open WebUI."""
from mcp.server.mcpserver import MCPServer
from core import (
    check_local_webui, review_http_headers, review_python_source, summarize_network
)
from simnet_public import simnet_public_page as _fetch_simnet_public_page

mcp = MCPServer(
    "Cybernova Lab Tools",
    instructions=(
        "Cybernova read-only lab. Only simnet_public_page makes a public HTTP request: "
        "a single rate-limited GET to a fixed allowlisted page of https://simnet.ua/; "
        "no redirect following, no arbitrary URLs, no cookies, credentials, scans or forms. "
        "All other analysis is offline except fixed localhost Open WebUI health check. "
        "No shell, no filesystem reads and no privileged target access. "
        "Report security observations as hypotheses, not verified vulnerabilities. "
        "Use names supplied by tools/list, NEVER invent web_get or other tool names."
    ),
)


@mcp.tool()
def gateway_status() -> dict:
    """Report exact installed tools, scope and operational restrictions."""
    return {
        "version": "0.2", "mode": "BOUNDED_PUBLIC_GET_LAB",
        "arbitrary_commands": False, "arbitrary_file_access": False,
        "external_target_requests": "one fixed HTTPS GET to allowlisted simnet.ua public page per invocation",
        "rate_limit": "one request every 5 seconds per server process",
        "tools": [
            "gateway_status", "python_static_review", "http_header_review",
            "ip_network_summary", "local_webui_health", "simnet_public_page",
        ],
    }


@mcp.tool()
def python_static_review(source: str) -> dict:
    """Parse supplied Python code for security indicators without executing it."""
    return review_python_source(source)


@mcp.tool()
def http_header_review(raw_headers: str, scheme: str = "https") -> dict:
    """Inspect pasted HTTP response headers, without contacting the remote host."""
    return review_http_headers(raw_headers, scheme)


@mcp.tool()
def ip_network_summary(cidr: str) -> dict:
    """Calculate CIDR network metadata offline (no probing)."""
    return summarize_network(cidr)


@mcp.tool()
def local_webui_health() -> dict:
    """Check only the fixed 127.0.0.1:18791 Open WebUI local service."""
    return check_local_webui()


@mcp.tool()
def simnet_public_page(page: str = "home") -> dict:
    """Fetch one public page from a fixed allowlist on https://simnet.ua. Use page='home' for the homepage. Returns real status, selected security headers and HTML summary. No arbitrary URLs, redirects or active probing."""
    return _fetch_simnet_public_page(page)


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http", host="127.0.0.1", port=18792,
        stateless_http=True, json_response=True,
    )
