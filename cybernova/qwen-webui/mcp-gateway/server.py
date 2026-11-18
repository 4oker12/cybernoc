#!/usr/bin/env python3
"""Cybernova: read-only MCP Streamable HTTP for same-host Open WebUI."""
from mcp.server.mcpserver import MCPServer
from core import (
    check_local_webui, review_http_headers, review_python_source, summarize_network
)

mcp = MCPServer(
    "Cybernova Lab Tools",
    instructions=(
        "Read-only LOCAL LAB. The python and headers tools analyze only the text given in arguments. "
        "The CIDR tool computes offline. The health tool probes one fixed localhost service. "
        "No shell, no file read, no external target requests, and no privileged scanning. "
        "Indicators are hypotheses, not confirmed vulnerabilities. Do not invent execution."
    ),
)


@mcp.tool()
def gateway_status() -> dict:
    """List exactly the permissions provided by this gateway."""
    return {
        "version": "0.1", "mode": "LOCAL_LAB_ONLY",
        "arbitrary_commands": False, "arbitrary_file_access": False,
        "external_target_requests": False,
        "tools": ["gateway_status", "python_static_review", "http_header_review",
                  "ip_network_summary", "local_webui_health"],
    }


@mcp.tool()
def python_static_review(source: str) -> dict:
    """Parse supplied Python text for syntax and security indicators, without running it."""
    return review_python_source(source)


@mcp.tool()
def http_header_review(raw_headers: str, scheme: str = "https") -> dict:
    """Check pasted HTTP response headers; never contact the origin server."""
    return review_http_headers(raw_headers, scheme)


@mcp.tool()
def ip_network_summary(cidr: str) -> dict:
    """Compute IPv4 or IPv6 network metadata without probing any host."""
    return summarize_network(cidr)


@mcp.tool()
def local_webui_health() -> dict:
    """Check only the fixed 127.0.0.1:18791 Open WebUI service."""
    return check_local_webui()


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http", host="127.0.0.1", port=18792,
        stateless_http=True, json_response=True,
    )
