"""Portable scope-closed tool MCP on the official FastMCP SDK.

The original Vast gateway stays unchanged. This backend runs in the same
sandbox/container as Console, so all MCP ports remain loopback-only. Targets
default to EMPTY; admin must explicitly authorize hostnames in scope.json.
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

CANDIDATES = (
    Path(__file__).resolve().parents[1] / "tool_gateway",
    Path(__file__).resolve().parents[2] / "qwen-webui" / "mcp-gateway",
)
GATEWAY_DIR = next((item for item in CANDIDATES
                    if (item / "core.py").is_file()), None)
if GATEWAY_DIR is None:
    raise RuntimeError("portable_tool_gateway_sources_missing")
sys.path.insert(0, str(GATEWAY_DIR))

from core import (
    check_local_webui, review_http_headers, review_python_source, summarize_network,
)
import http_client as _scoped
# Default-deny even if a source checkout includes an old nonempty scope.json.
_scoped._SCOPE = Path(os.environ.get(
    "CYBERNOVA_HTTP_SCOPE_FILE", "/__cybernova_no_scope_config__"
))
scoped_http_get = _scoped.http_get
_load_scope = _scoped._load_scope

mcp = FastMCP(
    "Cybernova Portable Tools", host="127.0.0.1", port=18792,
    stateless_http=True, json_response=True,
    instructions="Bounded offline tools plus explicitly scoped HTTP read-only checks.",
)


@mcp.tool()
def gateway_status() -> dict:
    """List scope and capabilities; no arbitrary shell or file access."""
    return {
        "ok": True, "version": "portable-1",
        "mode": "SCOPE_CLOSED",
        "authorized_hosts": sorted(_load_scope()),
        "tools": ["gateway_status", "python_static_review", "http_header_review",
                  "ip_network_summary", "local_webui_health", "http_get"],
        "arbitrary_commands": False,
        "arbitrary_file_access": False,
    }


@mcp.tool()
def python_static_review(source: str) -> dict:
    """Inspect user-provided Python text via AST; never run submitted code."""
    return review_python_source(source)


@mcp.tool()
def http_header_review(raw_headers: str, scheme: str = "https") -> dict:
    """Review user-provided headers offline."""
    return review_http_headers(raw_headers, scheme)


@mcp.tool()
def ip_network_summary(cidr: str) -> dict:
    """Calculate an IPv4/IPv6 subnet offline."""
    return summarize_network(cidr)


@mcp.tool()
def local_webui_health() -> dict:
    """Inspect only local WebUI service availability."""
    return check_local_webui()


@mcp.tool()
def http_get(url: str) -> dict:
    """GET one scoped public page, with no redirects or credentials."""
    return scoped_http_get(url)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
