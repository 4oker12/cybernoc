#!/usr/bin/env python3
"""Local Streamable HTTP protocol smoke; no external requests."""
import json
import time
import urllib.request

URL = "http://127.0.0.1:18792/mcp"
HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}


def rpc(method, params=None, identity=1):
    value = {"jsonrpc": "2.0", "method": method, "id": identity}
    if params is not None:
        value["params"] = params
    req = urllib.request.Request(URL, data=json.dumps(value).encode("utf-8"), method="POST", headers=HEADERS)
    with urllib.request.urlopen(req, timeout=5) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def main():
    initialized = None
    for attempt in range(20):
        try:
            initialized = rpc("initialize", {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "cybernova-smoke", "version": "0.2"},
            })
            break
        except OSError:
            time.sleep(0.35)
    if initialized is None:
        raise RuntimeError("MCP initialization failed")
    names = [tool["name"] for tool in rpc("tools/list", identity=2)["tools"]]
    expected = {"gateway_status", "python_static_review", "http_header_review",
                "ip_network_summary", "local_webui_health", "simnet_public_page"}
    if set(names) != expected:
        raise AssertionError("Unexpected tool set: " + repr(names))
    subnet = rpc("tools/call", {"name": "ip_network_summary", "arguments": {"cidr": "192.0.2.7/24"}}, identity=3)
    if "192.0.2.0/24" not in json.dumps(subnet):
        raise AssertionError("CIDR tool result invalid")
    rejected = rpc("tools/call", {"name": "simnet_public_page", "arguments": {"page": "https://example.net/"}}, identity=4)
    if "page_not_allowed" not in json.dumps(rejected):
        raise AssertionError("Allowlist enforcement failed")
    print("MCP_OK; revision:", initialized.get("protocolVersion"), "; tools:", ", ".join(names))
    print("SIMNET_ALLOWLIST_REJECTION_OK")


if __name__ == "__main__":
    main()
