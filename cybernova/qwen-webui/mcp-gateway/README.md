# Cybernova Tools — generic HTTP inspection gateway v0.3

The gateway exposes six generic MCP tools over Streamable HTTP at 127.0.0.1:18792.

| Tool name | Function |
| --- | --- |
| gateway_status | Capabilities and current authorized website hostnames |
| http_get | One real HTTP(S) GET for an authorized public URL |
| http_header_review | Offline inspection of HTTP headers |
| python_static_review | Offline AST analysis of pasted Python |
| ip_network_summary | Offline CIDR arithmetic |
| local_webui_health | Fixed localhost health probe |

**Website names do not appear in tool names or in http_client.py.** Set the authorized hostnames in scope.json, initially containing simnet.ua. For a future authorized website, add its exact hostname there. The tool code stays unchanged. Scope config is read for each request, so no restart is required to update an approved list.

## HTTP boundaries

HTTP GET only; 5s rate limit per process; 8s timeout; HTTPS validation; DNS addresses must all be public; connection pinned to a validated address; no proxies; no redirects; no custom headers/cookies/credentials; standard port 80/443 only; response content is summarized, not executed. A query string may be sent but never echoed in tool output. Returns HTTP status, selected headers (no session cookies), title, detected generator tags, sample internal paths. Does not assert that missing headers are vulnerabilities.

## Test and deployment

    D=/workspace/cybernova-qwen-webui-src/cybernova/qwen-webui/mcp-gateway
    PYTHONPATH="$D" /workspace/cybernova-qwen-webui-runtime/venv/bin/python -m unittest discover -s "$D/tests"
    tmux kill-session -t cybernova-tools
    bash "$D/install.sh"

The install script runs protocol smoke, tools/list verifies six generic tools and checks localhost blocking. The previous target-specific simnet_public_page tool is retired. Refresh the connection in Open WebUI to load the changed tool schema.

## Open WebUI
Admin → Settings → Integrations → External Tool Servers:
- Name: Cybernova Lab Tools
- Type: MCP Streamable HTTP
- URL: http://127.0.0.1:18792/mcp
- No auth **only on loopback-bound single-user Vast**; do not expose this port externally.

Select the tool connection for CYBERNOVA — Security Researcher. Ask it to call http_get(url="https://simnet.ua/") and report the actual tool result. A <tool_call> string or invented function is not proof of successful execution.
