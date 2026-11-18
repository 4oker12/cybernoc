# Cybernova Lab MCP gateway — v0.1

Read-only MCP Streamable HTTP server. Uses the existing Python virtual environment from Open WebUI, MCP SDK 2.x. Runs on localhost at port 18792 only.

## Five tools
1. gateway_status — current scope
2. python_static_review — AST-only user-supplied source review, never executes
3. http_header_review — pasted header analysis with cookie values suppressed
4. ip_network_summary — offline CIDR calculation
5. local_webui_health — GET fixed localhost:18791, no external destinations

No arbitrary terminal, filesystem, DNS or HTTP targets. No scans, no external execution.

## Install on Vast
From this branch clone:
  bash /workspace/cybernova-qwen-webui-src/cybernova/qwen-webui/mcp-gateway/install.sh

The installer runs tests, starts separate persistent tmux session cybernova-tools, and verifies real MCP initialize, tools/list, and tools/call.

## Open WebUI connection
From browser admin settings > Integrations > External Tool Servers > Add Connection:
- Type: MCP (Streamable HTTP)
- Name: Cybernova Lab Tools
- URL: http://127.0.0.1:18792/mcp
- Authentication: None (only because local same-host single-user lab)
- Save then enable tools in conversation / model profile.

Port 18792 does not need to be forwarded to Windows. Open WebUI connects to it locally on Vast. Never expose port 18792 to the internet without proper authentication and access policy.

This is initial tool integration; external targets and active security testing are out of scope until target authorization and execution limits are defined.
