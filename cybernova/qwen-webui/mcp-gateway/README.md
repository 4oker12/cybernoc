# Cybernova Lab MCP gateway — v0.2

Read-only MCP Streamable HTTP service on Vast, at loopback `127.0.0.1:18792`, using preinstalled Open WebUI virtual environment.

## Tools

| MCP tool | Access |
| --- | --- |
| `gateway_status` | Read tool inventory and limitations |
| `python_static_review` | Offline AST-based Python review |
| `http_header_review` | Offline inspection of pasted HTTP headers |
| `ip_network_summary` | Offline network arithmetic |
| `local_webui_health` | Fixed localhost GET to Open WebUI |
| `simnet_public_page` | One live GET to fixed, allowlisted public simnet.ua pages |

The last tool is **not** named `web_get`. It accepts a page key such as `{"page":"home"}`, not an arbitrary URL. It uses a minimum 5-second cooldown, 8-second timeout, TLS validation, no redirects, no cookies or login, no query strings and no request bodies. HTTP status, selected headers, title and sample internal paths can be returned; not page content or session secrets. No vulnerability exploitation or bulk discovery.

## Deploy and tests

`PYTHONPATH=cybernova/qwen-webui/mcp-gateway python3 -m unittest discover -s cybernova/qwen-webui/mcp-gateway/tests`

`bash /workspace/cybernova-qwen-webui-src/cybernova/qwen-webui/mcp-gateway/install.sh`

An already running `cybernova-tools` tmux session must be restarted after updating code to load new tools. The installer does not replace an active process. Run `smoke.py` to confirm exactly six MCP tools and allowlist behavior.

## Open WebUI

As admin, create/verify External Tool Servers → MCP Streamable HTTP:
- Name: Cybernova Lab Tools
- URL: `http://127.0.0.1:18792/mcp`
- Authentication: None only while both components are loopback-bound on trusted Vast.

In the chosen `CYBERNOVA — Security Researcher` profile or conversation, enable this connection. Refresh the UI after restarting the server. Ask model to list its actual tools and call `simnet_public_page(page="home")`.

A successful MCP smoke test does **not** prove the model sees the connection. Verify a real tool call in the Open WebUI chat; the literal text `<tool_call>` is not evidence of tool execution.

## Limits

Public GET observations are only indicative and require critical evaluation. Arbitrary HTTP URLs, shell execution, scans, login, credential capture or intrusive tests are not available. The separate Cybernova event-ring and local Qwen baseline sessions are not modified.
