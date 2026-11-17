# Cybernova MCP Deployment Add-on

This is an additive wrapper for the existing /workspace/cybersec-vast-mcp-v02/server.py. The original file and its existing MCP tools are not modified.

## Tools

- deployment_status: active release and updater state
- deployment_preview: approved branch HEAD and updater cursor
- deployment_stage(commit_sha): stage the pinned branch HEAD and run tests
- deployment_apply(commit_sha): promote a tested commit using the existing updater
- deployment_rollback(target): restore legacy or a managed release and stop updater for review
- deployment_recent_events(limit): read bounded local updater reports

The stage/apply/rollback operations take the **same exclusive lock** as the continuously running Auto Updater. Therefore they refuse to run while the 30-second daemon is active. During automatic operation, source updates from GitHub are applied by the daemon; stage/apply/rollback are maintenance methods, not a second concurrent updater.

Each operation is fixed, sha-pinned, runs as unprivileged cybernova, and does not execute arbitrary shell commands or URLs. No additional OpenAI API token is necessary to use these tools via the existing Secure MCP Tunnel.

## Test

From this directory:

    python3 -m unittest discover -s tests -v

## Activation on Vast

1. Obtain the approved code from branch cybernova-autodeploy into the workspace (using the existing read-only deploy key).
2. Run bash cybernova/mcp-addon/install.sh --check
3. Run bash cybernova/mcp-addon/install.sh --activate
4. The installer backs up the existing tunnel profile, imports the original MCP tools and adds the new ones, then restarts the existing tunnel.
5. In ChatGPT Plugins select CyberSec Vast and choose Refresh/Rescan. Check for the six new tools.

## Important: MCP Events

The tools above work in ordinary ChatGPT tool-calling. They do **not** provide event-triggered automatic activation of an idle ChatGPT conversation.

OpenAI's current MCP Events requires MCP 2.0 (protocol 2026-07-28) and a server advertising events capabilities, verified subscription callbacks, persistent storage, and signed webhook delivery. This v0.1 addon retains the existing stdio tunnel and deliberately does not falsely advertise a working events subscription. The deployment_recent_events tool is a read API, **not** an events/subscribe method.

Source of truth: https://developers.openai.com/plugins/build/mcp-events
