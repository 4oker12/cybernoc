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

## MCP Events v0.2

The same MCP server now registers the draft OpenAI methods:

- events/list — describes cybernova.deployment.completed
- events/subscribe — verifies a signed HTTPS challenge and persists the subscription
- events/unsubscribe — deletes the matching subscription, idempotently

The v2.3.0 Python SDK supports custom RPC handlers but drops unknown events from ServerCapabilities. The event bridge overrides server/discover with a raw dict containing capabilities.events on protocol 2026-07-28 only. Existing legacy tools and calls remain available.

Webhook subscriptions, signing secrets and delivery ledger are persisted in /workspace/cybernova-updater/events with mode 0600, owned by cybernova. The delivery worker scans reports every 30 seconds, emits one signed Standard Webhooks notification per matching report, and remembers accepted deliveries across restarts. HTTPS callbacks must resolve only to public IP addresses and are TLS-verified with DNS-pinned connections; redirects are not followed. No OpenAI API inference calls are made by the worker.

Only users of the private, single-user tunnel are authorized. This prototype does not implement multi-user identity/account partitioning. Do not expose the underlying server publicly or share its tunnel.

## Install and test

The installation helper runs all unit tests before changing the working tunnel:

    bash cybernova/mcp-addon/install.sh --check
    bash cybernova/mcp-addon/install.sh --activate

Refresh the existing ChatGPT CyberSec Vast plugin after activation. Confirm the cybernova.deployment.completed event appears and subscribe in a ChatGPT interface supporting MCP Events. The user supplies the subscription request through ChatGPT; this code does not invent a callback URL or signing secret.

Only successful challenge verification establishes an active subscription. An actual subscribed ChatGPT wake-up cannot be claimed until delivery is accepted by the supplied callback and ChatGPT responds.

Official protocol reference: https://developers.openai.com/plugins/build/mcp-events


## Fixed Cybernova research sessions (no per-command terminal approval)

This add-on defines **three typed tools**, separate from the original terminal API:

- `cybernova_session_start()` starts one predefined `local_qwen_baseline` job, returning a session ID immediately.
- `cybernova_session_status(session_id)` reports running, completed, failed or stalled.
- `cybernova_session_report(session_id)` returns bounded, non-sensitive validation metadata and verified evidence count.

The fixed preset invokes the **real local Qwen** and seven implemented adapters from the existing isolated checkout at `/workspace/cybernova-pentest-kit-src/cybernova/v10/pentest_pack`, using `/workspace/cybernova-lab-review-venv/bin/python`. It requires the environment previously prepared on Vast; it does not silently install dependencies.

The runner is executed as unprivileged `cybernova`, keeps private session records in `/workspace/cybernova-updater/sessions`, accepts no arbitrary commands, paths, hostnames, URLs, ports, shell arguments or new presets, and only permits loopback/offline synthetic actions. One session at a time; bounded timeout; raw stdout/stderr and original evidence remain private on Vast. Both scripted adapter use and Qwen-selected actions must pass before the final result is marked successful.

**This is not an external scanner.** It does not enable active assessment of `simnet.ua`, change `PLAN_ONLY`, or remove the original `terminal_execute` user-approval rule. Expanding from local baseline to an explicitly authorized external assessment must be developed and reviewed separately.

**One-time activation is still required.** First deploy this reviewed MCP add-on on Vast using `install.sh --check`, then `install.sh --activate` and refresh the connected MCP plugin. The current chat-only terminal tool cannot self-approve this installation; Work can operate the Jupyter terminal with the operator's existing access. Once the new tools are installed, their fixed research sessions do not use `approve_command.py` per internal step.

The code is staged in a feature branch for review. No deployment or tunnel restart occurs when the branch is created.

## Session-control installation review (18 November 2026)

The MCP wrapper requires the **v2 discovery/custom-handler APIs**, pinned to `mcp==2.3.0` in `requirements-mcp.txt`. The isolated lab environment is a different dependency boundary: its HTTPX/dnspython and `cybernova_lab` modules are checked as the unprivileged `cybernova` user. The installer never upgrades the live MCP SDK automatically.

`install.sh` defaults to `--check`; activation requires the explicit `--activate` argument. Check mode imports the source wrapper against the original server, checks required handlers, lab dependencies/service-user storage permissions, and the existing tunnel prerequisites without replacing the installed addon/profile. A per-install lock prevents concurrent installers; the lock descriptor is closed before launching long-running children.

Each activation takes a **new snapshot of the immediate previous addon and current profile**, even when that profile already points to an addon. Private `*.activation.<id>` snapshots include checksums. Failure after mutation restores that specific code/profile pair; failed code is preserved for diagnosis. Cron changes and a newly started event worker are rolled back when applicable, and a restarted tunnel is checked again after recovery. A historic `.yaml.before-addon` file is retained only as a legacy backup, not used as the current upgrade rollback source. Recovery errors stop and require operator inspection rather than claiming success.

Local verification: 36 tests passed with MCP SDK 2.3.0, including recovery of an already-installed addon, initial-install rollback, private unique snapshots, corruption refusal, symlinks and incomplete evidence rejection. These tests do **not** substitute for `install.sh --check/--activate` on Vast or prove reconnection of the live tunnel. Activation, plugin tool discovery and a live session remain unverified until actually run and observed there.
