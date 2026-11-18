# Cybernova Event Ring — Control Panel v0.1

A real, **local-only** control console for Cybernova on Vast. Python 3 standard library; no npm/build dependencies. It reads the existing Cybernova session and agent state files and Ollama's *fixed localhost* status endpoints. It does **not** alter the existing CyberSec MCP tunnel, updater, agent, or Ollama installation.

## Capabilities

- Seven-node ring: Trigger → ChatGPT → Session Control → Qwen → Tools → Observer → Decision.
- Shows actual local sessions (bounded), agent jobs, error statuses, allowlisted event metadata, Ollama model status and updater state.
- Auto refresh every five seconds; data is explicitly marked `LIVE` or `DEMO`.
- Copy a status summary for the ordinary ChatGPT conversation.
- Optional protected **Start Local Baseline** action calls exactly the preinstalled fixed `session_ops.py start` preset. No arbitrary commands, external targets, URLs, file paths or project names accepted from browser.
- UI blocks duplicate session starts; the session runner itself enforces a lock and one active session.

## Run a demo on any computer

```bash
python server.py --demo --port 18789
```

Open `http://127.0.0.1:18789/`. Demo mode is clearly labeled, uses synthetic data, and cannot start sessions. It is for visual review, **not** a real Vast connection.

## First live run on the existing Vast host

**Do not add this to the watched `cybernova-autodeploy` agent branch.** Check out this feature PR as a separate reviewed source directory and copy this `cybernova/control-panel` folder to a readable installation path. The installed MCP addon, existing updater and Qwen must remain unchanged.

The panel must run under the unprivileged `cybernova` user (the same user that owns its private sessions). Choose the token-file path under its private home/config directory. Example with a source checkout at `/workspace/cybernova-panel-src`:

```bash
# Check out/copy the reviewed panel source first. Run these only on a host you administer.
install -d -o cybernova -g cybernova -m 0700 /workspace/cybernova-panel-private
runuser -u cybernova -- /venv/main/bin/python /workspace/cybernova-panel-src/cybernova/control-panel/server.py \
    --init-token --token-file /workspace/cybernova-panel-private/token
runuser -u cybernova -- /venv/main/bin/python /workspace/cybernova-panel-src/cybernova/control-panel/server.py \
    --port 18789 --token-file /workspace/cybernova-panel-private/token
```

For an **explicit opt-in** to start predefined offline sessions, add `--enable-start` to the second command. The default is read-only.

The panel binds **only 127.0.0.1** on Vast. From Windows, open a local tunnel using your existing authorized SSH access, for example `ssh -L 18789:127.0.0.1:18789 <your-existing-vast-ssh-alias>`; then browse to `http://127.0.0.1:18789/`. Do not create a public `cloudflared` tunnel or expose port 18789 to `0.0.0.0`. Read the random token with your authorized server access and enter it in the panel login (never paste it into ChatGPT).

## Security and limitations

- Read access and control actions require a random private token in an `X-Cybernova-Token` header. Token lives in a 0600 file and is not logged or embedded into HTML.
- Same-origin POST, exact Host allowlist, no CORS, restrictive CSP, no-cache, clickjacking prevention.
- Read model refuses symlink session records, validates session IDs, restricts JSON sizes, redacts selected error text, and exposes **event names only** (not raw prompts, stdout, secrets or arbitrary tool arguments).
- UI uses DOM `textContent` for untrusted data (no HTML interpolation for logs).
- No real-time ChatGPT activity tracking; ordinary ChatGPT cannot be 'woken' server-side by this panel. ChatGPT is labeled external/manual. Event Ring is a visualization and a foundation for future transitions, not an already running self-driving loop.
- The `--enable-start` option is a permitted on-host administrative action; user must explicitly run the panel with it. Panel never circumvents the original terminal approval feature.
- Session report data are a limited view, not the complete raw evidence ledger.
- Operational status is best-effort: direct on-host reads can be blocked by filesystem permissions or missing optional components, which appear as empty/unknown rather than fabricated success.

## Tests

```bash
python -m unittest discover -s tests -v
python -m py_compile server.py ring.py
```

## Roadmap

1. Define durable append-only `cycle_id`, `phase`, event sequence and idempotency keys in an Observer service.
2. Add a limited typed 'package run' executor for locally authorized `PORTS`/`HTTP`/`TLS` fixture packs.
3. Teach the Windows controller to report verified completion and request *human-observable* ChatGPT analysis only when new evidence is ready. Explicit limits, approvals and pause controls before auto-iteration.
4. Extend the dashboard with evidence drill-down, module skills matrix, review of Qwen mistakes, progress over exercises, and approval gates for higher-risk work.