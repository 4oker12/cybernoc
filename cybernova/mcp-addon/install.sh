#!/usr/bin/env bash
# Safely attach deployment tools to the existing Secure MCP Tunnel.
# Run as root on user's Vast container; never prints secrets.
set -Eeuo pipefail
umask 077
MODE=--check
[[ "$#" -le 1 ]] || { echo 'Usage: install.sh [--check|--activate]'; exit 2; }
if [[ "$#" -gt 0 ]]; then MODE="$1"; fi
[[ "$MODE" == "--activate" || "$MODE" == "--check" ]] || { echo 'Usage: install.sh [--check|--activate]'; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo 'Run as root to manage existing tunnel profile'; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/workspace/cybernova-mcp-addon
ORIGINAL=/workspace/cybersec-vast-mcp-v02/server.py
PY=/workspace/cybersec-vast-mcp-v02/.venv/bin/python
PROFILE=/root/.config/tunnel-client/cybersec-vast.yaml
KEYFILE=/root/.config/tunnel-client/runtime-api-key
TUNNEL=/usr/local/bin/tunnel-client
exec 9>/workspace/.cybernova-mcp-addon.install.lock
flock -n 9 || { echo 'Another addon installer is running'; exit 1; }
echo "=== 1. VERIFY SOURCES ==="
test -f "$ORIGINAL" && test -x "$PY" && test -f "$PROFILE"
test -f "$SRC/registry.py" && test -f "$SRC/deployment_ops.py"
test -f "$SRC/addon_server.py" && test -f "$SRC/tests/test_deployment.py"
test -f "$SRC/session_registry.py" && test -f "$SRC/session_ops.py"
test -f "$SRC/events_core.py" && test -f "$SRC/events_bridge.py"
test -f "$SRC/install_state.py"
test -f "$SRC/tests/test_events.py" && test -f "$SRC/tests/test_sessions.py"
test -f /workspace/cybernova-updater/config.json
test -L /workspace/cybernova-agent
id cybernova >/dev/null

echo "=== 2. TEST ADDON (ISOLATED) ==="
"$PY" - <<'PYCODE'
import importlib.metadata
from mcp import types
from mcp.server.mcpserver import MCPServer
if not hasattr(types, "DiscoverResult"):
    raise SystemExit("MCP SDK v2 discovery API required; no dependency is changed automatically")
print("MCP SDK", importlib.metadata.version("mcp"))
PYCODE
(cd "$SRC" && "$PY" -m unittest discover -s tests -v)
"$PY" -m py_compile "$SRC/registry.py" "$SRC/deployment_ops.py" "$SRC/addon_server.py" "$SRC/events_core.py" "$SRC/events_bridge.py" "$SRC/session_registry.py" "$SRC/session_ops.py"
"$PY" -m py_compile "$SRC/install_state.py"

echo "=== 2a. VERIFY SOURCE WRAPPER WITHOUT CHANGING DEPLOYMENT ==="
"$PY" - "$SRC" <<'PYCODE'
import sys
sys.path.insert(0, sys.argv[1])
from addon_server import load_server
server = load_server()
required = ("server/discover", "events/list", "events/subscribe", "events/unsubscribe", "tools/list")
if not all(server._lowlevel_server.get_request_handler(method) is not None for method in required):
    raise SystemExit("Required MCP handlers missing")
print("Original server plus source addon imports successfully")
PYCODE

echo "=== 2b. VERIFY SESSION ENVIRONMENT AS SERVICE USER ==="
/usr/sbin/runuser -u cybernova -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 HOME=/nonexistent \
    /venv/main/bin/python - "$SRC/session_ops.py" <<'PYCODE'
import importlib.util, os, subprocess, sys
spec = importlib.util.spec_from_file_location("session_preflight", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if not module.LAB_PY.is_file() or not (module.LAB / "cybernova_lab" / "__main__.py").is_file():
    raise SystemExit("Session lab source or isolated Python missing")
storage = module.ROOT if module.ROOT.exists() else module.ROOT.parent
if storage.is_symlink() or not os.access(storage, os.W_OK | os.X_OK):
    raise SystemExit("Service user cannot write session storage")
subprocess.run([str(module.LAB_PY), "-c", "import httpx, dns; from cybernova_lab.registry import REGISTRY; from cybernova_lab.ollama import OllamaDecider; assert {'curl.http','httpx.http','openssl.x509','jq.json','python.ip','python.syntax','dnspython.zone'} <= set(REGISTRY); print('Session dependencies OK')"], cwd=module.LAB, check=True, timeout=20)
PYCODE

echo "=== 2c. VERIFY EXISTING TUNNEL ==="
test -s "$KEYFILE" || { echo "AUTH FILE MISSING: existing tunnel left untouched"; exit 1; }
test -x "$TUNNEL"
COUNT="$(pgrep -xc tunnel-client || true)"
if [[ "$COUNT" != "1" ]]; then
    echo "EXPECTED ONE TUNNEL PROCESS; FOUND $COUNT. Existing tunnel left untouched."
    exit 1
fi
OLDPID="$(pgrep -x tunnel-client)"


if [[ "$MODE" == "--check" ]]; then echo "CHECK OK, tunnel untouched"; exit 0; fi

# Snapshot the immediate previous state, including an already activated addon.
# A historical before-addon profile alone is not a rollback of an addon upgrade.
SNAPSHOT="$("$PY" "$SRC/install_state.py" snapshot "$DEST" "$PROFILE")"
CRON_TOUCHED=0
EVENT_WORKER_STARTED=0
TUNNEL_TOUCHED=0
if command -v crontab >/dev/null 2>&1; then
    crontab -u cybernova -l > "$SNAPSHOT/cron.before" 2>/dev/null || :
fi
start_tunnel() {
    nohup bash -c '
        export CONTROL_PLANE_API_KEY="$(cat /root/.config/tunnel-client/runtime-api-key)"
        exec /usr/local/bin/tunnel-client run --profile cybersec-vast
    ' >> /workspace/cybersec-tunnel.log 2>&1 < /dev/null 9>&- &
}
recover_activation() {
    local rc="$1"
    trap - ERR INT TERM
    set +e
    echo "Activation failed; restoring immediate previous addon/profile. Snapshot: $SNAPSHOT"
    if [[ "$EVENT_WORKER_STARTED" == 1 ]]; then
        pgrep -u cybernova -f '^/venv/main/bin/python /workspace/cybernova-mcp-addon/events_core.py poll$' | xargs -r kill -TERM
    fi
    if [[ "$TUNNEL_TOUCHED" == 1 ]]; then
        local current_pid
        current_pid="$(pgrep -x tunnel-client || true)"
        if [[ "$current_pid" =~ ^[0-9]+$ ]]; then
            kill -TERM "$current_pid"
            for _ in $(seq 1 30); do
                kill -0 "$current_pid" 2>/dev/null || break
                sleep 0.2
            done
        fi
    fi
    "$PY" "$SRC/install_state.py" restore "$SNAPSHOT" || { echo 'Snapshot restoration failed; manual recovery required'; exit 1; }
    if [[ "$CRON_TOUCHED" == 1 ]]; then crontab -u cybernova "$SNAPSHOT/cron.before"; fi
    if [[ "$TUNNEL_TOUCHED" == 1 ]]; then
        if [[ "$(pgrep -xc tunnel-client || true)" == 0 ]]; then start_tunnel; fi
        sleep 4
        curl -fsS --max-time 5 http://127.0.0.1:18280/healthz >/dev/null && echo 'Previous tunnel health restored'
    fi
    exit "$rc"
}
trap 'recover_activation $?' ERR
trap 'recover_activation 130' INT
trap 'recover_activation 143' TERM

echo "=== 3. PREPARE ADDON ==="
if [[ -e "$DEST" || -L "$DEST" ]]; then
    [[ -d "$DEST" && ! -L "$DEST" ]] || { echo 'Unsafe addon destination'; false; }
    BACKUP="$DEST.backup.$(date -u +%Y%m%dT%H%M%SZ)"
    mv -- "$DEST" "$BACKUP"
    echo "Previous addon saved: $BACKUP"
fi
install -d -m 0755 "$DEST"
install -m 0644 "$SRC/registry.py" "$DEST/registry.py"
install -m 0644 "$SRC/deployment_ops.py" "$DEST/deployment_ops.py"
install -m 0644 "$SRC/addon_server.py" "$DEST/addon_server.py"
install -m 0644 "$SRC/events_core.py" "$DEST/events_core.py"
install -m 0644 "$SRC/events_bridge.py" "$DEST/events_bridge.py"
install -m 0644 "$SRC/session_registry.py" "$DEST/session_registry.py"
install -m 0644 "$SRC/session_ops.py" "$DEST/session_ops.py"
install -m 0644 "$SRC/install_state.py" "$DEST/install_state.py"
install -d -m 0700 -o cybernova -g cybernova /workspace/cybernova-updater/sessions

echo "=== 4. VERIFY ORIGINAL SERVER + ADDON ==="
"$PY" - <<'PYCODE'
import sys
sys.path.insert(0,"/workspace/cybernova-mcp-addon")
from addon_server import load_server
mcp=load_server()
ll = mcp._lowlevel_server
required = ("server/discover","events/list","events/subscribe","events/unsubscribe")
assert all(ll.get_request_handler(method) is not None for method in required)
print("ORIGINAL MCP AND EVENTS RPC REGISTERED",type(mcp).__name__)
PYCODE

echo "=== 6. SAVE AND UPDATE TUNNEL PROFILE ==="
/venv/main/bin/python - "$PROFILE" <<'PYCODE'
import os, pathlib, sys, shutil
profile=pathlib.Path(sys.argv[1])
old="/workspace/cybersec-vast-mcp-v02/server.py"
new="/workspace/cybernova-mcp-addon/addon_server.py"
text=profile.read_text(encoding="utf-8")
if new in text:
    print("PROFILE ALREADY POINTS TO ADDON")
elif text.count(old)!=1:
    raise SystemExit("Refusing: original MCP command not found exactly once")
else:
    backup=profile.with_suffix(".yaml.before-addon")
    if not backup.exists():
        shutil.copy2(profile,backup)
        os.chmod(backup,0o600)
    tmp=profile.with_suffix(".yaml.new")
    tmp.write_text(text.replace(old,new),encoding="utf-8")
    os.chmod(tmp,0o600)
    os.replace(tmp,profile)
    print("PROFILE UPDATED; BACKUP:",backup)
PYCODE

echo "=== 7. RESTART SECURE TUNNEL ==="
TUNNEL_TOUCHED=1
kill -TERM "$OLDPID"
for i in $(seq 1 30); do
    if ! kill -0 "$OLDPID" 2>/dev/null; then break; fi
    sleep 0.2
done
if kill -0 "$OLDPID" 2>/dev/null; then
    echo "OLD TUNNEL DID NOT STOP; refusing to start a second one."
    false
fi
start_tunnel
sleep 4

echo "=== 8. HEALTH ==="
pgrep -ax tunnel-client || true
if curl -fsS --max-time 5 http://127.0.0.1:18280/healthz; then
    echo
    echo "MCP ADDON ACTIVE — refresh ChatGPT plugin metadata."
else
    echo "New tunnel failed health"
    false
fi

echo "=== 9. START EVENT DELIVERY WORKER ==="
install -d -m 0700 -o cybernova -g cybernova /workspace/cybernova-updater/events
if ! pgrep -u cybernova -f "^/venv/main/bin/python /workspace/cybernova-mcp-addon/events_core.py poll$" >/dev/null; then
    EVENT_WORKER_STARTED=1
    runuser -u cybernova -- sh -c 'nohup /venv/main/bin/python /workspace/cybernova-mcp-addon/events_core.py poll >> /workspace/cybernova-updater/events/worker.log 2>&1 < /dev/null 9>&- &' 9>&-
fi
if command -v crontab >/dev/null 2>&1; then
    CURRENT="$(crontab -u cybernova -l 2>/dev/null || true)"
    if ! printf "%s\n" "$CURRENT" | grep -q "CYBERNOVA_EVENTS_WORKER_RESTART"; then
        CRON_TOUCHED=1
        { printf "%s\n" "$CURRENT"; printf "%s\n" "@reboot /venv/main/bin/python /workspace/cybernova-mcp-addon/events_core.py poll >> /workspace/cybernova-updater/events/worker.log 2>&1 # CYBERNOVA_EVENTS_WORKER_RESTART"; } | crontab -u cybernova -
    fi
fi
sleep 1
pgrep -u cybernova -af "events_core.py poll" || { echo "Event worker did not start"; false; }
trap - ERR INT TERM
echo "Activation recovery snapshot: $SNAPSHOT"
echo "MCP EVENTS BACKEND STARTED — now rescan the ChatGPT plugin events."
