#!/usr/bin/env bash
# Safely attach deployment tools to the existing Secure MCP Tunnel.
# Run as root on user's Vast container; never prints secrets.
set -Eeuo pipefail
MODE=--activate
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
echo "=== 1. VERIFY SOURCES ==="
test -f "$ORIGINAL" && test -x "$PY" && test -f "$PROFILE"
test -f "$SRC/registry.py" && test -f "$SRC/deployment_ops.py"
test -f "$SRC/addon_server.py" && test -f "$SRC/tests/test_deployment.py"
test -f /workspace/cybernova-updater/config.json
test -L /workspace/cybernova-agent
id cybernova >/dev/null

echo "=== 2. TEST ADDON (ISOLATED) ==="
(cd "$SRC" && /venv/main/bin/python -m unittest discover -s tests -v)
/venv/main/bin/python -m py_compile "$SRC/registry.py" "$SRC/deployment_ops.py" "$SRC/addon_server.py"
"$PY" -c 'import mcp; print("MCP SDK OK")'

if [[ "$MODE" == "--check" ]]; then echo "CHECK OK, tunnel untouched"; exit 0; fi

echo "=== 3. PREPARE ADDON ==="
if [[ -e "$DEST" || -L "$DEST" ]]; then
    [[ -d "$DEST" && ! -L "$DEST" ]] || { echo 'Unsafe addon destination'; exit 1; }
    BACKUP="$DEST.backup.$(date -u +%Y%m%dT%H%M%SZ)"
    mv -- "$DEST" "$BACKUP"
    echo "Previous addon saved: $BACKUP"
fi
install -d -m 0755 "$DEST"
install -m 0644 "$SRC/registry.py" "$DEST/registry.py"
install -m 0644 "$SRC/deployment_ops.py" "$DEST/deployment_ops.py"
install -m 0644 "$SRC/addon_server.py" "$DEST/addon_server.py"

echo "=== 4. VERIFY ORIGINAL SERVER + ADDON ==="
"$PY" - <<'PYCODE'
import sys
sys.path.insert(0,"/workspace/cybernova-mcp-addon")
from addon_server import load_server
mcp=load_server()
print("ORIGINAL MCP AND NEW TOOLS REGISTERED",type(mcp).__name__)
PYCODE

echo "=== 5. SAVE AND UPDATE TUNNEL PROFILE ==="
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

echo "=== 6. RESTART SECURE TUNNEL ==="
test -s "$KEYFILE" || { echo "AUTH FILE MISSING: profile changed, existing tunnel still running"; exit 1; }
test -x "$TUNNEL"
COUNT="$(pgrep -xc tunnel-client || true)"
if [[ "$COUNT" != "1" ]]; then
    echo "EXPECTED ONE TUNNEL PROCESS; FOUND $COUNT. Do not restart automatically."
    exit 1
fi
OLDPID="$(pgrep -x tunnel-client)"
kill -TERM "$OLDPID"
for i in $(seq 1 30); do
    if ! kill -0 "$OLDPID" 2>/dev/null; then break; fi
    sleep 0.2
done
nohup bash -c '
    export CONTROL_PLANE_API_KEY="$(cat /root/.config/tunnel-client/runtime-api-key)"
    exec /usr/local/bin/tunnel-client run --profile cybersec-vast
' >> /workspace/cybersec-tunnel.log 2>&1 < /dev/null &
sleep 4

echo "=== 7. HEALTH ==="
pgrep -ax tunnel-client || true
curl -fsS --max-time 5 http://127.0.0.1:18280/healthz || {
    echo
    echo "Tunnel health failed; restore profile from .before-addon if needed."
    exit 1
}
echo
echo "MCP ADDON ACTIVE — refresh ChatGPT plugin metadata."
