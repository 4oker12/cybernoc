#!/usr/bin/env bash
# Only local MCP startup. No additional packages and no WebUI modifications.
set -Eeuo pipefail
umask 077
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
PY="/workspace/cybernova-qwen-webui-runtime/venv/bin/python"
if [ ! -x "$PY" ]; then echo 'ERROR: existing WebUI venv not found' >&2; exit 2; fi
"$PY" -c 'from mcp.server.mcpserver import MCPServer; print("SDK_V2_OK")'
PYTHONPATH="$HERE" "$PY" -m unittest discover -s "$HERE/tests" -p 'test_*.py' -v
if ss -lnt '( sport = :18792 )' | grep -q LISTEN; then
    tmux has-session -t cybernova-tools 2>/dev/null || { echo "Untracked port 18792 process"; exit 3; }
elif tmux has-session -t cybernova-tools 2>/dev/null; then
    echo 'MCP tmux exists but not listening; inspect manually' >&2
    exit 4
else
    tmux new-session -d -s cybernova-tools "exec '$PY' -u '$HERE/server.py'"
fi
"$PY" "$HERE/smoke.py"
echo 'CYBERNOVA_MCP_READY=http://127.0.0.1:18792/mcp'
