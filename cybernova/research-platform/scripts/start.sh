#!/usr/bin/env bash
# Start a dedicated research console session; leave all other Vast services alone.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="cybernova-research"
PORT="${CYBERNOVA_PORT:-18794}"
case "$PORT" in
  ''|*[!0-9]*) echo "Invalid port"; exit 2;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "Port must be between 1024 and 65535"; exit 2
fi
cd "$ROOT"
python3 -m unittest discover -s tests -p 'test_*.py' -q
python3 app.py --check --db /tmp/cybernova-console-preflight.sqlite3
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "CYBERNOVA_RESEARCH_ALREADY_RUNNING"
else
  if command -v ss >/dev/null 2>&1 &&
     ss -lnt "( sport = :$PORT )" | grep -q LISTEN; then
    echo "Port $PORT already has another listener, refusing to start"
    exit 3
  fi
  mkdir -p state
  export CYBERNOVA_PORT="$PORT"
  tmux new-session -d -s "$SESSION" "cd '$ROOT' && exec bash scripts/serve.sh"
fi
python3 - "$PORT" <<'PY'
import json
import sys
import time
from urllib.request import urlopen
port=int(sys.argv[1])
for attempt in range(20):
    try:
        with urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2) as response:
            data=json.load(response)
        if not data.get("ok") or data["result"].get("network_scanning_available"):
            raise SystemExit("Unsafe or invalid controller status")
        print("CYBERNOVA_RESEARCH_READY=http://127.0.0.1:%d/" % port)
        print("OFFLINE_TOOLS=%d LOCAL_QWEN_ENABLED=%s" % (
            data["result"]["implemented_offline_tools"], data["result"]["agent_enabled"]))
        break
    except (OSError,ValueError,KeyError):
        time.sleep(.25)
else:
    raise SystemExit("Console did not respond; inspect tmux cybernova-research")
PY
