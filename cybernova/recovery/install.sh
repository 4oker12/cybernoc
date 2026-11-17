#!/usr/bin/env bash
# Bootstrap from the PRIVATE cybernova-autodeploy Git repository.
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/cybernova/v10"
BRIDGE_SRC="$ROOT/cybernova/bridge"
PY=/venv/main/bin/python
[[ -x "$PY" ]] || PY=python3
MODEL='brianmatzelle/qwen3-coder-heretic:30b'
info(){ printf '\n[Cybernova Recovery] %s\n' "$*"; }
fail(){ echo "ERROR: $*" >&2; exit 1; }
[[ -d /workspace && -f "$SRC/agent.py" && -f "$BRIDGE_SRC/server.py" ]] || fail 'Missing sources or Vast /workspace'
"$PY" -c 'import tomllib' || fail 'Python 3.11+ required'
command -v nvidia-smi >/dev/null || fail 'No NVIDIA GPU driver'
info 'Verify source tests and GPU'
(cd "$SRC" && "$PY" -m unittest discover -s tests -q)
nvidia-smi --query-gpu=index,name,memory.total --format=csv,noheader
[[ "$*" != '--check' ]] || exit 0
[[ "$#" -eq 0 || "$1" == '--install' ]] || fail 'Usage: bash install.sh [--check|--install]'
[[ "$EUID" -eq 0 ]] || fail 'Initial setup needs root in the Vast container'
AGENT=/workspace/cybernova-agent
PROJECTS=/workspace/cybernova-projects
BRIDGE=/workspace/vast-bridge
[[ ! -L "$AGENT" && ! -L "$BRIDGE" ]] || fail 'Existing managed symlink: use Auto Updater instead'
info 'Install v1.0 agent without deleting projects or jobs'
mkdir -p "$AGENT" "$AGENT/jobs" "$PROJECTS" /workspace/cybernova-backups
if [[ -f "$AGENT/agent.py" ]]; then
 BACKUP="/workspace/cybernova-backups/$(date -u +%Y%m%dT%H%M%SZ)"
 mkdir -p "$BACKUP"
 cp -a "$AGENT/agent.py" "$BACKUP/"
 [[ ! -d "$AGENT/cybernova_agent" ]] || cp -a "$AGENT/cybernova_agent" "$BACKUP/"
fi
cp "$SRC/agent.py" "$SRC/core.py" "$AGENT/"
mkdir -p "$AGENT/cybernova_agent"
cp "$SRC/cybernova_agent/"*.py "$AGENT/cybernova_agent/"
"$PY" -m compileall -q "$AGENT"
if ! id cybernova >/dev/null 2>&1; then
 useradd --system --home-dir /workspace --shell /usr/sbin/nologin cybernova
fi
chown -R cybernova:cybernova "$AGENT" "$PROJECTS"
chmod 700 "$AGENT/jobs"
info 'Install standalone, read-only MCP diagnostics'
mkdir -p "$BRIDGE"
cp "$BRIDGE_SRC/core.py" "$BRIDGE_SRC/server.py" "$BRIDGE_SRC/requirements.txt" "$BRIDGE/"
"$PY" -m venv "$BRIDGE/.venv"
"$BRIDGE/.venv/bin/python" -m pip install -q -r "$BRIDGE/requirements.txt"
(cd "$BRIDGE" && "$BRIDGE/.venv/bin/python" -c 'import mcp,core,server')
info 'Install Ollama if needed'
if ! command -v ollama >/dev/null 2>&1; then
 tmp="$(mktemp)"
 trap 'rm -f "$tmp"' EXIT
 curl -fsSL https://ollama.com/install.sh -o "$tmp"
 sh "$tmp"
 rm -f "$tmp"; trap - EXIT
fi
if ! curl -fsS --max-time 3 http://127.0.0.1:11434/api/version >/dev/null; then
 mkdir -p /workspace/ollama-models /workspace/cybernova-logs
 nohup env OLLAMA_HOST=127.0.0.1:11434 OLLAMA_MODELS=/workspace/ollama-models ollama serve > /workspace/cybernova-logs/ollama.log 2>&1 < /dev/null &
 for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then break; fi
  sleep 1
 done
fi
curl -fsS --max-time 3 http://127.0.0.1:11434/api/version >/dev/null || fail 'Ollama server unavailable'
info 'Pull model (~19GB, cached if already downloaded)'
ollama pull "$MODEL"
info 'Check agent and GPU'
runuser -u cybernova -- "$PY" "$AGENT/agent.py" doctor
ollama ps || true
info 'Source and model installed. ChatGPT MCP tunnel and GitHub SSH deploy key require separate private enrollment.'
