#!/usr/bin/env bash
# Cybernova Qwen + Open WebUI. Non-destructive, binds UI only to 127.0.0.1.
set -Eeuo pipefail
umask 077

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="/workspace/cybernova-qwen-webui-runtime"
WEB_PORT="18791"
OLLAMA_URL="http://127.0.0.1:11434"
mkdir -p "$RUNTIME" "$RUNTIME/data"
chmod 700 "$RUNTIME"

if ! curl --noproxy '*' -fsS --max-time 5 "$OLLAMA_URL/api/tags" >/dev/null; then
  echo 'ERROR: Ollama API is unavailable at localhost:11434' >&2
  exit 2
fi
if ! ollama show brianmatzelle/qwen3-coder-heretic:30b >/dev/null 2>&1; then
  echo 'ERROR: existing Qwen Heretic model is not installed' >&2
  exit 3
fi
echo '[1/4] Creating persistent specialized Ollama model'
ollama create cybernova-security:30b -f "$HERE/Modelfile" >/dev/null

SECRET="$RUNTIME/webui-secret"
if [ ! -s "$SECRET" ]; then
  (umask 077; openssl rand -hex 32 > "$SECRET")
fi
chmod 600 "$SECRET"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo '[2/4] Installing WebUI using Docker Compose'
  ENVFILE="$RUNTIME/.env"
  (umask 077; printf 'WEBUI_SECRET_KEY=%s\n' "$(cat "$SECRET")" > "$ENVFILE")
  chmod 600 "$ENVFILE"
  docker compose --project-name cybernova-webui --env-file "$ENVFILE" -f "$HERE/compose.yml" up -d
  echo 'LAUNCH_MODE=docker'
else
  echo '[2/4] Docker unavailable; using isolated Python venv'
  VENV="$RUNTIME/venv"
  if [ ! -x "$VENV/bin/open-webui" ]; then
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install --disable-pip-version-check --upgrade pip
    "$VENV/bin/python" -m pip install --disable-pip-version-check open-webui
  fi
  if ! command -v tmux >/dev/null 2>&1; then
    echo 'ERROR: tmux unavailable; cannot persist Python WebUI process' >&2
    exit 4
  fi
  if ! tmux has-session -t cybernova-webui 2>/dev/null; then
    tmux new-session -d -s cybernova-webui "bash '$HERE/start-python.sh'"
  fi
  echo 'LAUNCH_MODE=python-tmux'
fi

echo '[3/4] Checking model metadata'
ollama show cybernova-security:30b | head -25
echo '[4/4] Checking private listener'
sleep 3
if curl --noproxy '*' -fsS --max-time 5 "http://127.0.0.1:$WEB_PORT/" >/dev/null; then
  echo "CYBERNOVA_WEBUI_READY=http://127.0.0.1:$WEB_PORT"
else
  echo "CYBERNOVA_WEBUI_STARTING=http://127.0.0.1:$WEB_PORT"
  echo "For Python mode: tmux capture-pane -t cybernova-webui -p | tail -50"
  echo "For Docker mode: docker compose --project-name cybernova-webui -f $HERE/compose.yml logs --tail 50"
fi
echo 'IMPORTANT: local-only listener. Use private SSH forwarding or authenticated tunnel, never expose Ollama directly.'
