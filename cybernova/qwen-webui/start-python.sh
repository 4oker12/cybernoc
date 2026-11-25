#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
RUNTIME="/workspace/cybernova-qwen-webui-runtime"
export DATA_DIR="$RUNTIME/data"
export WEBUI_SECRET_KEY="$(cat "$RUNTIME/webui-secret")"
export OLLAMA_BASE_URL="http://127.0.0.1:11434"
export ENABLE_SIGNUP="True"
export WEBUI_AUTH="True"
exec "$RUNTIME/venv/bin/open-webui" serve --host 127.0.0.1 --port 18791
