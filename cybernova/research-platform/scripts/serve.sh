#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PORT="${CYBERNOVA_PORT:-18794}"
LLM="${CYBERNOVA_LLM_ENABLED:-0}"
if [ "$LLM" = "1" ]; then
  exec python3 app.py --port "$PORT" --enable-local-llm --model "${CYBERNOVA_MODEL:-cybernova-security:30b}"
else
  exec python3 app.py --port "$PORT"
fi
