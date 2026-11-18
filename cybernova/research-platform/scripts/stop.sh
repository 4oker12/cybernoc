#!/usr/bin/env bash
set -euo pipefail
SESSION="cybernova-research"
if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
  echo "CYBERNOVA_RESEARCH_STOPPED"
else
  echo "CYBERNOVA_RESEARCH_NOT_RUNNING"
fi
