#!/usr/bin/env bash
# Run after the PUBLIC deploy key has been added to GitHub.
set -Eeuo pipefail
WORK=/workspace/cybernova-updater
APP="$WORK/app"
CONFIG="$WORK/config.json"
PY=/venv/main/bin/python
[[ -x "$PY" ]] || PY=/workspace/cybersec-vast-mcp-v02/.venv/bin/python
[[ -x "$PY" ]] || { echo 'Python 3.12 virtual environment missing' >&2; exit 1; }
[[ -e "$WORK/secrets/deploy_key" && -f "$CONFIG" ]] || { echo 'Updater not bootstrapped' >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || { echo 'Start script must be run by operator (root), watcher runs as cybernova' >&2; exit 1; }
runuser -u cybernova -- env PYTHONPATH="$APP" "$PY" -m cybernova_updater.cli --config "$CONFIG" once || {
  echo 'Preflight/baseline failed. Inspect status and reports; not starting daemon.' >&2
  exit 1
}
# Run detached under the unprivileged account; cron adds an optional restart path.
runuser -u cybernova -- sh -c "nohup env PYTHONPATH=$APP $PY -m cybernova_updater.cli --config $CONFIG run >> $WORK/runner.log 2>&1 </dev/null &"
printf 'Cybernova updater daemon launched; state: %s/state.json\n' "$WORK"
# Keep this idempotent and do not alter unrelated cron entries.
if command -v crontab >/dev/null 2>&1; then
  existing="$(crontab -u cybernova -l 2>/dev/null || true)"
  marker="# CYBERNOVA_AUTODEPLOY_RESTART"
  if ! grep -Fq "$marker" <<< "$existing"; then
    { printf '%s\n' "$existing"; printf '@reboot env PYTHONPATH=%s %s -m cybernova_updater.cli --config %s run >> %s/runner.log 2>&1 %s\n' "$APP" "$PY" "$CONFIG" "$WORK" "$marker"; } | crontab -u cybernova -
    echo 'Cron @reboot registration added for cybernova user.'
  fi
fi
