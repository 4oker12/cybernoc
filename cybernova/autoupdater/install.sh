#!/usr/bin/env bash
# One-time Vast bootstrap. Runs by the operator as root, the watcher never does.
set -Eeuo pipefail
[[ "$EUID" == 0 ]] || { echo 'Install bootstrap requires root once' >&2; exit 1; }
SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORK=/workspace/cybernova-updater
ACTIVE=/workspace/cybernova-agent
APP=$WORK/app
SECRETS=$WORK/secrets
USER_NAME=cybernova
[[ -d /workspace ]] || { echo 'Missing /workspace' >&2; exit 1; }
[[ -x /venv/main/bin/python ]] || { echo 'Vast Python 3.12 missing' >&2; exit 1; }
[[ ! -L "$WORK" ]] || { echo 'Unsafe updater work symlink' >&2; exit 1; }
PYTHONPATH="$SRC" PYTHONPATH="$SRC" /venv/main/bin/python -m unittest discover -s "$SRC/tests" -v
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$WORK" --shell /usr/sbin/nologin "$USER_NAME"
fi
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$WORK" "$SECRETS" "$WORK/releases" "$WORK/reports" "$WORK/data" "$WORK/data/jobs" "$WORK/data/operations"
if [[ -e "$ACTIVE" && ! -L "$ACTIVE" ]]; then
    [[ -d "$ACTIVE" ]] || { echo 'Active agent must be a directory' >&2; exit 1; }
    [[ ! -e "$WORK/current" && ! -L "$WORK/current" ]] || { echo 'Existing pointer but legacy agent not enrolled; manual review' >&2; exit 1; }
    [[ ! -e "$WORK/legacy-agent" ]] || { echo 'Legacy backup exists; manual review' >&2; exit 1; }
    # Refuse migration while local Qwen worker is running.
    if [[ -d "$ACTIVE/jobs" ]]; then
        /venv/main/bin/python - "$ACTIVE/jobs" <<'PYCODE'
import os,sys,json,pathlib
for p in pathlib.Path(sys.argv[1]).glob('*/state.json'):
    try: s=json.loads(p.read_text())
    except Exception: continue
    if s.get('status') in ('queued','running'):
        pid=s.get('pid')
        if isinstance(pid,int) and pid>1:
            try: os.kill(pid,0)
            except ProcessLookupError: continue
            except PermissionError: pass
            raise SystemExit('ERROR: active Qwen worker; stop it before migration')
PYCODE
    fi
    mv -- "$ACTIVE" "$WORK/legacy-agent"
    for state_dir in jobs operations; do
        if [[ -d "$WORK/legacy-agent/$state_dir" && ! -L "$WORK/legacy-agent/$state_dir" ]]; then
            # Do not replace a previously migrated persistent folder.
            if [[ -n "$(ls -A "$WORK/data/$state_dir")" ]]; then
                echo "Persistent $state_dir is non-empty, manual review required" >&2; exit 1
            fi
            rmdir "$WORK/data/$state_dir"
            mv "$WORK/legacy-agent/$state_dir" "$WORK/data/$state_dir"
        fi
        if [[ ! -e "$WORK/legacy-agent/$state_dir" ]]; then
            ln -s "$WORK/data/$state_dir" "$WORK/legacy-agent/$state_dir"
        fi
    done
    chown -R "$USER_NAME:$USER_NAME" "$WORK/legacy-agent" "$WORK/data"
    ln -s "$WORK/legacy-agent" "$WORK/current"
    ln -s "$WORK/current" "$ACTIVE"
fi
if [[ ! -L "$ACTIVE" ]] || [[ "$(readlink "$ACTIVE")" != "$WORK/current" ]]; then
    echo 'Active agent symlink is invalid; stop and inspect' >&2; exit 1
fi
if [[ -d "$APP" ]]; then
    rm -rf "$WORK/app-old"
    mv -- "$APP" "$WORK/app-old"
fi
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$APP/cybernova_updater"
cp -p "$SRC"/cybernova_updater/*.py "$APP/cybernova_updater/"
chown -R "$USER_NAME:$USER_NAME" "$APP"
if [[ ! -f "$WORK/config.json" ]]; then
    install -o "$USER_NAME" -g "$USER_NAME" -m 0600 "$SRC/config.example.json" "$WORK/config.json"
fi
if [[ ! -f "$SECRETS/deploy_key" ]]; then
    runuser -u "$USER_NAME" -- ssh-keygen -q -t ed25519 -N '' -f "$SECRETS/deploy_key" -C 'cybernova-vast-readonly'
fi
# GitHub.com official Ed25519 host key, per docs.github.com; never use accept-new/ssh-keyscan unverified.
cat > "$SECRETS/known_hosts" <<'KNOWN'
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
KNOWN
chown "$USER_NAME:$USER_NAME" "$SECRETS/known_hosts"
chmod 600 "$SECRETS/known_hosts" "$SECRETS/deploy_key" "$WORK/config.json"
# Prevent accidentally running without the GitHub deploy key grant: start only after user adds key.
printf '\nBOOTSTRAP OK. Add this PUBLIC key to GitHub Deploy keys (read-only):\n\n'
cat "$SECRETS/deploy_key.pub"
printf '\nGitHub: https://github.com/4oker12/cybernoc/settings/keys\n'
printf 'After adding the key, start via:\n'
printf '  runuser -u cybernova -- env PYTHONPATH=%s /venv/main/bin/python -m cybernova_updater.cli --config %s/config.json run\n' "$APP" "$WORK"
printf 'Do not paste private key or GitHub Issues token into chat.\n'
