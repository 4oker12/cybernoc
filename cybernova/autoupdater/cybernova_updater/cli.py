"""Operational entrypoint for the Cybernova 24-hour Git auto-updater."""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import sys
from .core import Settings, Watcher


def main(argv=None):
    parser = argparse.ArgumentParser(description='Cybernova Git 30s/24h stop-on-failure updater')
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('command', choices=('run', 'once', 'status'))
    args = parser.parse_args(argv)
    cfg = Settings.from_json(args.config)
    if args.command == 'status':
        state = cfg.work / 'state.json'
        print(state.read_text(encoding='utf-8') if state.is_file() else '{"status": "not_initialized"}')
        return 0
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        parser.error('Refusing to deploy as root; run as the dedicated cybernova user')
    cfg.work.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (cfg.work / '.runner.lock').open('a+') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'ok': False, 'error': 'Another updater instance owns the lock'}))
            return 2
        watcher = Watcher(cfg)
        state = watcher.tick() if args.command == 'once' else watcher.run()
        print(json.dumps({'status': state['status'], 'deployed_commit': state.get('deployed_commit'),
                          'error': state.get('error'), 'expires_at': state.get('expires_at')},ensure_ascii=False))
        return 1 if state['status'] == 'stopped_error' else 0


if __name__ == '__main__':
    sys.exit(main())
