#!/usr/bin/env python3
"""Local-only Cybernova control panel. API requires a private bearer token."""
from __future__ import annotations
import argparse
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hashlib
import hmac
import json
import os
import secrets
import sys
from urllib.parse import urlsplit

from ring import Paths, snapshot, start_local_baseline

HERE = Path(__file__).resolve().parent
WEB = HERE / 'web'
FILES = {'/': ('index.html', 'text/html; charset=utf-8'),
         '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
         '/style.css': ('style.css', 'text/css; charset=utf-8')}
DEFAULT_TOKEN_FILE = Path.home() / '.local/share/cybernova-panel/token'


def create_token_file(path: Path):
    if path.exists() or path.is_symlink():
        raise FileExistsError('Token already exists; not replacing')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(secrets.token_urlsafe(48) + '\n')
    return path


def read_token(path: Path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing or unsafe token file; use --init-token')
    mode = path.stat().st_mode
    if mode & 0o077:
        raise ValueError('Token file permissions must be 0600')
    value = path.read_text(encoding='utf-8').strip()
    if len(value) < 40 or len(value) > 256:
        raise ValueError('Invalid token length')
    return value


class PanelHandler(BaseHTTPRequestHandler):
    server_version = 'CybernovaPanel/0.1'
    sys_version = ''

    def _headers(self, code, mime='application/json; charset=utf-8', size=0):
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _json(self, data, status=200):
        buf = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self._headers(status, size=len(buf))
        self.wfile.write(buf)

    def _safe_host(self):
        # No alternate Host values, to avoid localhost DNS rebinding.
        host = self.headers.get('Host','').lower()
        return host in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}

    def _auth(self):
        given = self.headers.get('X-Cybernova-Token', '')
        return hmac.compare_digest(given, self.server.token)

    def _origin_ok(self):
        origin = self.headers.get('Origin', '')
        return origin in {f'http://127.0.0.1:{self.server.server_port}', f'http://localhost:{self.server.server_port}'}

    def do_GET(self):
        if not self._safe_host():
            return self._json({'ok': False, 'error':'invalid_host'}, 403)
        path = urlsplit(self.path).path
        if path in FILES:
            filename, mime = FILES[path]
            data = (WEB / filename).read_bytes()
            self._headers(200, mime, len(data))
            return self.wfile.write(data)
        if not self._auth():
            return self._json({'ok': False, 'error':'unauthorized'}, 401)
        if path == '/api/status':
            data = snapshot(self.server.paths, demo=self.server.demo)
            data['capabilities'] = {'local_session_start':self.server.enable_start and not self.server.demo,
                                    'automatic_chat_wake':False,'external_scanning':False}
            return self._json(data)
        return self._json({'ok': False, 'error':'not_found'}, 404)

    def do_POST(self):
        if not self._safe_host() or not self._origin_ok():
            return self._json({'ok': False, 'error':'forbidden_origin'}, 403)
        if not self._auth():
            return self._json({'ok': False, 'error':'unauthorized'}, 401)
        if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Content-Length') != '2':
            return self._json({'ok':False,'error':'invalid_payload'}, 400)
        if self.rfile.read(2) != b'{}':
            return self._json({'ok':False,'error':'invalid_payload'}, 400)
        if urlsplit(self.path).path != '/api/session/start':
            return self._json({'ok':False,'error':'not_found'},404)
        if self.server.demo or not self.server.enable_start:
            return self._json({'ok':False,'error':'start_disabled'},403)
        data = start_local_baseline(self.server.paths)
        return self._json(data, 200 if data.get('ok') else 409)

    def log_message(self, format, *args):
        # Avoid logging paths/queries or authentication material.
        pass


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, token, paths, demo=False, enable_start=False):
        super().__init__(address, PanelHandler)
        self.token=token
        self.paths=paths
        self.demo=demo
        self.enable_start=enable_start


def main(argv=None):
    parser = argparse.ArgumentParser(description='Cybernova localhost-only ring control panel')
    parser.add_argument('--port', type=int, default=18789)
    parser.add_argument('--demo', action='store_true', help='Explicitly simulated data; no Vast calls')
    parser.add_argument('--enable-start', action='store_true', help='Allow ONLY fixed offline Qwen baseline')
    parser.add_argument('--init-token', action='store_true', help='Generate private token file once')
    parser.add_argument('--token-file', type=Path, default=DEFAULT_TOKEN_FILE)
    args = parser.parse_args(argv)
    if args.init_token:
        try:
            create_token_file(args.token_file)
            print('Token file created:', args.token_file, '(contents not printed)')
            return 0
        except (OSError, ValueError) as exc:
            print('Cannot create token file:', type(exc).__name__, file=sys.stderr)
            return 2
    if not 1024 <= args.port <= 65535:
        parser.error('Port must be 1024..65535')
    if os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0 and not args.demo:
        parser.error('Run LIVE panel as unprivileged cybernova user, not root')
    try:
        token = 'demo' if args.demo else read_token(args.token_file)
        server = PanelServer(('127.0.0.1',args.port), token, Paths(), demo=args.demo,
                             enable_start=args.enable_start)
    except (OSError, ValueError) as exc:
        print('Panel startup failed:', type(exc).__name__, str(exc)[:120], file=sys.stderr)
        return 2
    print(f'Cybernova Panel v0.1 — http://127.0.0.1:{args.port}/')
    print('Mode:', 'DEMO (not real)' if args.demo else 'LIVE local only')
    print('Start local session:', 'enabled' if args.enable_start and not args.demo else 'disabled')
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())