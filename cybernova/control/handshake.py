#!/usr/bin/env python3
"""Single-purpose GitHub Issues echo responder for Cybernova Vast.

No remote command execution. No secrets printed. Fixed repository and protocol.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
from typing import Any
from urllib import request

REPO = '4oker12/cybernoc'
PROTOCOL = 'cybernova-handshake/v1'
SOURCE = 'vast-cybernova-controller'
VERSION = '1.2.0'
ID_RE = re.compile(r'^CN-HS-[0-9]{8}-[0-9]{2}$')
BASE = 'https://api.github.com/repos/' + REPO


class GitHubAPI:
    def __init__(self, token_file: Path):
        if token_file.is_symlink() or not token_file.is_file():
            raise RuntimeError('Issues token file missing or is symlink')
        if token_file.stat().st_mode & 0o077:
            raise RuntimeError('Issues token file must be private (mode 0600)')
        self._token = token_file.read_text(encoding='utf-8').strip()
        if not self._token:
            raise RuntimeError('Issues token file is empty')

    def call(self, path: str, method: str = 'GET', payload: dict | None = None) -> Any:
        # Only repository issue endpoints; URL/path never comes from GitHub content.
        if not re.fullmatch(r'/issues/[1-9][0-9]*(?:/comments)?', path):
            raise ValueError('Only issue and issue-comments paths allowed')
        if method not in ('GET', 'POST'):
            raise ValueError('Method not permitted')
        if method == 'POST' and not path.endswith('/comments'):
            raise ValueError('Only comments can be created')
        body = None if payload is None else json.dumps(payload).encode('utf-8')
        req = request.Request(BASE + path, method=method, data=body,
                              headers={'Authorization': 'Bearer ' + self._token,
                                       'Accept': 'application/vnd.github+json',
                                       'X-GitHub-Api-Version': '2022-11-28',
                                       'User-Agent': 'Cybernova-Vast-Echo/1.2'})
        try:
            with request.urlopen(req, timeout=15) as resp:
                # Bound the response size. Error messages never include authorization header.
                data = resp.read(100_001)
                if len(data) > 100_000:
                    raise RuntimeError('GitHub response too large')
                return json.loads(data)
        except Exception as exc:
            raise RuntimeError('GitHub Issues request failed: ' + type(exc).__name__) from None


def extract_response(body: str) -> dict | None:
    for m in re.finditer(r'```json\s*(\{.*?\})\s*```', body or '', re.S):
        try:
            d = json.loads(m.group(1))
        except (ValueError, TypeError):
            continue
        if d.get('protocol') == PROTOCOL and d.get('source') == SOURCE and d.get('status') == 'received':
            return d
    return None


def handshake(api: Any, issue_number: int, request_id: str) -> dict:
    if not ID_RE.fullmatch(request_id):
        raise ValueError('Malformed request ID')
    if not 1 <= issue_number <= 10000:
        raise ValueError('Issue number outside allowed range')
    issue = api.call(f'/issues/{issue_number}')
    if (issue.get('state') != 'open' or issue.get('user', {}).get('login') != '4oker12'
            or request_id not in issue.get('title', '')
            or f'`{request_id}`' not in issue.get('body', '')
            or f'`{PROTOCOL}`' not in issue.get('body', '')
            or '**Тип:** `echo`' not in issue.get('body', '')):
        return {'status': 'ignored', 'request_id': request_id, 'reason': 'not a trusted echo request'}
    comments = api.call(f'/issues/{issue_number}/comments')
    if not isinstance(comments, list):
        raise RuntimeError('Unexpected comments format')
    for entry in comments:
        response = extract_response(entry.get('body', ''))
        if response is not None and response.get('request_id') == request_id:
            return {'status': 'already_answered', 'request_id': request_id,
                    'comment_url': entry.get('html_url')}
    response = {
        'protocol': PROTOCOL,
        'request_id': request_id,
        'source': SOURCE,
        'status': 'received',
        'controller_version': VERSION,
        'agent_version': 'not-probed',
        'received_at_utc': datetime.now(timezone.utc).isoformat(),
        'message': 'PING received; GitHub round trip OK',
    }
    # The stable request_id and the format make at-least-once calls deduplicatable.
    comment = ('Cybernova Vast controller response (echo only):\n\n'
               '```json\n' + json.dumps(response, ensure_ascii=False, indent=2) + '\n```')
    result = api.call(f'/issues/{issue_number}/comments', 'POST', {'body': comment})
    return {'status': 'sent', 'request_id': request_id,
            'comment_url': result.get('html_url')}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Cybernova Vast Github Issue echo handshake')
    parser.add_argument('--token-file', type=Path, default=Path('/workspace/cybernova-updater/secrets/github-issues-token'))
    parser.add_argument('--issue', type=int, default=1)
    parser.add_argument('--request-id', default='CN-HS-20261117-01')
    args = parser.parse_args(argv)
    try:
        report = handshake(GitHubAPI(args.token_file), args.issue, args.request_id)
    except (RuntimeError, ValueError) as exc:
        report = {'status': 'failed', 'error': str(exc)}
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['status'] in ('sent', 'already_answered') else 2


if __name__ == '__main__':
    raise SystemExit(main())