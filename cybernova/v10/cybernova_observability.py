"""Read-only Cybernova status for existing vast_diagnostic MCP tool.

No arbitrary paths, no arbitrary commands, no outbound traffic. The only HTTP
requests target the fixed local Ollama endpoint. Logs are untrusted data.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

VERSION = '0.6'
MAX_TAIL = 12000
JOB_NAME = re.compile(r'^[a-f0-9]{16}$')
MODEL = 'brianmatzelle/qwen3-coder-heretic:30b'


def _redact(text: str) -> str:
    """Best-effort only: do not print actual credentials into logs."""
    patterns = [
        (r'sk-(?:proj-)?[a-zA-Z0-9_-]{10,}', 'sk-[REDACTED]'),
        (r'hf_[A-Za-z0-9]{15,}', 'hf_[REDACTED]'),
        (r'(?i)(Authorization\s*:\s*Bearer\s+)\S+', r'\1[REDACTED]'),
        (r'(?i)((?:api[_-]?key|access[_-]?token|password|secret)\s*[=:]\s*)[^\s,;]+', r'\1[REDACTED]'),
    ]
    for pattern, substitute in patterns:
        text = re.sub(pattern, substitute, text)
    return text


def _job_root() -> Path:
    """Known job directory; env override exists only for isolated tests."""
    return Path(os.environ.get('CYBERSEC_JOBS', '/workspace/cybersec-vast-jobs'))


def _read_job(job_dir: Path) -> dict | None:
    if not JOB_NAME.fullmatch(job_dir.name) or job_dir.is_symlink() or not job_dir.is_dir():
        return None
    meta = job_dir / 'state.json'
    if not meta.is_file() or meta.is_symlink():
        return None
    try:
        raw = meta.read_bytes()[:18000]
        state = json.loads(raw.decode('utf-8'))
        if not isinstance(state, dict):
            return None
        # Read only fields we explicitly expose, not arbitrary future metadata.
        return {
            'job_id': job_dir.name,
            'workflow': str(state.get('workflow', ''))[:100],
            'status': str(state.get('status', 'unknown'))[:40],
            'step': str(state.get('step', ''))[:100],
            'updated_at': str(state.get('updated_at', ''))[:64],
            'error': _redact(str(state.get('error') or ''))[:700],
            'warning': _redact(str(state.get('warning') or ''))[:300],
            'pid': state.get('pid') if isinstance(state.get('pid'), int) else None,
        }
    except (OSError, ValueError, UnicodeError, TypeError):
        return None


def _tail_log(job_dir: Path, limit: int = MAX_TAIL) -> tuple[str, bool]:
    file = job_dir / 'output.log'
    if not file.is_file() or file.is_symlink():
        return '(log not written yet)', False
    try:
        with file.open('rb') as handle:
            handle.seek(0, 2)
            total = handle.tell()
            offset = max(0, total - 50000)
            handle.seek(offset)
            block = handle.read(50000)
        output = block.decode('utf-8', errors='replace')
        # If reading tail of a larger log, discard first partial line.
        if offset and '\n' in output:
            output = output.split('\n', 1)[1]
        output = _redact(output)
        return output[-limit:], total > limit
    except OSError as exc:
        return f'(log read failed: {type(exc).__name__})', False


def _jobs_snapshot() -> dict:
    root = _job_root()
    if not root.exists():
        return {'job_found': False, 'job_message': 'No Cybernova jobs on disk'}
    candidates = []
    try:
        for path in root.iterdir():
            item = _read_job(path)
            if item:
                candidates.append((item, path))
    except OSError as exc:
        return {'job_found': False, 'job_message': f'Job directory unreadable: {type(exc).__name__}'}
    if not candidates:
        return {'job_found': False, 'job_message': 'No valid job records'}
    candidates.sort(key=lambda item: item[0]['updated_at'], reverse=True)
    # A running job should take priority over an unrelated completed job.
    active = [pair for pair in candidates if pair[0]['status'] in ('running', 'queued')]
    latest, folder = (active or candidates)[0]
    log, truncated = _tail_log(folder)
    alive = None
    if latest['status'] in ('running', 'queued') and isinstance(latest.get('pid'), int) and latest['pid'] > 1:
        try:
            os.kill(latest['pid'], 0)
            alive = True
        except ProcessLookupError:
            alive = False
        except PermissionError:
            alive = True
    attention = 'worker_process_missing' if alive is False else ('job_failed' if latest['status'] == 'failed' else None)
    return {
        'job_found': True,
        'job_id': latest['job_id'],
        'job_workflow': latest['workflow'],
        'job_status': latest['status'],
        'job_step': latest['step'],
        'job_updated_at': latest['updated_at'],
        'job_error': latest['error'],
        'job_warning': latest['warning'],
        'job_log_tail': log,
        'job_log_truncated': truncated,
        'recent_jobs': [dict(item) for item, _ in candidates[:8]],
        'job_count': len(candidates),
        'job_worker_alive': alive,
        'job_attention': attention,
    }


def _ollama_api(path: str) -> dict | None:
    req = urllib.request.Request('http://127.0.0.1:11434' + path, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=2.5) as r:
            data = r.read(262144)
        payload = json.loads(data)
        return payload if isinstance(payload, dict) else None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def _ollama_snapshot() -> dict:
    tags = _ollama_api('/api/tags')
    running = _ollama_api('/api/ps')
    installed = []
    for item in (tags or {}).get('models', [])[:30]:
        if isinstance(item, dict):
            installed.append({'name': str(item.get('name', ''))[:140], 'size_bytes': item.get('size', 0)})
    loaded = []
    for item in (running or {}).get('models', [])[:10]:
        if isinstance(item, dict):
            loaded.append({'name': str(item.get('name', ''))[:140], 'size_vram': item.get('size_vram', None)})
    return {
        'ollama_api_reachable': tags is not None,
        'ollama_models_installed': installed,
        'ollama_models_loaded': loaded,
        'target_model': MODEL,
        'target_model_installed': any(item['name'] == MODEL for item in installed),
    }


def _tmux_snapshot() -> dict:
    if not shutil.which('tmux'):
        return {'terminal_available': False, 'terminal_reason': 'tmux executable absent'}
    try:
        present = subprocess.run(['tmux', '-L', 'cybersec-mcp', 'has-session', '-t', 'work'],
                                 capture_output=True, text=True, timeout=3)
        if present.returncode != 0:
            return {'terminal_available': False, 'terminal_reason': 'work session not found'}
        r = subprocess.run(['tmux', '-L', 'cybersec-mcp', 'capture-pane', '-p', '-J', '-t', 'work:0.0', '-S', '-140'],
                           capture_output=True, text=True, errors='replace', timeout=5)
        if r.returncode != 0:
            return {'terminal_available': False, 'terminal_reason': 'capture failed'}
        output = _redact(r.stdout)
        return {'terminal_available': True, 'terminal_log_tail': output[-4500:], 'terminal_log_truncated': len(output) > 4500}
    except (OSError, subprocess.TimeoutExpired):
        return {'terminal_available': False, 'terminal_reason': 'capture unavailable'}


def snapshot(kind: str) -> dict:
    if kind == 'ollama':
        return _ollama_snapshot()
    if kind == 'workspace':
        result = {'observability_version': VERSION}
        result.update(_jobs_snapshot())
        result.update(_tmux_snapshot())
        result.update(_ollama_snapshot())
        try:
            from cybernova_agent_observability import snapshot as agent_snapshot
            result.update(agent_snapshot())
        except (ImportError, OSError, ValueError) as exc:
            result["agent_observability_error"] = type(exc).__name__
        return result
    return {}
