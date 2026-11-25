"""Cybernova MCP core diagnostics. Public tool schema unchanged from v0.4.

The existing ChatGPT connection exposes bridge_health and vast_diagnostic; to
avoid stale tool registration, the latter returns additional observability
fields for existing `workspace`/`ollama` presets. Fixed commands only.

Observability is dynamically loaded from disk on every request, so subsequent
read-only dashboard upgrades can be installed without a tunnel restart.
"""
from __future__ import annotations

import importlib.util
import platform
import subprocess
import sys
from pathlib import Path

TORCH_PYTHON = str(Path('/venv/main/bin/python')) if Path('/venv/main/bin/python').is_file() else sys.executable
PRESETS: dict[str, list[str]] = {
    'gpu': ['nvidia-smi', '--query-gpu=name,memory.total,memory.used,utilization.gpu,temperature.gpu,driver_version', '--format=csv,noheader'],
    'disk': ['df', '-h', '/'],
    'memory': ['free', '-h'],
    'python': [sys.executable, '--version'],
    'torch_cuda': [TORCH_PYTHON, '-c', 'import torch; print("torch:",torch.__version__); print("cuda:",torch.cuda.is_available()); print("gpu:",torch.cuda.get_device_name(0) if torch.cuda.is_available() else "none")'],
    'ollama': ['ollama', '--version'],
    'heretic': [TORCH_PYTHON, '-m', 'pip', 'show', 'heretic-llm'],
    'processes': ['ps', '-eo', 'pid,comm,%cpu,%mem', '--sort=-%cpu'],
    'workspace': ['ls', '-lah', '/workspace'],
}


def health() -> dict:
    return {
        'bridge': 'CyberSec Vast Bridge',
        'status': 'ready',
        'python': platform.python_version(),
        'tools': list(PRESETS),
        'observability': '0.6',
        'existing_schema_compatible': True,
    }


def _enhance(kind: str, out: dict) -> None:
    """Read-only dynamic extension: failure never breaks base diagnostics."""
    if kind not in ('workspace', 'ollama'):
        return
    path = Path(__file__).with_name('cybernova_observability.py')
    if not path.is_file():
        out['observability_warning'] = 'Cybernova extension unavailable'
        return
    try:
        spec = importlib.util.spec_from_file_location('_cybernova_observability_live', path)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        out.update(module.snapshot(kind))
    except Exception as exc:
        out['observability_warning'] = f'{type(exc).__name__}: {str(exc)[:180]}'


def run_diagnostic(kind: str) -> dict:
    if kind not in PRESETS:
        return {'ok': False, 'error': 'Unknown diagnostic. Allowed: ' + ', '.join(PRESETS)}
    try:
        r = subprocess.run(
            PRESETS[kind], shell=False, capture_output=True, text=True,
            errors='replace', timeout=45 if kind == 'torch_cuda' else 15,
            check=False,
        )
        content = ((r.stdout or '') + ('\n' + r.stderr if r.stderr else '')).strip()
        out = {
            'ok': r.returncode == 0,
            'kind': kind,
            'exit_code': r.returncode,
            'output': content[:6000],
            'truncated': len(content) > 6000,
        }
    except FileNotFoundError:
        out = {'ok': False, 'kind': kind, 'error': 'Executable not installed'}
    except subprocess.TimeoutExpired:
        out = {'ok': False, 'kind': kind, 'error': 'Diagnostic timeout'}
    _enhance(kind, out)
    return out
