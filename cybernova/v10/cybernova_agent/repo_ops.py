"""Bounded Git and Python CLI installer for the Cybernova local agent.

Qwen chooses *which approved operation*; Python enforces the operation's scope.
Never an arbitrary shell, arbitrary Git URL, pip package or system apt command.
Run the worker as a non-root service user. Git source is staged, never executed.
"""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import re
from .common import BASE

REPOSITORY = 'https://github.com/4oker12/cybernoc.git'
BRANCH = 'cybernova-autodeploy'
OPS_HOME = BASE / 'operations'
DIR = 'github-src'
INSTALLABLE = {
    'ruff': '0.14.6',
    'pytest': '9.0.1',
    'httpx': '0.28.1',
    'rich': '14.2.0',
}


def _env() -> dict:
    # Keep only basics; do not leak the model agent's env into git/pip processes.
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR') if k in os.environ}
    env.update(GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1',
               GIT_OPTIONAL_LOCKS='0', PIP_NO_INPUT='1',
               PYTHONNOUSERSITE='1', PIP_DISABLE_PIP_VERSION_CHECK='1')
    return env


def _run(argv: list[str], cwd: Path, timeout=45) -> str:
    p = subprocess.run(argv, cwd=str(cwd), env=_env(), shell=False,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=timeout, check=False)
    if p.returncode != 0:
        # Avoid leaking credential helpers or private remote diagnostics to logs.
        raise RuntimeError(f'{Path(argv[0]).name} exited {p.returncode}; inspect configured Git access or package availability')
    return p.stdout[:3000].strip()


def _require_user() -> None:
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        raise PermissionError('Use a non-root cybernova service account for git/pip tools')


def _private_area(root: Path) -> Path:
    """Outside the workspace Qwen can edit with write_file."""
    if root.is_symlink() or not re.fullmatch(r'[a-z][a-z0-9_-]{0,39}', root.name):
        raise ValueError('Invalid project root')
    if OPS_HOME.is_symlink():
        raise ValueError('Operations home symlink forbidden')
    OPS_HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = OPS_HOME / root.name
    if directory.is_symlink():
        raise ValueError('Operations project symlink forbidden')
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory


def _checkout(root: Path) -> Path:
    area = _private_area(root)
    path = area / DIR
    if path.is_symlink():
        raise ValueError('Git checkout symlink forbidden')
    if not path.resolve().is_relative_to(area.resolve()):
        raise ValueError('Git checkout escapes operations root')
    return path

def _origin(path: Path) -> str:
    return _run(['git', '-C', str(path), 'remote', 'get-url', 'origin'], path)


def repo_status(root: Path) -> dict:
    try:
        path = _checkout(root)
        if not path.exists():
            return {'ok': True, 'cloned': False, 'repo': '4oker12/cybernoc', 'branch': BRANCH}
        if not (path / '.git').is_dir() or (path / '.git').is_symlink():
            raise ValueError('Not a regular isolated Git checkout')
        if _origin(path) != REPOSITORY:
            raise ValueError('Git origin does not match approved repository')
        commit = _run(['git', '-C', str(path), 'rev-parse', 'HEAD'], path)
        branch = _run(['git', '-C', str(path), 'symbolic-ref', '--short', 'HEAD'], path)
        dirty = bool(_run(['git', '-C', str(path), 'status', '--porcelain', '--untracked-files=no'], path))
        return {'ok': True, 'cloned': True, 'commit': commit, 'branch': branch,
                'dirty': dirty, 'repo': '4oker12/cybernoc'}
    except (ValueError, PermissionError, OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return {'ok': False, 'error': str(exc)[:250]}


def repo_sync(root: Path) -> dict:
    """Fetch only the operator-owned branch, refusing local changes and rewind."""
    try:
        _require_user()
        path = _checkout(root)
        if not path.exists():
            with tempfile.TemporaryDirectory(prefix='.cybernova-git-', dir=path.parent) as temp:
                dest = Path(temp) / 'checkout'
                _run(['git', '-c', 'core.hooksPath=/dev/null', 'clone', '--depth', '20',
                      '--single-branch', '--branch', BRANCH, '--', REPOSITORY, str(dest)], path.parent, 90)
                if _origin(dest) != REPOSITORY:
                    raise ValueError('Unexpected Git origin')
                if _run(['git', '-C', str(dest), 'symbolic-ref', '--short', 'HEAD'], dest) != BRANCH:
                    raise ValueError('Unexpected Git branch')
                os.replace(dest, path)
        else:
            current = repo_status(root)
            if not current.get('ok') or not current.get('cloned') or current.get('dirty'):
                raise ValueError('Repository untrusted or modified; refusing update')
            if current['branch'] != BRANCH:
                raise ValueError('Unexpected Git branch')
            _run(['git', '-C', str(path), '-c', 'core.hooksPath=/dev/null', 'fetch',
                  '--no-tags', '--depth', '100', 'origin', f'refs/heads/{BRANCH}'], path, 90)
            _run(['git', '-C', str(path), '-c', 'core.hooksPath=/dev/null', 'merge',
                  '--ff-only', 'FETCH_HEAD'], path, 30)
        state = repo_status(root)
        if state.get('ok'):
            state['download_only'] = True
            state['executed_remote_code'] = False
        return state
    except (ValueError, PermissionError, OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return {'ok': False, 'error': str(exc)[:260]}


def install_python_tool(root: Path, name: str) -> dict:
    """Install an explicitly approved pinned Python CLI into a *project* venv."""
    try:
        _require_user()
        if name not in INSTALLABLE:
            return {'ok': False, 'error': 'Tool not on approved installation list',
                    'allowed': sorted(INSTALLABLE)}
        if root.is_symlink():
            raise ValueError('Symlink project root forbidden')
        venv = _private_area(root) / '_tools_venv'
        if venv.is_symlink():
            raise ValueError('Virtual environment symlink forbidden')
        py = venv / 'bin' / 'python'
        if not py.is_file():
            import sys
            _run([sys.executable, '-m', 'venv', str(venv)], root, 60)
        spec = name + '==' + INSTALLABLE[name]
        _run([str(py), '-m', 'pip', 'install', '--only-binary=:all:',
              '--no-input', '--disable-pip-version-check', spec], root, 150)
        meta = _run([str(py), '-m', 'pip', 'show', name], root, 15)
        if f'Version: {INSTALLABLE[name]}' not in meta:
            raise RuntimeError('Installed version verification failed')
        return {'ok': True, 'tool': name, 'version': INSTALLABLE[name],
                'environment': 'operations/<project>/_tools_venv', 'scope': 'project_only',
                'verified': True}
    except (ValueError, PermissionError, OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return {'ok': False, 'error': str(exc)[:260]}


def execute_repo_tool(root: Path, name: str, args: dict) -> dict:
    if not isinstance(args, dict):
        return {'ok': False, 'error': 'Tool arguments must be an object'}
    if name == 'repo_status' and not args:
        return repo_status(root)
    if name == 'repo_sync' and not args:
        return repo_sync(root)
    if name == 'install_python_tool':
        return install_python_tool(root, args.get('name', ''))
    return {'ok': False, 'error': 'Unknown or invalid repository operation'}
