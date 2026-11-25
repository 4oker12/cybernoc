"""30-second Git watcher, 24-hour session, stop-on-failure deployer.

Designed for a non-root service account. Updates only the approved Cybernova agent
subtree. No shell evaluation, no automatic rollback, no system package changes.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Callable, Protocol
from urllib import request

REPO = '4oker12/cybernoc'
URL = 'git@github.com:4oker12/cybernoc.git'
BRANCH = 'cybernova-autodeploy'
SOURCE = 'cybernova/v10'
SHA_RE = re.compile(r'^[0-9a-f]{40}$')
INTERVAL = 30
WINDOW = 24 * 60 * 60
FILE_LIMIT = 300
SINGLE_LIMIT = 2_000_000
TOTAL_LIMIT = 12_000_000


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def atomic_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix='.state-', delete=False) as fh:
        temp = Path(fh.name)
        json.dump(obj, fh, sort_keys=True, indent=2, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temp, path)
    os.chmod(path, 0o600)


@dataclass(frozen=True)
class Settings:
    work: Path
    active: Path
    deploy_key: Path
    known_hosts: Path
    github_issue_token_file: Path | None = None
    github_reporting: bool = False
    poll_seconds: int = INTERVAL
    window_seconds: int = WINDOW
    source: str = SOURCE
    repo: str = REPO
    branch: str = BRANCH
    git_url: str = URL
    test_timeout: int = 120

    def __post_init__(self) -> None:
        if (self.poll_seconds, self.window_seconds) != (30, 86400):
            raise ValueError('Mode locked to 30s polling and 24h window')
        if (self.repo, self.branch, self.git_url, self.source) != (REPO, BRANCH, URL, SOURCE):
            raise ValueError('Repository, branch and source must stay pinned')
        if self.work == self.active or self.work in self.active.parents or self.active in self.work.parents:
            raise ValueError('Work and active directories must be separate')
        if self.github_reporting and not self.github_issue_token_file:
            raise ValueError('GitHub Issues token file required for remote reporting')
        if self.test_timeout < 1 or self.test_timeout > 300:
            raise ValueError('Test timeout outside 1-300s')

    @classmethod
    def from_json(cls, config: Path) -> 'Settings':
        d = json.loads(config.read_text(encoding='utf-8'))
        allowed = {f.name for f in dataclasses.fields(cls)}
        if set(d) - allowed:
            raise ValueError('Unknown config settings: ' + ', '.join(sorted(set(d)-allowed)))
        for field in ('work', 'active', 'deploy_key', 'known_hosts', 'github_issue_token_file'):
            if d.get(field) is not None:
                d[field] = Path(d[field]).expanduser().absolute()
        for field in ('work','active','deploy_key','known_hosts'):
            if field not in d:
                raise ValueError('Missing config field ' + field)
        return cls(**d)


class GitBackend:
    """Read-only Git client with a single approved SSH remote, no shell expansion."""
    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.repo = cfg.work / 'git-cache'

    def _environment(self) -> dict:
        if not self.cfg.deploy_key.is_file() or not self.cfg.known_hosts.is_file():
            raise RuntimeError('SSH deploy key or verified known_hosts not provisioned')
        if self.cfg.deploy_key.stat().st_mode & 0o077:
            raise RuntimeError('Deploy key must not be readable by group/others')
        env = {k: os.environ[k] for k in ('HOME','PATH','LANG','LC_ALL') if k in os.environ}
        # Paths are configured locally by the operator, never by Qwen or Git content.
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                   GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0',
                   GIT_SSH_COMMAND=(f'ssh -F /dev/null -i {shlex.quote(str(self.cfg.deploy_key))} '
                                    f'-o IdentitiesOnly=yes -o BatchMode=yes '
                                    f'-o StrictHostKeyChecking=yes '
                                    f'-o UserKnownHostsFile={shlex.quote(str(self.cfg.known_hosts))}'))
        return env

    def _git(self, args: list[str], cwd: Path, timeout: int = 30, binary: bool = False):
        p = subprocess.run(['git', *args], cwd=str(cwd), env=self._environment(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False, stdin=subprocess.DEVNULL)
        if p.returncode:
            raise RuntimeError(f'git command failed: exit={p.returncode} (remote/auth/network)')
        return p.stdout if binary else p.stdout.decode('utf-8', 'replace').strip()

    def head(self) -> str:
        out = self._git(['ls-remote', '--exit-code', URL, 'refs/heads/'+BRANCH], self.cfg.work)
        sha = out.split('\t', 1)[0] if '\t' in out else ''
        if not SHA_RE.fullmatch(sha):
            raise RuntimeError('Invalid remote HEAD')
        return sha

    def fetch(self, expected: str) -> None:
        if not SHA_RE.fullmatch(expected):
            raise ValueError('Invalid commit hash')
        if not (self.repo / 'HEAD').is_file():
            if self.repo.exists():
                raise ValueError('Git cache path is not a bare repository')
            self.repo.mkdir(mode=0o700)
            self._git(['init','--bare','--quiet'], self.repo)
            self._git(['remote','add','origin',URL], self.repo)
        if self._git(['remote','get-url','origin'], self.repo) != URL:
            raise RuntimeError('Git origin changed unexpectedly')
        self._git(['fetch', '--no-tags', '--depth=100', 'origin',
                   f'+refs/heads/{BRANCH}:refs/remotes/origin/{BRANCH}'], self.repo, timeout=90)
        actual = self._git(['rev-parse', f'refs/remotes/origin/{BRANCH}'], self.repo)
        if actual != expected:
            raise RuntimeError('Remote HEAD changed during fetch; stopped for consistency')

    def is_descendant(self, older: str, newer: str) -> bool:
        if not SHA_RE.fullmatch(older) or not SHA_RE.fullmatch(newer):
            raise ValueError('Invalid commit hash')
        p = subprocess.run(['git', 'merge-base', '--is-ancestor', older, newer],
                           cwd=str(self.repo), env=self._environment(),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, timeout=15, check=False)
        if p.returncode == 0:
            return True
        if p.returncode == 1:
            return False
        raise RuntimeError('Unable to verify branch ancestry')

    def tree(self, sha: str) -> str:
        if not SHA_RE.fullmatch(sha):
            raise ValueError('Invalid commit hash')
        tree = self._git(['rev-parse', f'{sha}:{SOURCE}'], self.repo)
        if not SHA_RE.fullmatch(tree):
            raise RuntimeError('Invalid source tree hash')
        return tree

    def materialize(self, sha: str, destination: Path) -> None:
        if not SHA_RE.fullmatch(sha):
            raise ValueError('Invalid commit hash')
        if destination.exists() or destination.is_symlink():
            raise ValueError('Staging destination already exists')
        destination.mkdir(mode=0o700, parents=True)
        # Git archive prevents .git/hooks and checked out submodules running.
        blob = self._git(['archive', '--format=tar', sha, SOURCE], self.repo,
                         timeout=30, binary=True)
        if len(blob) > TOTAL_LIMIT:
            raise ValueError('Archive too large')
        prefix = SOURCE + '/'
        count, total = 0, 0
        with tarfile.open(fileobj=BytesIO(blob), mode='r:') as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError('Archive contains unsupported link/device')
                if not member.name.startswith(prefix):
                    raise ValueError('Unexpected archive path')
                relative = member.name[len(prefix):]
                path = PurePosixPath(relative)
                if not relative or path.is_absolute() or '..' in path.parts:
                    raise ValueError('Unsafe archive member path')
                count += 1
                total += member.size
                if count > FILE_LIMIT or member.size > SINGLE_LIMIT or total > TOTAL_LIMIT:
                    raise ValueError('Source size limits exceeded')
                # MCP server integration files must never be promoted by the agent updater.
                if path.parts[0] not in ('cybernova_agent','tests') and relative not in ('agent.py','README_RU.md','cybernova_agent_observability.py'):
                    continue
                if not (relative.endswith(('.py','.md','.txt','.json','.toml','.yaml','.yml'))):
                    raise ValueError('Unexpected executable/binary file in source')
                dest = destination / path.as_posix()
                if not dest.resolve().is_relative_to(destination.resolve()):
                    raise ValueError('Archive escapes staging root')
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(member) as contents, dest.open('xb') as writer:
                    shutil.copyfileobj(contents, writer)
                dest.chmod(0o600)
        if not (destination / 'agent.py').is_file() or not (destination / 'tests').is_dir():
            raise RuntimeError('Agent entrypoint and tests are required')


def _test_preexec() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (130, 130))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10_000_000, 10_000_000))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Deployer:
    def __init__(self, cfg: Settings):
        self.cfg = cfg

    def _test(self, path: Path) -> str:
        # Test code is still code; dedicated unprivileged service account is essential.
        env = {'HOME': str(self.cfg.work), 'PATH': os.environ.get('PATH','/usr/bin:/bin'),
               'LANG': 'C.UTF-8', 'PYTHONPATH': str(path),
               'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
        p = subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-v'],
                           cwd=path, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, stdin=subprocess.DEVNULL,
                           timeout=self.cfg.test_timeout, check=False, preexec_fn=_test_preexec)
        result = p.stdout[-9000:]
        if p.returncode:
            raise RuntimeError(f'Agent tests failed: exit={p.returncode}\n{result[-5500:]}')
        return result

    def _check_idle(self) -> None:
        jobs = self.cfg.work / 'data' / 'jobs'
        if not jobs.exists():
            return
        for p in jobs.glob('*/state.json'):
            try:
                s = json.loads(p.read_text(encoding='utf-8'))
                if s.get('status') in ('queued','running'):
                    pid = s.get('pid')
                    if isinstance(pid, int) and pid > 1:
                        try:
                            os.kill(pid, 0)
                            raise RuntimeError('Agent has active jobs; deployment blocked')
                        except ProcessLookupError:
                            continue
                        except PermissionError:
                            raise RuntimeError('Active agent job ownership unknown; deployment blocked')
            except (ValueError, json.JSONDecodeError):
                continue

    def _verify_managed_link(self) -> Path:
        """Root provisions this link once; later we only change an owned pointer."""
        pointer = self.cfg.work / 'current'
        if not self.cfg.active.is_symlink():
            raise RuntimeError('Agent not enrolled: active must be symlink to managed current pointer')
        if os.readlink(self.cfg.active) != str(pointer):
            raise RuntimeError('Agent symlink points outside managed deployment')
        if pointer.exists() and not pointer.is_symlink():
            raise RuntimeError('Managed pointer must be symlink')
        if pointer.is_symlink():
            target = pointer.resolve()
            if not target.is_relative_to(self.cfg.work.resolve()):
                raise RuntimeError('Managed current pointer escapes updater work area')
            if not target.is_dir():
                raise RuntimeError('Managed current target is not a directory')
        return pointer

    def verify_existing(self) -> str:
        self._verify_managed_link()
        return self._test(self.cfg.active)

    def apply(self, sha: str, tree: str, repo: GitBackend) -> dict:
        self._check_idle()
        pointer = self._verify_managed_link()
        releases = self.cfg.work / 'releases'
        releases.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage = releases / (sha + '.staging')
        release = releases / sha
        if stage.exists() or stage.is_symlink() or release.exists() or release.is_symlink():
            raise RuntimeError('Release/staging already exists; inspect prior attempt')
        repo.materialize(sha, stage)
        before = self._test(stage)
        # Durable state lives outside release directories; installed agent expects BASE/jobs.
        data_root = self.cfg.work / 'data'
        for persistent in ('jobs', 'operations', 'history'):
            location = data_root / persistent
            if not location.is_dir() or location.is_symlink():
                raise RuntimeError(f'Persistent state directory missing: {persistent}')
            (stage / persistent).symlink_to(location, target_is_directory=True)
        marker = {'commit':sha,'tree':tree,'installed_at':utc(time.time())}
        atomic_json(stage/'.cybernova-release.json', marker)
        os.replace(stage, release)
        previous = str(pointer.resolve()) if pointer.is_symlink() else None
        next_pointer = self.cfg.work / '.current.next'
        if next_pointer.exists() or next_pointer.is_symlink():
            raise RuntimeError('Pending deployment pointer exists; manual review required')
        try:
            os.symlink(release, next_pointer)
            os.replace(next_pointer, pointer)
        except BaseException:
            if next_pointer.is_symlink():
                next_pointer.unlink()
            raise
        # No rollback on failed post-test: stop and report, preserving evidence.
        after = self._test(self.cfg.active)
        return {'commit':sha,'source_tree':tree,'previous_release':previous,
                'active_release':str(release),'pretest_tail':before[-1800:],
                'posttest_tail':after[-1800:]}


class Reporter:
    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.dir = cfg.work / 'reports'

    @staticmethod
    def sanitize(value: str) -> str:
        # Best-effort log masking. Never intentionally collect full environment dumps.
        value = re.sub(r'(?i)(authorization\s*:\s*bearer\s+)\S+',
                       r'\1[REDACTED]', value)
        value = re.sub(r'(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*\S+',
                       r'\1=[REDACTED]', value)
        value = re.sub(r'gh[pousr]_[a-zA-Z0-9_]{20,}', '[REDACTED]', value)
        value = re.sub(r'sk-(?:proj-)?[a-zA-Z0-9_-]{10,}', 'sk-[REDACTED]', value)
        value = re.sub(r'hf_[A-Za-z0-9]{15,}', 'hf_[REDACTED]', value)
        value = re.sub(r'-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----.*?'
                       r'-----END (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----',
                       '[PRIVATE KEY REDACTED]', value, flags=re.S)
        return value[:6000]

    def publish(self, report: dict) -> dict:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        safe = dict(report)
        safe['detail'] = self.sanitize(str(report.get('detail','')))
        filename = f"{int(report['timestamp'])}-{report['commit'][:12]}-{report['status']}.json"
        path = self.dir / filename
        atomic_json(path, safe)
        result = {'local_report':str(path),'github_issue':None}
        if not self.cfg.github_reporting:
            return result
        token_file = self.cfg.github_issue_token_file
        if not token_file or not token_file.is_file():
            raise RuntimeError(f'Local report saved; GitHub Issues token file missing: {path}')
        if token_file.stat().st_mode & 0o077:
            raise RuntimeError(f'Local report saved; token file permissions must be 0600: {path}')
        token = token_file.read_text(encoding='utf-8').strip()
        if not token:
            raise RuntimeError(f'Local report saved; GitHub Issues token file empty: {path}')
        title = f"[Cybernova] {report['status'].upper()} {report['commit'][:12]}"
        body = (f"Commit: `{report['commit']}`\n\n"
                f"Status: **{report['status'].upper()}**\n\n"
                f"Time: {utc(report['timestamp'])}\n\n"
                f"Details:\n```text\n{safe['detail']}\n```\n")
        req = request.Request(f'https://api.github.com/repos/{REPO}/issues',
                              data=json.dumps({'title':title,'body':body}).encode('utf-8'),
                              headers={'Authorization':f'Bearer {token}',
                                       'Accept':'application/vnd.github+json',
                                       'X-GitHub-Api-Version':'2022-11-28',
                                       'User-Agent':'Cybernova-Vast-Updater/1.1'},method='POST')
        try:
            with request.urlopen(req, timeout=12) as response:
                data = json.loads(response.read(20000))
                result['github_issue'] = data.get('html_url')
        except Exception as exc:
            raise RuntimeError(f'Local report saved but GitHub issue was not created: {type(exc).__name__}: {path}') from None
        return result


class Watcher:
    """Pure-ish one-tick state machine; fake Git, deploy and reporter are testable."""
    def __init__(self, cfg: Settings, git=None, deployer=None, reporter=None,
                 clock: Callable[[],float] = time.time):
        self.cfg=cfg
        cfg.work.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.git=git if git is not None else GitBackend(cfg)
        self.deployer=deployer if deployer is not None else Deployer(cfg)
        self.reporter=reporter if reporter is not None else Reporter(cfg)
        self.clock=clock
        self.statefile=cfg.work/'state.json'
        self.state = json.loads(self.statefile.read_text(encoding='utf-8')) if self.statefile.is_file() else {
            'status':'waiting','baseline_commit':None,'baseline_tree':None,
            'last_seen_commit':None,'deployed_commit':None,'deployed_tree':None,
            'started_at':None,'expires_at':None,'last_poll_at':None,
            'last_report':None,'error':None,
        }

    def _save(self) -> None:
        atomic_json(self.statefile,self.state)

    def _report(self, sha: str, status: str, detail: str, now: float) -> None:
        obj = {'version':1,'commit':sha,'status':status,'detail':detail,'timestamp':now,
               'window_started_at':self.state.get('started_at'),
               'window_expires_at':self.state.get('expires_at')}
        # Always write local report before trying remote GitHub Issues.
        published = self.reporter.publish(obj)
        self.state['last_report']=published
        self._save()

    def tick(self) -> dict:
        now=self.clock()
        if self.state['status'] in ('stopped_error','stopped_window'):
            return dict(self.state)
        expires=self.state.get('expires_at')
        if expires is not None and now >= expires:
            self.state.update(status='stopped_window',last_poll_at=now)
            self._save()
            return dict(self.state)
        sha = None
        try:
            sha=self.git.head()
            if not SHA_RE.fullmatch(sha):
                raise RuntimeError('Invalid Git HEAD')
            if self.state['baseline_commit'] is None:
                self.git.fetch(sha)
                tree=self.git.tree(sha)
                self.state.update(baseline_commit=sha,baseline_tree=tree,
                                  last_seen_commit=sha,last_poll_at=now)
                self._save()
                return dict(self.state)
            if sha == self.state['last_seen_commit']:
                self.state['last_poll_at']=now
                self._save()
                return dict(self.state)
            self.git.fetch(sha)
            if not self.git.is_descendant(self.state['last_seen_commit'], sha):
                raise RuntimeError('Non-fast-forward Git history detected; deployment stopped')
            tree=self.git.tree(sha)
            self.state.update(last_poll_at=now)
            if tree == (self.state.get('deployed_tree') or self.state['baseline_tree']):
                # Non-agent commit: do not start the 24-hour session.
                self.state['last_seen_commit']=sha
                self._save()
                return dict(self.state)
            if self.state['started_at'] is None:
                self.state.update(started_at=now,expires_at=now+WINDOW,status='active')
                self._save()
            # Do not redo a deployment after a crash between installation and state commit.
            marker = self.cfg.active / '.cybernova-release.json'
            if marker.is_file():
                installed = json.loads(marker.read_text(encoding='utf-8'))
                if installed.get('commit')==sha and installed.get('tree')==tree:
                    verified=self.deployer.verify_existing()
                    deployment={'commit':sha,'source_tree':tree,'recovered_from_marker':True,
                                'posttest_tail':verified[-1800:]}
                else:
                    deployment=self.deployer.apply(sha,tree,self.git)
            else:
                deployment=self.deployer.apply(sha,tree,self.git)
            self.state.update(status='active',deployed_commit=sha,deployed_tree=tree,
                              last_seen_commit=sha,error=None)
            self._save()
            self._report(sha,'success',json.dumps(deployment,ensure_ascii=False),now)
        except Exception as exc:
            detail=self.reporter.sanitize(f'{type(exc).__name__}: {exc}')
            self.state.update(status='stopped_error',error=detail,last_poll_at=now)
            self._save()
            try:
                self._report(sha if sha and SHA_RE.fullmatch(sha) else '0'*40,
                             'failed',detail,now)
            except Exception as post_exc:
                self.state['report_delivery_error']=type(post_exc).__name__
                self._save()
        return dict(self.state)

    def run(self, sleep: Callable[[float],None]=time.sleep) -> dict:
        while True:
            state=self.tick()
            if state['status'] in ('stopped_error','stopped_window'):
                return state
            sleep(self.cfg.poll_seconds)
