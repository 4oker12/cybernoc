"""Deterministic workflow + real isolated Git/release integration tests."""
from __future__ import annotations
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cybernova_updater import core

SHA_A = 'a'*40
SHA_B = 'b'*40
SHA_C = 'c'*40
TREE_1 = '1'*40
TREE_2 = '2'*40
TREE_3 = '3'*40


def git(*argv, cwd=None):
    return subprocess.check_output(['git', *argv], cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


class FakeGit:
    def __init__(self):
        self.sha = SHA_A
        self.trees = {SHA_A:TREE_1,SHA_B:TREE_2,SHA_C:TREE_3}
        self.seen = []
    def head(self): return self.sha
    def fetch(self, sha): self.seen.append(sha)
    def tree(self, sha): return self.trees[sha]
    def is_descendant(self, old, new): return True
    def materialize(self, sha, destination):
        destination.mkdir(parents=True)
        (destination/'agent.py').write_text('print("hi")\n')
        (destination/'tests').mkdir()
        (destination/'tests'/'test_a.py').write_text('import unittest\nclass T(unittest.TestCase):\n def test_a(self): self.assertTrue(True)\n')


class BadGit(FakeGit):
    def materialize(self, sha, destination):
        super().materialize(sha, destination)
        (destination/'tests'/'test_a.py').write_text('import unittest\nclass T(unittest.TestCase):\n def test_a(self): self.fail("test intentionally failed")\n')


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.work = root/'work'
        self.work.mkdir()
        for n in ('jobs','operations'):(self.work/'data'/n).mkdir(parents=True)
        self.active = root/'agent'
        self.legacy = self.work/'legacy'
        self.legacy.mkdir()
        os.symlink(self.legacy,self.work/'current')
        os.symlink(self.work/'current',self.active)
        self.cfg = core.Settings(self.work,self.active,root/'id',root/'known')
        self.git = FakeGit()
        self.time = 1000.
        self.w = core.Watcher(self.cfg, git=self.git,clock=lambda:self.time)

    def test_baseline_does_not_start_window(self):
        state=self.w.tick()
        self.assertEqual(state['status'],'waiting')
        self.assertIsNone(state['expires_at'])
        self.assertEqual(state['baseline_commit'], SHA_A)
        self.assertEqual(self.git.seen,[SHA_A])

    def test_non_code_commit_does_not_start_session(self):
        self.w.tick()
        self.git.sha = SHA_B
        self.git.trees[SHA_B] = TREE_1
        state=self.w.tick()
        self.assertIsNone(state['started_at'])
        self.assertEqual(state['last_seen_commit'], SHA_B)

    def test_first_real_commit_starts_24h_session_and_applies(self):
        self.w.tick()
        self.time=1300
        self.git.sha = SHA_B
        result=self.w.tick()
        self.assertEqual(result['status'],'active')
        self.assertEqual(result['started_at'],1300)
        self.assertEqual(result['expires_at'], 1300+86400)
        self.assertEqual(result['deployed_commit'], SHA_B)
        self.assertEqual(json.loads((self.active/'.cybernova-release.json').read_text())['commit'],SHA_B)
        self.assertTrue(any(self.work.joinpath('reports').glob('*success.json')))

    def test_next_commit_new_release_before_deadline(self):
        self.test_first_real_commit_starts_24h_session_and_applies()
        self.time=2000
        self.git.sha=SHA_C
        state=self.w.tick()
        self.assertEqual(state['deployed_commit'],SHA_C)
        self.assertEqual(state['expires_at'],1300+86400)
        self.assertTrue((self.work/'releases'/SHA_B).is_dir())
        self.assertEqual(len(list((self.work/'reports').glob('*success.json'))),2)

    def test_exact_24h_deadline_stops_without_git_call(self):
        self.test_first_real_commit_starts_24h_session_and_applies()
        self.time=1300+86400
        self.git.sha=SHA_C
        state=self.w.tick()
        self.assertEqual(state['status'],'stopped_window')
        self.assertEqual(state['deployed_commit'],SHA_B)
        self.assertEqual(self.git.seen,[SHA_A,SHA_B])

    def test_test_failure_stops_and_reports(self):
        self.git=BadGit()
        self.w=core.Watcher(self.cfg,git=self.git,clock=lambda:self.time)
        self.w.tick()
        self.git.sha=SHA_B
        state=self.w.tick()
        self.assertEqual(state['status'],'stopped_error')
        self.assertIn('tests failed',state['error'])
        self.assertEqual((self.work/'current').resolve(),self.legacy)
        self.assertTrue(list((self.work/'reports').glob('*failed.json')))
        self.git.sha=SHA_C
        self.assertEqual(self.w.tick()['status'],'stopped_error')

    def test_network_failure_stops_once(self):
        self.git.head=lambda: (_ for _ in ()).throw(OSError('offline'))
        state=self.w.tick()
        self.assertEqual(state['status'],'stopped_error')
        self.assertIn('offline',state['error'])
        self.assertTrue(list((self.work/'reports').glob('*failed.json')))

    def test_state_survives_restart(self):
        self.w.tick()
        self.git.sha=SHA_B
        self.w.tick()
        second=core.Watcher(self.cfg,git=self.git,clock=lambda:9999.)
        self.assertEqual(second.tick()['deployed_commit'],SHA_B)
        self.assertEqual(len(list((self.work/'reports').glob('*success.json'))),1)

    def test_disallow_wrong_symlink(self):
        self.w.tick()
        (self.active).unlink()
        os.symlink('/tmp/incorrect',self.active)
        self.git.sha=SHA_B
        state=self.w.tick()
        self.assertEqual(state['status'],'stopped_error')
        self.assertIn('symlink',state['error'])

    def test_github_reporter_requires_0600_token(self):
        token=self.work/'token'
        token.write_text('secret')
        token.chmod(0o644)
        cfg=core.Settings(self.work,self.active,self.cfg.deploy_key,self.cfg.known_hosts,token,True)
        writer=core.Reporter(cfg)
        with self.assertRaisesRegex(RuntimeError,'permissions'):
            writer.publish({'timestamp':123,'commit':SHA_A,'status':'success','detail':'ok'})
        self.assertTrue(list((self.work/'reports').glob('*success.json')))

    def test_optional_issue_failure_stops_after_local_report(self):
        self.w.tick()
        self.git.sha=SHA_B
        self.w.reporter.publish=lambda r: (_ for _ in ()).throw(RuntimeError('issue rejected'))
        s=self.w.tick()
        self.assertEqual(s['status'],'stopped_error')
        self.assertEqual(s['report_delivery_error'],'RuntimeError')

    def test_read_only_status_is_not_execution(self):
        self.assertEqual(self.cfg.poll_seconds,30)
        self.assertEqual(self.cfg.window_seconds,86400)
        with self.assertRaises(ValueError):
            core.Settings(self.work,self.active,self.cfg.deploy_key,self.cfg.known_hosts,poll_seconds=15)
        with self.assertRaises(ValueError):
            core.Settings(self.work,self.active,self.cfg.deploy_key,self.cfg.known_hosts,branch='main')

    def test_local_report_sanitizes_obvious_secrets(self):
        self.assertNotIn('12345',core.Reporter.sanitize('token=12345'))
        self.assertNotIn('abcde',core.Reporter.sanitize('Authorization: Bearer abcde'))
        self.assertNotIn('secretBODY',core.Reporter.sanitize('-----BEGIN OPENSSH PRIVATE KEY-----\nsecretBODY\n-----END OPENSSH PRIVATE KEY-----'))

    def test_repeated_run_does_not_deploy(self):
        self.test_first_real_commit_starts_24h_session_and_applies()
        for i in range(5):self.w.tick()
        self.assertEqual(len(list((self.work/'reports').glob('*success.json'))),1)

    def test_bad_file_name_refused(self):
        with self.assertRaises(ValueError):
            self.cfg.__class__(self.work,self.active,self.cfg.deploy_key,self.cfg.known_hosts,source='../outside')


class GitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.bare=self.root/'remote.git'
        git('init','--bare','--initial-branch=cybernova-autodeploy',str(self.bare))
        self.seed=self.root/'seed'
        git('clone',str(self.bare),str(self.seed))
        git('config','user.name','Cybernova Test',cwd=self.seed)
        git('config','user.email','test@example.invalid',cwd=self.seed)
        self.package=self.seed/'cybernova'/'v10'
        self.package.mkdir(parents=True)
        (self.package/'agent.py').write_text('print("v1")\n')
        (self.package/'tests').mkdir()
        (self.package/'tests'/'test_a.py').write_text('import unittest\nclass T(unittest.TestCase):\n def test_a(self): self.assertTrue(True)\n')
        git('add','.',cwd=self.seed)
        git('commit','-m','first',cwd=self.seed)
        git('push','origin','HEAD:cybernova-autodeploy',cwd=self.seed)
        self.cfg=core.Settings(self.root/'work',self.root/'agent',self.root/'id',self.root/'known')
        self.cfg.work.mkdir()

    def test_git_clone_archive_and_test(self):
        gb=core.GitBackend(self.cfg)
        # Override approved remote for a strictly local isolated test only.
        with patch.object(core,'URL',str(self.bare)):
            with patch.object(gb,'_environment',return_value={'HOME':str(self.root),'PATH':os.environ.get('PATH','/usr/bin:/bin')}):
                head=gb.head()
                gb.fetch(head)
                tree=gb.tree(head)
                target=self.root/'stage'
                gb.materialize(head,target)
        self.assertTrue((target/'agent.py').exists())
        self.assertEqual(core.Deployer(self.cfg)._test(target).count('OK'),1)
        self.assertTrue(core.SHA_RE.fullmatch(tree))

    def test_tar_symlink_rejected(self):
        gb=core.GitBackend(self.cfg)
        content=BytesIO()
        with tarfile.open(fileobj=content,mode='w') as archive:
            link=tarfile.TarInfo('cybernova/v10/tests/escape.py')
            link.type=tarfile.SYMTYPE
            link.linkname='/etc/passwd'
            archive.addfile(link)
        with patch.object(gb,'_git',return_value=content.getvalue()):
            with self.assertRaisesRegex(ValueError,'unsupported link'):
                gb.materialize(SHA_A,self.root/'stage')


if __name__=='__main__': unittest.main()

class AdditionalTests(unittest.TestCase):
    def test_force_push_stops_and_reports(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);work=root/'work';work.mkdir()
            active=root/'agent'
            cfg=core.Settings(work,active,root/'id',root/'known')
            git=FakeGit()
            watcher=core.Watcher(cfg,git=git,clock=lambda:100)
            watcher.tick();git.sha=SHA_B
            git.is_descendant=lambda old,new:False
            out=watcher.tick()
            self.assertEqual(out['status'],'stopped_error')
            self.assertIn('Non-fast-forward',out['error'])
            self.assertTrue(list((work/'reports').glob('*failed.json')))

    def test_crash_recovery_retests_installed_release(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);work=root/'work';work.mkdir()
            active=root/'agent';legacy=work/'legacy';legacy.mkdir()
            for n in ('jobs','operations'):(work/'data'/n).mkdir(parents=True)
            (work/'current').symlink_to(legacy)
            active.symlink_to(work/'current')
            cfg=core.Settings(work,active,root/'id',root/'known')
            git=FakeGit();w=core.Watcher(cfg,git=git,clock=lambda:100)
            w.tick();git.sha=SHA_B;w.tick()
            state=json.loads((work/'state.json').read_text())
            # Simulate crash after swapping pointer, before writing commit to state.
            state['deployed_commit']=None;state['deployed_tree']=None;state['last_seen_commit']=SHA_A
            core.atomic_json(work/'state.json',state)
            new=core.Watcher(cfg,git=git,clock=lambda:101)
            with patch.object(core.Deployer,'_test',side_effect=RuntimeError('postcheck failed')):
                output=new.tick()
            self.assertEqual(output['status'],'stopped_error')
            self.assertIn('postcheck failed',output['error'])

    def test_github_post_via_issue_mocked(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);work=root/'work';work.mkdir()
            token=root/'report.token';token.write_text('example-only-token');token.chmod(0o600)
            cfg=core.Settings(work,root/'agent',root/'id',root/'known',token,True)
            class Response:
                def __enter__(self):return self
                def __exit__(self,*_):return None
                def read(self,_):return b'{"html_url":"https://github.com/4oker12/cybernoc/issues/99"}'
            def mock_open(req,timeout):
                self.assertEqual(req.get_method(),'POST')
                self.assertEqual(req.full_url,'https://api.github.com/repos/4oker12/cybernoc/issues')
                body=json.loads(req.data)
                self.assertIn('SUCCESS',body['title'])
                return Response()
            with patch.object(core.request,'urlopen',side_effect=mock_open):
                x=core.Reporter(cfg).publish({'timestamp':123,'commit':SHA_A,'status':'success','detail':'ok'})
            self.assertTrue(x['github_issue'].endswith('/99'))

    def test_ssh_command_quotes_paths(self):
        with tempfile.TemporaryDirectory(prefix='path with spaces ') as t:
            root=Path(t);work=root/'work';work.mkdir()
            key=root/'ssh private key';key.write_text('test');key.chmod(0o600)
            kh=root/'known hosts';kh.write_text('test');kh.chmod(0o600)
            cfg=core.Settings(work,root/'agent',key,kh)
            env=core.GitBackend(cfg)._environment()
            self.assertIn("'",env['GIT_SSH_COMMAND'])
            self.assertNotIn('GITHUB_TOKEN',env)

class GitWatcherEndToEndTests(unittest.TestCase):
    def test_real_git_commit_then_failed_commit_stops_without_activation(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); bare=root/'remote.git'; seed=root/'seed'
            git('init','--bare','--initial-branch=cybernova-autodeploy',str(bare))
            git('clone',str(bare),str(seed))
            git('config','user.name','Cybernova Test',cwd=seed)
            git('config','user.email','robot@example.invalid',cwd=seed)
            source=seed/'cybernova'/'v10'
            (source/'tests').mkdir(parents=True)
            (source/'agent.py').write_text('print("baseline")\n')
            (source/'tests'/'test_ok.py').write_text('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertTrue(1)\n')
            git('add','.',cwd=seed);git('commit','-m','baseline',cwd=seed)
            git('push','origin','HEAD:cybernova-autodeploy',cwd=seed)
            work=root/'work';work.mkdir()
            for n in ('jobs','operations'): (work/'data'/n).mkdir(parents=True)
            legacy=work/'legacy';legacy.mkdir()
            (work/'current').symlink_to(legacy)
            active=root/'agent';active.symlink_to(work/'current')
            cfg=core.Settings(work,active,root/'key',root/'known')
            backend=core.GitBackend(cfg)
            when=[1000.]
            local_env={'HOME':str(root),'PATH':os.environ['PATH']}
            with patch.object(core,'URL',str(bare)),patch.object(backend,'_environment',return_value=local_env):
                watcher=core.Watcher(cfg,git=backend,clock=lambda:when[0])
                self.assertEqual(watcher.tick()['status'],'waiting')
                (source/'agent.py').write_text('print("working")\n')
                git('add','.',cwd=seed);git('commit','-m','working',cwd=seed)
                git('push','origin','HEAD:cybernova-autodeploy',cwd=seed)
                when[0]=1050
                self.assertEqual(watcher.tick()['status'],'active')
                self.assertEqual((active/'agent.py').read_text(),'print("working")\n')
                (source/'tests'/'test_ok.py').write_text('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.fail("intentional")\n')
                git('add','.',cwd=seed);git('commit','-m','broken',cwd=seed)
                git('push','origin','HEAD:cybernova-autodeploy',cwd=seed)
                when[0]=1100
                state=watcher.tick()
                self.assertEqual(state['status'],'stopped_error')
                self.assertEqual((active/'agent.py').read_text(),'print("working")\n')
                self.assertEqual(len(list((work/'reports').glob('*.json'))),2)
