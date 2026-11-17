"""Behavioral checks for bounded repository and dependency tools."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cybernova_agent import repo_ops, model

class RepoOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'demo'; self.root.mkdir()
        patcher=patch.object(repo_ops,'OPS_HOME',Path(self.tmp.name)/'protected_ops');patcher.start();self.addCleanup(patcher.stop)

    def test_only_approved_repository_and_branch(self):
        self.assertEqual(repo_ops.REPOSITORY,'https://github.com/4oker12/cybernoc.git')
        self.assertEqual(repo_ops.BRANCH,'cybernova-autodeploy')
        self.assertNotIn('shell',repo_ops.repo_sync.__code__.co_names)

    def test_unknown_command_fails(self):
        result=repo_ops.execute_repo_tool(self.root,'bash',{'cmd':'cat /etc/shadow'})
        self.assertFalse(result['ok'])

    def test_arguments_rejected(self):
        self.assertFalse(repo_ops.execute_repo_tool(self.root,'repo_sync',{'url':'https://other.example'} )['ok'])
        self.assertFalse(repo_ops.execute_repo_tool(self.root,'repo_status',{'path':'../../root'})['ok'])

    def test_missing_checkout_is_safe(self):
        x=repo_ops.repo_status(self.root)
        self.assertEqual(x['cloned'],False)
        self.assertTrue(x['ok'])

    def test_git_root_escape_denied(self):
        (repo_ops._private_area(self.root)/repo_ops.DIR).symlink_to('/etc')
        self.assertFalse(repo_ops.repo_sync(self.root)['ok'])

    def test_root_install_denied(self):
        with patch.object(repo_ops.os,'geteuid',return_value=0):
            result=repo_ops.install_python_tool(self.root,'ruff')
        self.assertFalse(result['ok'])
        self.assertIn('non-root',result['error'])

    def test_unknown_package_never_reaches_pip(self):
        with patch.object(repo_ops.os,'geteuid',return_value=1000), patch.object(repo_ops,'_run') as runner:
            x=repo_ops.install_python_tool(self.root,'evilpackage')
        self.assertFalse(x['ok'])
        runner.assert_not_called()

    def test_pinned_tools_no_arbitrary_package(self):
        self.assertTrue(all(v.count('.')==2 for v in repo_ops.INSTALLABLE.values()))
        self.assertIn('ruff',repo_ops.INSTALLABLE)
        self.assertNotIn('bash',repo_ops.INSTALLABLE)

    def test_git_failed_dirty_prevents_update(self):
        checkout=repo_ops._private_area(self.root)/repo_ops.DIR
        checkout.mkdir()
        with patch.object(repo_ops.os,'geteuid',return_value=1000), patch.object(repo_ops,'repo_status',return_value={'ok':True,'cloned':True,'dirty':True,'branch':repo_ops.BRANCH}),patch.object(repo_ops,'_run') as runner:
            result=repo_ops.repo_sync(self.root)
        self.assertFalse(result['ok'])
        runner.assert_not_called()

    def test_model_exposes_native_tools(self):
        actions={x['function']['name'] for x in model.TOOLS}
        self.assertTrue({'repo_status','repo_sync','install_python_tool'} <= actions)
        x=model._decision_from_response({'message':{'tool_calls':[{'function':{'name':'repo_sync','arguments':{}}}]}})
        self.assertEqual(x['action'],'repo_sync')

    def test_protected_environment_drops_tokens(self):
        with patch.dict(repo_ops.os.environ, {'GITHUB_TOKEN':'dont-leak','HOME':'/tmp'}):
            env=repo_ops._env()
        self.assertNotIn('GITHUB_TOKEN',env)
        self.assertEqual(env['GIT_TERMINAL_PROMPT'],'0')

    def test_status_rejects_unexpected_origin(self):
        d=repo_ops._private_area(self.root)/repo_ops.DIR
        (d/'.git').mkdir(parents=True)
        with patch.object(repo_ops,'_origin',return_value='https://evil.example/clone.git'):
            x=repo_ops.repo_status(self.root)
        self.assertFalse(x['ok'])

if __name__=='__main__':unittest.main()
