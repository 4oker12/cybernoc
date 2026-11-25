from pathlib import Path
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('handshake', Path(__file__).parents[1] / 'handshake.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

RID = 'CN-HS-20261117-01'

class Fake:
    def __init__(self, valid=True):
        self.valid = valid
        self.comments = []
        self.calls = []
    def call(self, path, method='GET', payload=None):
        self.calls.append((path, method))
        if path == '/issues/1':
            return {'state': 'open', 'user': {'login': '4oker12'},
                    'title': '[Cybernova handshake] ' + RID,
                    'body': f'**Request ID:** `{RID}`\n**Протокол:** `{module.PROTOCOL}`\n**Тип:** `echo`' if self.valid else 'bad'}
        if path == '/issues/1/comments':
            if method == 'GET':
                return self.comments
            d = {'body': payload['body'], 'html_url': 'https://github.com/4oker12/cybernoc/issues/1#issuecomment-9'}
            self.comments.append(d)
            return d
        raise AssertionError(path)

class Tests(unittest.TestCase):
    def test_real_request_can_be_answered(self):
        f=Fake()
        r=module.handshake(f,1,RID)
        self.assertEqual('sent',r['status'])
        self.assertEqual(RID,module.extract_response(f.comments[0]['body'])['request_id'])
        self.assertIn('GitHub round trip OK', f.comments[0]['body'])

    def test_reply_is_idempotent(self):
        f=Fake()
        module.handshake(f,1,RID)
        self.assertEqual('already_answered',module.handshake(f,1,RID)['status'])
        self.assertEqual(1,len(f.comments))
        self.assertEqual(1,len([x for x in f.calls if x[1]=='POST']))

    def test_untrusted_issue_is_ignored(self):
        f=Fake(valid=False)
        self.assertEqual('ignored', module.handshake(f,1,RID)['status'])
        self.assertEqual(0,len(f.comments))

    def test_rejects_unexpected_request_ids(self):
        with self.assertRaises(ValueError):
            module.handshake(Fake(),1,'../../.ssh/private')

    def test_invalid_issue_number(self):
        with self.assertRaises(ValueError):
            module.handshake(Fake(),0,RID)

    def test_response_parser_rejects_non_echo(self):
        self.assertIsNone(module.extract_response('```json\n{"protocol":"abc","status":"received"}\n```'))

    def test_token_file_mode_is_enforced(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'token'
            p.write_text('sample',encoding='utf8')
            p.chmod(0o644)
            with self.assertRaises(RuntimeError):
                module.GitHubAPI(p)
            p.chmod(0o600)
            self.assertIsInstance(module.GitHubAPI(p),module.GitHubAPI)

    def test_api_restricts_routes_before_network(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'token';p.write_text('dummy');p.chmod(0o600)
            a=module.GitHubAPI(p)
            with self.assertRaises(ValueError):
                a.call('/repos/other/private')
            with self.assertRaises(ValueError):
                a.call('/issues/1',method='POST',payload={})

    def test_get_post_failure_hides_transport_details(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'token';p.write_text('dummy123');p.chmod(0o600)
            a=module.GitHubAPI(p)
            with patch.object(module.request,'urlopen',side_effect=RuntimeError('token is dummy123')):
                with self.assertRaises(RuntimeError) as ctx:
                    a.call('/issues/1')
                self.assertNotIn('dummy123',str(ctx.exception))

if __name__ == '__main__':
    unittest.main()