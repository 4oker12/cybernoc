import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ring, server, observer

class ReadModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.paths=ring.Paths(self.root/'updater', self.root/'agent',self.root/'ops.py',self.root/'python')
        (self.paths.updater/'sessions').mkdir(parents=True)
        (self.paths.agent/'jobs').mkdir(parents=True)
    def tearDown(self):
        self.tmp.cleanup()
    def record(self,id,started,status='completed',passed=True):
        folder=self.paths.updater/'sessions'/id
        folder.mkdir()
        (folder/'session.json').write_text(json.dumps({'session_id':id,'started_at':started}))
        (folder/'result.json').write_text(json.dumps({'state':status,'passed':passed,'reason':'all_checks_passed','qwen_successful_actions':2,'evidence_manifests_verified':12}))
    def test_session_scope_and_metadata_projection(self):
        sid='a'*32
        self.record(sid,123)
        self.record('b'*32,124,'failed',False)
        other=self.paths.updater/'sessions'/'c'*0 if False else None
        self.assertEqual([x['id'] for x in ring.sessions(self.paths)], ['b'*32,'a'*32])
        self.assertTrue(ring.sessions(self.paths)[1]['passed'])
        self.assertNotIn('arguments',ring.sessions(self.paths)[0])
    def test_invalid_ids_symlinks_and_oversize_rejected(self):
        valid='a'*32
        self.record(valid,1)
        bad=self.paths.updater/'sessions'/'xyz'
        bad.mkdir()
        (bad/'session.json').write_text('{}')
        link=self.paths.updater/'sessions'/('b'*32)
        link.symlink_to(self.paths.updater/'sessions'/valid,target_is_directory=True)
        folder=self.paths.updater/'sessions'/('c'*32)
        folder.mkdir()
        (folder/'session.json').write_text('a'*132000)
        self.assertEqual(len(ring.sessions(self.paths)),1)
    def test_event_only_allowlist_no_raw_text(self):
        jid='a'*16
        p=self.paths.agent/'jobs'/jid
        p.mkdir()
        (p/'state.json').write_text(json.dumps({'status':'failed','updated_at':'2026-11-18T06:00:00Z','error':'token=supersecret'}))
        (p/'events.jsonl').write_text('\n'.join([json.dumps({'ts':'2026-11-18T06:00:00Z','event':'decision','args':{'content':'private prompt'}}), json.dumps({'ts':'2026-11-18T06:01:00Z','event':'unknown','secret':'a'})])+'\n')
        jobs=ring.agent_jobs(self.paths)
        self.assertNotIn('supersecret', jobs[0]['error'])
        events=ring.agent_events(self.paths,jobs)
        self.assertEqual(len(events),1)
        self.assertNotIn('args',events[0])
    def test_demo_cannot_be_mistaken_for_live(self):
        s=ring.demo_snapshot()
        self.assertEqual(s['mode'],'DEMO')
        self.assertEqual(s['scope'],'LOCAL_LAB_ONLY')
    def test_missing_runner_never_runs_shell(self):
        self.assertEqual(ring.start_local_baseline(self.paths)['reason'],'session_runner_missing')
    def test_token_file_private_and_no_overwrite(self):
        f=self.root/'private'/'token'
        server.create_token_file(f)
        self.assertEqual(len(server.read_token(f))>=40,True)
        self.assertEqual(os.stat(f).st_mode & 0o777,0o600)
        with self.assertRaises(FileExistsError):server.create_token_file(f)
        os.chmod(f,0o644)
        with self.assertRaises(ValueError):server.read_token(f)

class APITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.paths=ring.Paths(Path(self.tmp.name))
        self.server=server.PanelServer(('127.0.0.1',0),'z'*50,self.paths,enable_start=True)
        self.port=self.server.server_port
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.original_host=f'127.0.0.1:{self.port}'
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3);self.tmp.cleanup()
    def fetch(self,path, token=None, method='GET',origin=None,data=None,host=None):
        h={'Host':host or self.original_host}
        if token:h['X-Cybernova-Token']=token
        if origin is not None:h['Origin']=origin
        if method=='POST':h['Content-Type']='application/json'
        req=Request(f'http://127.0.0.1:{self.port}{path}',data=data,headers=h,method=method)
        try:
            with urlopen(req,timeout=3) as resp:return resp.status,resp.read()
        except HTTPError as exc:return exc.code,exc.read()
    def test_index_public_api_authenticated(self):
        self.assertEqual(self.fetch('/')[0],200)
        self.assertEqual(self.fetch('/api/status')[0],401)
        with patch.object(server,'snapshot',return_value=ring.demo_snapshot()):
            code,raw=self.fetch('/api/status',token='z'*50)
            self.assertEqual(code,200)
            self.assertEqual(json.loads(raw)['mode'],'DEMO')
    def test_cross_origin_and_csrf_rejected(self):
        t='z'*50
        self.assertEqual(self.fetch('/api/session/start',t,'POST','https://evil.test',b'{}')[0],403)
        self.assertEqual(self.fetch('/api/session/start',t,'POST',None,b'{}')[0],403)
        self.assertEqual(self.fetch('/api/session/start',t,'POST',f'http://127.0.0.1:{self.port}',b'{"cmd":"id"}')[0],400)
    def test_action_is_exactly_fixed_no_user_arguments(self):
        with patch.object(server,'start_local_baseline',return_value={'ok':True,'session_id':'a'*32}) as m:
            c,body=self.fetch('/api/session/start','z'*50,'POST',f'http://127.0.0.1:{self.port}',b'{}')
            self.assertEqual(c,200)
            self.assertEqual(json.loads(body)['session_id'],'a'*32)
            m.assert_called_once()
    def test_start_disabled_by_default(self):
        self.server.enable_start=False
        self.assertEqual(self.fetch('/api/session/start','z'*50,'POST',f'http://127.0.0.1:{self.port}',b'{}')[0],403)
    def test_observer_api_requires_token_and_valid_cursor(self):
        self.server.observer=observer.Observer(Path(self.tmp.name)/'observer')
        self.assertEqual(self.fetch('/api/observer/events')[0],401)
        self.assertEqual(self.fetch('/api/observer/events?after=-1','z'*50)[0],400)
        self.assertEqual(self.fetch('/api/observer/events?after=3&extra=1','z'*50)[0],400)
        code,body=self.fetch('/api/observer/events?after=0','z'*50)
        self.assertEqual(code,200)
        self.assertEqual(json.loads(body)['events'],[])

    def test_sensitive_headers(self):
        req=Request(f'http://127.0.0.1:{self.port}/')
        with urlopen(req,timeout=3) as r:
            self.assertEqual(r.headers['X-Frame-Options'],'DENY')
            self.assertEqual(r.headers['Cache-Control'],'no-store')
            self.assertIn("script-src 'self'",r.headers['Content-Security-Policy'])

if __name__=='__main__':unittest.main()

class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.paths=ring.Paths(root/'updater',root/'agent')
        (self.paths.updater/'sessions').mkdir(parents=True)
        (self.paths.agent/'jobs').mkdir(parents=True)
        self.directory=root/'private'
        self.monitor=observer.Observer(self.directory)

    def session(self, sid, state='running'):
        folder=self.paths.updater/'sessions'/sid
        folder.mkdir(exist_ok=True)
        (folder/'session.json').write_text(json.dumps({'session_id':sid,'started_at':100}))
        result=folder/'result.json'
        if state!='running':
            result.write_text(json.dumps({'state':state,'passed':state=='completed'}))
        elif result.exists():
            result.unlink()

    def job(self, jid, state='running'):
        folder=self.paths.agent/'jobs'/jid
        folder.mkdir(exist_ok=True)
        (folder/'state.json').write_text(json.dumps({'job_id':jid,'status':state,'updated_at':'2026-11-18T06:02:00Z','secret':'private text'}))

    def test_bootstrap_is_silent_and_terminal_transition_is_once(self):
        sid='a'*32
        self.session(sid,'running')
        self.assertEqual(self.monitor.collect(self.paths)['new_events'],0)
        self.session(sid,'completed')
        self.assertEqual(self.monitor.collect(self.paths)['new_events'],1)
        self.assertEqual(self.monitor.collect(self.paths)['new_events'],0)
        event=self.monitor.read()['events'][0]
        self.assertEqual((event['seq'],event['kind'],event['state']),(1,'session','completed'))
        self.assertNotIn('secret',str(event))
        self.assertEqual(observer.Observer(self.directory).read()['latest_seq'],1)

    def test_new_fast_completed_session_is_not_missed(self):
        self.monitor.collect(self.paths)
        self.session('f'*32,'completed')
        self.assertEqual(self.monitor.collect(self.paths)['new_events'],1)
        self.assertEqual(self.monitor.read()['events'][0]['id'],'f'*32)

    def test_preexisting_terminal_session_is_not_replayed(self):
        self.session('a'*32,'completed')
        self.monitor.collect(self.paths)
        self.assertEqual(self.monitor.read()['events'],[])

    def test_agent_transitions_and_cursor(self):
        jid='a'*16
        self.job(jid,'running')
        self.monitor.collect(self.paths)
        self.job(jid,'failed')
        self.monitor.collect(self.paths)
        self.job('b'*16,'needs_human')
        self.monitor.collect(self.paths)
        events=self.monitor.read()['events']
        self.assertEqual([x['state'] for x in events],['failed','needs_human'])
        self.assertEqual(len(self.monitor.read(after=1)['events']),1)
        self.assertEqual(self.monitor.read(after=2)['events'],[])
        with self.assertRaises(ValueError):self.monitor.read(after=-1)
        with self.assertRaises(ValueError):self.monitor.read(after=True)

    def test_directory_permissions(self):
        if os.name=='posix':
            self.assertEqual(os.stat(self.directory).st_mode & 0o777,0o700)
            self.assertEqual(os.stat(self.monitor.dbfile).st_mode & 0o777,0o600)