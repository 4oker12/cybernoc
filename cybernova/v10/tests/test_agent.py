import tempfile,unittest,json,os
from pathlib import Path
from unittest.mock import patch
from cybernova_agent import common,tools,model
from cybernova_agent_observability import snapshot

class PolicyTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.job='0'*16
  patcher=patch.object(tools,'BASE',self.root/'agent');patcher.start();self.addCleanup(patcher.stop)
 def test_no_escape(self):
  for path in ('../bad.py','/etc/passwd','a/.hidden.py','a\\bad.py','leak.sh'):
   with self.assertRaises(ValueError,msg=path):tools.safe_path(self.root,path)
 def test_symlink_rejected(self):
  (self.root/'outer.py').symlink_to('/etc/passwd')
  with self.assertRaises(ValueError):tools.safe_path(self.root,'outer.py')
 def test_write_compile_and_snapshot(self):
  r=tools.execute_tool(self.root,'write_file',{'path':'pkg/hello.py','content':'print("hello")\n'},self.job)
  self.assertTrue(r['ok'])
  self.assertTrue(tools.execute_tool(self.root,'check_file',{'path':'pkg/hello.py'},self.job)['ok'])
  r=tools.execute_tool(self.root,'write_file',{'path':'pkg/hello.py','content':'def : broken'},self.job)
  self.assertTrue(r['ok']);self.assertFalse(tools.execute_tool(self.root,'check_file',{'path':'pkg/hello.py'},self.job)['ok'])
  self.assertEqual(len(list((self.root/'agent'/'history'/self.job).glob('*.bak'))),1)
 def test_json(self):
  tools.execute_tool(self.root,'write_file',{'path':'data.json','content':'{"ok":true}'},self.job)
  self.assertTrue(tools.execute_tool(self.root,'check_file',{'path':'data.json'},self.job)['ok'])
 def test_markdown_nonempty(self):
  tools.execute_tool(self.root,'write_file',{'path':'README.md','content':'# Project'},self.job)
  self.assertEqual(tools.execute_tool(self.root,'check_file',{'path':'README.md'},self.job)['check'],'nonempty_utf8_only')
 def test_unknown_tool(self):
  self.assertFalse(tools.execute_tool(self.root,'run_shell',{'cmd':'rm -rf /'},self.job)['ok'])

class MonitorTests(unittest.TestCase):
 def test_empty(self):
  with tempfile.TemporaryDirectory() as d,patch('cybernova_agent_observability.ROOT',Path(d)):
   self.assertFalse(snapshot()['agent_job_found'])
 def test_job(self):
  with tempfile.TemporaryDirectory() as d,patch('cybernova_agent_observability.ROOT',Path(d)):
   root=Path(d);j=root/('f'*16);j.mkdir();(j/'state.json').write_text(json.dumps({'status':'needs_human','question':'Review tests'}));(j/'output.log').write_text('event')
   res=snapshot();self.assertEqual(res['agent_status'],'needs_human');self.assertIn('event',res['agent_log_tail'])

class ModelTests(unittest.TestCase):
 def test_model_schema_has_bounded_output(self):
  self.assertIn('write_file',model.SYS)
  self.assertIn('ONE valid JSON object',model.SYS)

if __name__=='__main__':unittest.main()
