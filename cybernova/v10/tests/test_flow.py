from __future__ import annotations
import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from cybernova_agent import common,tools,worker

class FlowTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  root=Path(self.tmp.name)
  self.jobs=root/'agent'/'jobs'; self.project_root=root/'projects';self.home=root/'agent';self.job='a'*16
  self.job_dir=self.jobs/self.job;self.job_dir.mkdir(parents=True)
  self.state={'job_id':self.job,'goal':'Create a valid Python file with a trivial function','project':'demo','max_steps':8,'max_seconds':30}
  (self.job_dir/'state.json').write_text(json.dumps(self.state))
  for obj,attr,val in [(common,'JOBS',self.jobs),(tools,'PROJECTS',self.project_root),(tools,'BASE',self.home),(worker,'jidpath',lambda _:self.job_dir),(worker,'project_root',lambda _:tools.project_root('demo')),(worker,'state_update',lambda _id,**changes:common.state_update(_id,**changes)),(worker,'event',lambda _id,ev,**kwargs:common.event(_id,ev,**kwargs))]:
   p=patch.object(obj,attr,val);p.start();self.addCleanup(p.stop)
 def test_completed_after_real_syntax_check(self):
  actions=iter([{'action':'write_file','args':{'path':'hello.py','content':'def hello():\n    return 42\n'},'reason':'Implement'}, {'action':'check_file','args':{'path':'hello.py'},'reason':'Verify'},{'action':'finish','args':{'summary':'Python syntax check passed; runtime not tested'},'reason':'Done'}])
  p=patch.object(worker,'chat',lambda *x,**kw:next(actions));p.start();self.addCleanup(p.stop)
  worker.run(self.job)
  self.assertEqual(json.loads((self.job_dir/'state.json').read_text())['status'],'succeeded')
  self.assertEqual(json.loads((self.job_dir/'report.json').read_text())['checked'],True)
 def test_finish_without_check_blocked(self):
  actions=iter([{'action':'write_file','args':{'path':'hello.py','content':'pass'},'reason':'write'}, {'action':'finish','args':{'summary':'Looks fine'},'reason':'finish'}, {'action':'ask_human','args':{'question':'Need approval for unverified file'},'reason':'Cannot verify'}])
  p=patch.object(worker,'chat',lambda *x,**kw:next(actions));p.start();self.addCleanup(p.stop)
  worker.run(self.job)
  self.assertEqual(json.loads((self.job_dir/'state.json').read_text())['status'],'needs_human')
 def test_three_identical_actions_stops(self):
  action={'action':'list_files','args':{},'reason':'Repeated'}
  p=patch.object(worker,'chat',lambda *x,**kw:action);p.start();self.addCleanup(p.stop)
  worker.run(self.job)
  self.assertEqual(json.loads((self.job_dir/'state.json').read_text())['status'],'failed')
  self.assertIn('Repeated identical action',json.loads((self.job_dir/'state.json').read_text())['error'])

 def test_repeated_list_after_changes_is_not_a_loop(self):
  actions=iter([
    {'action':'list_files','args':{},'reason':'Inspect empty project'},
    {'action':'write_file','args':{'path':'hello.py','content':'def hello():\n    return 42\n'},'reason':'Implement'},
    {'action':'check_file','args':{'path':'hello.py'},'reason':'Check Python'},
    {'action':'list_files','args':{},'reason':'Inspect after adding Python'},
    {'action':'write_file','args':{'path':'README.md','content':'# Hello\nUsage: hello()'},'reason':'Document'},
    {'action':'check_file','args':{'path':'README.md'},'reason':'Check Markdown'},
    {'action':'list_files','args':{},'reason':'Inspect final files'},
    {'action':'finish','args':{'summary':'Python syntax checked; README non-empty'},'reason':'Done'},
  ])
  p=patch.object(worker,'chat',lambda *x,**kw:next(actions));p.start();self.addCleanup(p.stop)
  worker.run(self.job)
  self.assertEqual(json.loads((self.job_dir/'state.json').read_text())['status'],'succeeded')

 def test_duplicate_readonly_is_rejected_without_aborting_job(self):
  actions=iter([
    {'action':'write_file','args':{'path':'hello.py','content':'pass\n'},'reason':'Create'},
    {'action':'check_file','args':{'path':'hello.py'},'reason':'Verify'},
    {'action':'list_files','args':{},'reason':'List'},
    {'action':'list_files','args':{},'reason':'Repeat, corrected by controller'},
    {'action':'finish','args':{'summary':'Syntax checked'},'reason':'Done'},
  ])
  p=patch.object(worker,'chat',lambda *x,**kw:next(actions));p.start();self.addCleanup(p.stop)
  worker.run(self.job)
  self.assertEqual(json.loads((self.job_dir/'state.json').read_text())['status'],'succeeded')
  self.assertIn('Duplicate read-only action', (self.job_dir/'output.log').read_text())

if __name__=='__main__': unittest.main()
