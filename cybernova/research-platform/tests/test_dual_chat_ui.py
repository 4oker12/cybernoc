"""Independent GPT chat, persistence and safe Markdown regressions."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fastapi.testclient import TestClient
from console import server,siwc,siwc_inference
from console.siwc_chat_store import GPTChatStore,GPTChatError
from console.tunnel_access import allowed_path

class DualChatTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.db=Path(t.name)/"communications.sqlite3"
        self.store=GPTChatStore(self.db)

    def test_two_turns_and_reload(self):
        tid=self.store.save_exchange(None,"gpt-6.2-sol","Вопрос","Ответ")
        self.store.save_exchange(tid,"gpt-6.2-sol","Уточнение","Ответ два")
        other=GPTChatStore(self.db)
        self.assertEqual([x["role"] for x in other.context(tid)],
                         ["user","assistant","user","assistant"])
        self.assertEqual(len(other.get_thread(tid)["messages"]),4)
        if os.name!="nt":
            self.assertEqual(self.db.stat().st_mode & 0o077,0)
        with self.assertRaises(GPTChatError):
            other.save_exchange(None,"gpt","abc","")

    def test_qwen_and_gpt_use_independent_local_tool_runtimes(self):
        self.assertIs(server.agent.local_tool_runtime, server.deepseek_tool_runtime)
        self.assertIsNot(server.deepseek_tool_runtime, server.gpt_tool_runtime)
        self.assertNotEqual(
            server.deepseek_tool_runtime.browser_profile_dir,
            server.gpt_tool_runtime.browser_profile_dir,
        )

    def test_source_commit_uses_git_and_marks_dirty_checkout(self):
        from subprocess import CompletedProcess
        server._source_commit.cache_clear()
        self.addCleanup(server._source_commit.cache_clear)
        with patch.dict(os.environ, {"CYBERNOVA_SOURCE_COMMIT": ""}, clear=False):
            with patch.object(server.subprocess, "run", side_effect=[
                CompletedProcess([], 0, stdout="a" * 40, stderr=""),
                CompletedProcess([], 0, stdout="", stderr=""),
            ]):
                self.assertEqual(server._source_commit(), "a" * 40)
            server._source_commit.cache_clear()
            with patch.object(server.subprocess, "run", side_effect=[
                CompletedProcess([], 0, stdout="b" * 40, stderr=""),
                CompletedProcess([], 0, stdout=" M console/server.py\\n", stderr=""),
            ]):
                self.assertEqual(server._source_commit(), "uncommitted:" + "b" * 12)

    def test_gpt_http_is_separate_from_qwen_tasks(self):
        calls=[]
        def fake(model,messages,**kwargs):
            calls.append((messages,kwargs))
            return {"model":model,"answer":"ok","source":"offline"}
        with patch.object(server,"gpt_chat_store",return_value=self.store),\
             patch.object(server,"chatgpt_chat",side_effect=fake),\
             patch.object(server,"communication_store") as qwen:
            api=TestClient(server.app,base_url="http://127.0.0.1:18794")
            r=api.post("/api/siwc/chat",json={"model":"gpt-6.2-sol","message":"Привет"})
            self.assertEqual(r.status_code,200,r.text)
            tid=r.json()["thread_id"]
            r=api.post("/api/siwc/chat",json={"thread_id":tid,"model":"gpt-6.2-sol","message":"А теперь?"})
            self.assertEqual(r.status_code,200,r.text)
            self.assertEqual([x["role"] for x in calls[1][0]],["user","assistant","user"])
            self.assertEqual(len(api.get("/api/siwc/chat",params={"thread_id":tid}).json()["messages"]),4)
            self.assertEqual(api.get("/api/siwc/chats").json()["threads"][0]["thread_id"],tid)
            qwen.assert_not_called()

    def test_oauth_chat_does_not_send_tools_or_store_cloud_history(self):
        class Stream:
            def __enter__(self):return self
            def __exit__(self,*_):return None
            def __iter__(self):
                return iter([b'data: {"type":"response.output_text.delta","delta":"OK"}\n',
                             b'data: {"type":"response.completed"}\n'])
        class Opener:
            def open(self,req,**_):
                self.payload=json.loads(req.data)
                return Stream()
        opener=Opener()
        messages=[{"role":"user","content":"First"},{"role":"assistant","content":"Answer"},
                  {"role":"user","content":"Followup"}]
        with patch.object(siwc_inference,"models",return_value=[{"slug":"gpt-6.2-sol"}]),\
             patch.object(siwc_inference.connection,"access",return_value="test"),\
             patch.object(siwc_inference.request,"build_opener",return_value=opener):
            self.assertEqual(siwc_inference.chat(
                "gpt-6.2-sol",messages,
                user_context="SHARED USER PROFILE",
                profile_instructions="CHATGPT CUSTOM INSTRUCTIONS",
            )["answer"],"OK")
        self.assertEqual(opener.payload["input"],messages)
        self.assertIn("SHARED USER PROFILE",opener.payload["instructions"])
        self.assertIn("CHATGPT CUSTOM INSTRUCTIONS",opener.payload["instructions"])
        self.assertFalse(opener.payload["store"])
        self.assertNotIn("tools",opener.payload)
        with self.assertRaises(siwc.SIWCError):
            siwc_inference.chat("gpt-6.2-sol",[{"role":"system","content":"bad"}])

    def test_routes_and_simple_ui(self):
        for path,method in (("/api/siwc/chat","POST"),("/api/siwc/chat?thread_id=one","GET"),
                            ("/api/siwc/chats","GET"),("/api/profile-settings","GET"),
                            ("/api/profile-settings","POST"),("/api/model-config","GET"),
                            ("/api/model-config","POST"),("/static/markdown.js","GET"),
                            ("/static/ux.css","GET"),("/static/ux.js","GET"),
                            ("/static/model-settings.js","GET")):
            self.assertTrue(allowed_path(path,method))
        self.assertFalse(allowed_path("/api/siwc/tokens","GET"))
        html=(ROOT/"console/static/index.html").read_text()
        js=(ROOT/"console/static/app.js").read_text()
        for marker in ('id="modeQwen"','id="modeChatGPT"','id="gptThreadList"',
                       'id="gptTopModel"','id="navProfile"','id="profileDialog"',
                       'data-profile-tab="chatgpt"','/static/markdown.js','/static/ux.css',
                       '/static/model-settings.js','/static/ux.js'):
            self.assertIn(marker,html)
        self.assertEqual(html.count('src="/static/markdown.js"'),1)
        self.assertIn('async function sendGPT()',js)
        self.assertIn('setFormatted(pending.body,result.answer',js)
        self.assertIn("qwenRunning:false", js)
        self.assertIn("gptRunning:false", js)
        self.assertIn('if(!text||state.qwenRunning)return;', js)
        self.assertIn('if(!message||state.gptRunning)return;', js)
        self.assertIn('busy(true,"qwen")', js)
        self.assertIn('busy(true,"gpt")', js)
        self.assertNotIn("innerHTML=",js)
        if shutil.which("node"):
            check = subprocess.run(
                ["node", "--check", str(ROOT / "console" / "static" / "app.js")],
                capture_output=True, text=True,
            )
            self.assertEqual(check.returncode, 0, check.stderr)

    @unittest.skipUnless(shutil.which("node"),"Node unavailable")
    def test_markdown_render_with_no_dom_html_injection(self):
        source=ROOT/"console/static/markdown.js"
        check=subprocess.run(["node","--check",str(source)],capture_output=True,text=True)
        self.assertEqual(check.returncode,0,check.stderr)
        script=r"""
const vm=require('node:vm');
class N {
 constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.className='';this.dataset={};}
 append(...n){this.children.push(...n);}
 appendChild(n){this.children.push(n);return n;}
}
const doc={createElement:tag=>new N(tag),
 createTextNode:t=>({tag:'#text',textContent:t,children:[]})};
const w={};vm.runInNewContext(process.argv[1],{document:doc,window:w,URL});
const text=['# Отчёт','**Рекомендация Qwen**','**важный** пункт',
'| Следующий шаг | Критерий успеха |','| --- | --- |','| Проверить лог | Есть запись |',
'- Первый пункт','[плохая ссылка](javascript:alert(1)) <img src=x>'].join('\n');
const walk=n=>[n,...(n.children||[]).flatMap(walk)];
const nodes=walk(w.CybernovaMarkdown.render(text)),tags=nodes.map(x=>x.tag);
for(const t of ['h2','strong','section','table','th','td','ul','li']){
 if(!tags.includes(t))throw Error('missing '+t+': '+tags.join(','));
}
if(tags.includes('img')||tags.includes('a'))throw Error('unsafe HTML');
if(!nodes.some(x=>(x.className||'').includes('md-note-recommendation')))
 throw Error('recommendation not recognized');
"""
        check=subprocess.run(["node","-e",script,source.read_text()],
                             capture_output=True,text=True)
        self.assertEqual(check.returncode,0,check.stderr)

if __name__=="__main__":
    unittest.main()
