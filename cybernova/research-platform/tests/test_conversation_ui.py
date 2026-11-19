"""Regression coverage for independent GPT conversations and readable UI."""
from __future__ import annotations
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from console import server, siwc_chat_store, communication
from console.tunnel_access import allowed_path
from fastapi import HTTPException


class GPTConversationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)/"comms.sqlite3"
        self.qwen=communication.CommunicationStore(self.path)
        self.store=siwc_chat_store.GPTChatStore(self.path)

    def test_gpt_dialogue_is_durable_and_separate_from_qwen(self):
        task=self.qwen.create_task("Qwen network lab")
        tid=self.store.save_exchange(None,"gpt-6.2-sol","Привет","Здравствуйте.")
        self.store.save_exchange(tid,"gpt-6.2-sol","А дальше?","Продолжим.")
        self.assertEqual([m["role"] for m in self.store.context(tid)],
                         ["user","assistant","user","assistant"])
        self.assertEqual(len(self.store.list_threads()),1)
        self.assertEqual(self.store.get_thread(tid)["messages"][-1]["content"],
                         "Продолжим.")
        self.assertEqual(self.qwen.get_task(task["task_id"])["title"],"Qwen network lab")
        self.assertEqual(len(self.qwen.read_dialog(task["task_id"])["messages"]),0)
        reopened=siwc_chat_store.GPTChatStore(self.path)
        self.assertEqual(len(reopened.get_thread(tid)["messages"]),4)

    def test_gpt_api_uses_only_its_own_context_without_mcp(self):
        conversations=[]
        def answer(model,history):
            conversations.append(history)
            return {"answer":"GPT answer","model":model,"source":"chatgpt_plan_responses"}
        with patch.object(server,"gpt_chat_store",return_value=self.store),\
             patch.object(server,"chatgpt_chat",side_effect=answer),\
             patch.object(server,"agent") as agent:
            first=server.siwc_chat_message(server.ChatGPTMessageRequest(
                model="gpt-6.2-sol",message="Первый вопрос"))
            second=server.siwc_chat_message(server.ChatGPTMessageRequest(
                thread_id=first["thread_id"],model="gpt-6.2-sol",
                message="Продолжение"))
            agent.run.assert_not_called()
        self.assertEqual([m["role"] for m in conversations[1]],
                         ["user","assistant","user"])
        self.assertEqual(conversations[1][-1]["content"],"Продолжение")
        self.assertEqual(first["thread_id"],second["thread_id"])

    def test_failed_chat_is_not_persisted(self):
        with patch.object(server,"gpt_chat_store",return_value=self.store),\
             patch.object(server,"chatgpt_chat",
                          side_effect=server.SIWCError("not_connected")):
            with self.assertRaises(HTTPException) as caught:
                server.siwc_chat_message(server.ChatGPTMessageRequest(
                    model="gpt-6.2-sol",message="test"))
        self.assertEqual(caught.exception.status_code,409)
        self.assertEqual(self.store.list_threads(),[])

    def test_gateway_only_allows_specific_authenticated_chat_routes(self):
        self.assertTrue(allowed_path("/api/siwc/chats","GET"))
        self.assertTrue(allowed_path("/api/siwc/chat?thread_id=gpt_AAA","GET"))
        self.assertTrue(allowed_path("/api/siwc/chat","POST"))
        self.assertTrue(allowed_path("/static/markdown.js","GET"))
        self.assertFalse(allowed_path("/api/siwc/tokens","GET"))

    def test_markup_is_loaded_once_and_has_no_html_execution(self):
        html=(ROOT/"console/static/index.html").read_text()
        js=(ROOT/"console/static/markdown.js").read_text()
        app=(ROOT/"console/static/app.js").read_text()
        self.assertEqual(html.count('src="/static/markdown.js"'),1)
        self.assertNotIn("innerHTML",js.split("(function () {",1)[1])
        self.assertIn("CybernovaMarkdown.render",app)
        self.assertIn('id="modeChatGPT"',html)
        self.assertIn('id="gptThreadList"',html)


@unittest.skipUnless(shutil.which("node"),"Node runtime unavailable")
class BrowserMarkdownTests(unittest.TestCase):
    def test_safe_rendering_of_sections_tables_code_and_lists(self):
        js=StringJS = r'''
        const fs=require("fs"),vm=require("vm"),assert=require("assert");
        const mk=(tag)=>({
          tagName:tag.toUpperCase(),className:"",dataset:{},textContent:"",
          children:[],append(...nodes){this.children.push(...nodes)},
          appendChild(node){this.children.push(node);return node},
        });
        global.document={createElement:mk,createTextNode:(text)=>({textContent:text,nodeType:3})};
        global.window={};
        vm.runInThisContext(fs.readFileSync(process.argv[1],"utf8"));
        const input=[
          "## Анализ", "",
          "**Рекомендация Qwen:** Проверить источник", "",
          "Следующий шаг | Критерий успеха |",
          "| --- | --- |",
          "| Проверить | Результат |", "",
          "- Собрать сведения", "- Сопоставить", "",
          "'''bash", "echo <safe>", "'''", "",
          "<img src=x onerror=alert(1)>",
          "[bad](javascript:alert(1))"
        ].join("\n").replace(/'''/g,String.fromCharCode(96).repeat(3));
        const rendered=window.CybernovaMarkdown.render(input);
        const nodes=[];
        const visit=(n)=>{nodes.push(n);for(const c of n.children||[])visit(c)};
        visit(rendered);
        assert(nodes.some(n=>n.className==="md-note md-note-recommendation"));
        assert(nodes.some(n=>n.tagName==="TABLE"));
        assert(nodes.some(n=>n.tagName==="UL"));
        assert(nodes.some(n=>n.tagName==="PRE"));
        assert(nodes.some(n=>n.tagName==="STRONG"||n.tagName==="H3"));
        assert(!nodes.some(n=>n.tagName==="IMG"||n.tagName==="SCRIPT"));
        const content=nodes.map(n=>n.textContent||"").join(" ");
        assert(content.includes("<img src=x onerror=alert(1)>"));
        '''
        script_path=ROOT/"console/static/markdown.js"
        result=subprocess.run([shutil.which("node"),"-e",js,str(script_path)],
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr[-2500:])


if __name__=="__main__":
    unittest.main()
