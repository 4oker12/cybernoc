"""Regression: real HTML script loading contract and JS event wiring.

Previously a malformed </script tag prevented app.js from loading and left
every button dead while all Python/API tests still passed.
"""
import json
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
STATIC=ROOT/"console"/"static"


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.starts=[]
        self.ends=0
    def handle_starttag(self,tag,attrs):
        if tag=="script":
            self.starts.append(dict(attrs))
    def handle_endtag(self,tag):
        if tag=="script":
            self.ends+=1


class WebUIBootTests(unittest.TestCase):
    def test_browser_receives_closed_external_scripts(self):
        html=(STATIC/"index.html").read_text(encoding="utf-8")
        self.assertNotIn("</script\n",html)
        self.assertNotIn("<script defer src=\"/static/markdown.js\"></script\n",html)
        parsed=Scripts()
        parsed.feed(html)
        self.assertEqual([x.get("src") for x in parsed.starts],
                         ["/static/markdown.js?v=20261123-semantic-sections-1","/static/app.js?v=20261128-green-activity-2",
                          "/static/model-settings.js?v=20261123-deepseek-controls-1","/static/ux.js?v=20261123-global-design-2"])
        self.assertEqual(parsed.ends,4)
        self.assertEqual(html.count("</script>"),4)

    def test_global_github_design_system_covers_the_research_console(self):
        html=(STATIC/"index.html").read_text(encoding="utf-8")
        design=(STATIC/"design-system.css").read_text(encoding="utf-8")
        self.assertIn('/static/design-system.css?v=20261128-green-activity-2',html)
        self.assertGreater(html.index('/static/design-system.css'),html.index('/static/ux.css'))
        for selector in ('.sidebar','.topbar','.chat-msg.from-user .message-body',
                         '.md-content strong','.md-section--risk','.md-code',
                         '.tool-batch','.tool-picker','.collab-entry','.inspector',
                         '.profile-dialog',':root[data-theme="dark"]'):
            self.assertIn(selector,design)
        self.assertIn('--accent:#1f883d',design)
        self.assertIn('--purple:#8250df',design)
        self.assertIn('--success:#1a7f37',design)

    def test_control_panel_uses_the_same_light_design_language(self):
        root=ROOT.parent/"control-panel"/"web"
        html=(root/"index.html").read_text(encoding="utf-8")
        design=(root/"design-system.css").read_text(encoding="utf-8")
        self.assertIn('<meta name="color-scheme" content="light">',html)
        self.assertIn('/design-system.css?v=20261123-github-global-2',html)
        self.assertGreater(html.index('/design-system.css'),html.index('/style.css'))
        for selector in ('.sidebar','.nav-link.active','.metric','.panel',
                         '.ring-node','.participant-status','.auth-modal'):
            self.assertIn(selector,design)
        self.assertIn('--blue:#0969da',design)
        self.assertIn('--purple:#8250df',design)
        self.assertIn('--green:#1a7f37',design)

    def test_chat_headings_and_compact_composer_contract(self):
        html=(STATIC/"index.html").read_text(encoding="utf-8")
        css=(STATIC/"styles.css").read_text(encoding="utf-8")
        app=(STATIC/"app.js").read_text(encoding="utf-8")
        self.assertIn('<textarea id="messageInput" rows="1"',html)
        self.assertIn('min-height:30px;height:30px;max-height:140px',css)
        self.assertIn('.md-content>h2',css)
        self.assertIn('font-weight:850',css)
        self.assertIn('font-size:20px',css)
        self.assertIn('function resizeComposer()',app)
        self.assertIn('showReviewStatus(pending,result.review)',app)
        self.assertNotIn('Grandmaster · NOC / Development',app)
        self.assertIn(".collab-entry .collab-full .md-content>h2",css)
        self.assertIn("selected ultra-clean editorial style",css)
        self.assertNotIn('id="pasteOutputButton"',html)
        self.assertIn("Ctrl+V — вставить вывод",html)
        self.assertIn(".followup-question{",css)
        self.assertIn("background:#eaf2ff",css)

    def test_green_accent_single_composer_focus_and_compact_usage(self):
        design=(STATIC/"design-system.css").read_text(encoding="utf-8")
        variant=(STATIC/"variant3.css").read_text(encoding="utf-8")
        app=(STATIC/"app.js").read_text(encoding="utf-8")
        self.assertIn("--accent:#1f883d",design)
        self.assertIn("--accent-strong:#166534",design)
        self.assertIn(".composer textarea#messageInput:focus-visible",variant)
        self.assertIn("outline:none!important;border:0!important",variant)
        self.assertIn(".token-usage-receipt { display: none !important; }",variant)
        self.assertIn(".composer-meta #tokenUsageStatus",variant)
        self.assertIn(".inline-tools .tool-batch-count",variant)
        self.assertIn(".followup-question:focus:not(:focus-visible)",variant)
        self.assertIn('["qwen","offer"].includes(result.source)',app)
        self.assertIn("answer_without_offer",app)
        self.assertIn("button.dataset.prompt=text",app)
        self.assertIn('"Токены · вход: "+formatTokens(last.input)',app)

    def test_deepseek_controls_are_real_and_contextual(self):
        html=(STATIC/"index.html").read_text(encoding="utf-8")
        script=(STATIC/"model-settings.js").read_text(encoding="utf-8")
        app=(STATIC/"app.js").read_text(encoding="utf-8")
        self.assertIn('id="modelQuickSettings"',html)
        self.assertIn('preset.id = "modelPreset"',script)
        self.assertIn('effort.id = "modelReasoningEffort"',script)
        self.assertIn('["deepseek-v4-pro", "DeepSeek V4 Pro',script)
        self.assertIn('["max", "Max',script)
        self.assertIn('reasoning_effort:',script)
        self.assertIn('openProfileSettings("model")',app)

    def test_green_heading_hierarchy_and_clear_task_statuses(self):
        design=(STATIC/"design-system.css").read_text(encoding="utf-8")
        app=(STATIC/"app.js").read_text(encoding="utf-8")
        self.assertIn("--heading:#1f883d",design)
        self.assertIn("--heading:#3fb950",design)
        self.assertIn("color:var(--heading)",design)
        self.assertIn(".followup-questions{display:flex;flex-direction:row",design)
        self.assertIn('completed: "Готово"',app)
        self.assertIn('needs_review: "Нужна проверка"',app)
        self.assertIn("button.title=taskName",app)
        self.assertIn('aria-label","Открыть исследование:',app)

    @unittest.skipUnless(shutil.which("node"),"Node.js unavailable")
    def test_buttons_bind_and_qwen_chatgpt_switch_responds(self):
        html=(STATIC/"index.html").read_text(encoding="utf-8")
        app=(STATIC/"app.js").read_text(encoding="utf-8")
        script=r"""
const vm=require('node:vm');
const [html, app] = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
const nodes=new Map();
class Elem {
  constructor(id=''){
    this.id=id;this.listeners={};this.hidden=false;this.disabled=false;
    this.textContent='';this.value='';this.dataset={};this.children=[];
    this.options=[];this.className='';this.scrollTop=0;this.scrollHeight=0;
    this.classList={
      add:()=>{},remove:()=>{},toggle:()=>{},contains:()=>false
    };
  }
  addEventListener(type,fn){this.listeners[type]=fn;}
  querySelectorAll(){return [];}
  setAttribute(){}
  append(...child){this.children.push(...child);}
  appendChild(child){this.children.push(child);return child;}
  replaceChildren(...child){this.children=child;}
  cloneNode(){return new Elem(this.id);}
  remove(){}
  focus(){}
  scrollIntoView(){}
  querySelector(){return null;}
  get childNodes(){return this.children;}
}
for(const id of ids)nodes.set(id,new Elem(id));
const byId=id=>nodes.get(id)||null;
const css={
 '.conversation':new Elem('conversation'),
 '.upload-button':new Elem('upload-button'),
 '.auto-tools-label':new Elem('auto-tools-label'),
 '.connection-label':new Elem('connection-label'),
 '.chatgpt-connection':new Elem('chatgpt-connection')
};
const callbacks={};
const document={
 getElementById:byId,
 querySelector:selector=>css[selector]||null,
 addEventListener:(name,fn)=>callbacks[name]=fn,
 createElement:tag=>new Elem(tag),
 createTextNode:t=>({textContent:t})
};
const window={
 addEventListener:(name,fn)=>{(window.listeners||(window.listeners={}))[name]=fn;},
 dispatchEvent:event=>{const fn=window.listeners?.[event.type];if(fn)fn(event);},
 location:{search:'',pathname:'/',hostname:'127.0.0.1',port:'18795'},
 history:{replaceState(){}},
 setInterval(){},
 navigator:{},
};
const fetch=async path=>({
 ok:true,status:200,
 json:async()=>{
   if(path==='/api/status')return {model:'Qwen test',ollama_ready:true,
       mcp_ready:true,tools:[],communication:{enabled:true}};
   if(path==='/api/siwc/status')return {connected:false,plan_usage:false};
   if(path==='/api/siwc/chats')return {threads:[]};
   if(path==='/api/comm/tasks')return {tasks:[]};
   return {};
 }
});
const context={document,window,fetch,URLSearchParams,console,
  navigator:{clipboard:{readText:async()=>'PS> Get-Process\\npython 1234'}}};
vm.runInNewContext(app,context);
if(typeof callbacks.DOMContentLoaded!=='function')throw Error('Init handler missing');
callbacks.DOMContentLoaded();
if(byId('pasteOutputButton')!==null)
 throw Error('Custom clipboard paste button should be removed');
for(const id of ['sendButton','newSession','modeQwen','modeChatGPT','navChatGPT','navTools']){
 if(typeof byId(id).listeners.click!=='function')throw Error('Button not bound: '+id);
}
byId('modeChatGPT').listeners.click();
if(byId('gptMessages').hidden||!byId('messages').hidden)
 throw Error('ChatGPT click did not change visible conversation');
byId('modeQwen').listeners.click();
if(byId('messages').hidden||!byId('gptMessages').hidden)
 throw Error('Qwen click did not restore Qwen conversation');
byId('modeCollab').listeners.click();
if(byId('collabMessages').hidden||!byId('messages').hidden||!byId('gptMessages').hidden)
 throw Error('Collaboration click did not show the two-model transcript');
byId('modeQwen').listeners.click();
context.busy(true);
if(byId('modeCollab').disabled)
 throw Error('Independent model request wrongly disabled collaboration tab');
byId('modeCollab').listeners.click();
if(byId('collabMessages').hidden)
 throw Error('Could not enter collaboration while regular model is running');
if(byId('newSession').disabled)
 throw Error('Collaboration new task was locked by an unrelated model call');
context.busy(false);
byId('sidebarCollapse').listeners.click();
if(byId('sidebarExpand').hidden)
 throw Error('Sidebar could not be collapsed');
byId('sidebarExpand').listeners.click();
if(!byId('sidebarExpand').hidden)
 throw Error('Sidebar could not be expanded');
if(typeof byId('collabFinish').listeners.click!=='function')
 throw Error('Finish button not wired');
for(const id of ['collabPlan','collabWorkRun']){
 if(typeof byId(id).listeners.click!=='function')
   throw Error('Work orchestrator button not wired: '+id);
}
const largeMessage='Full technical evidence paragraph. '.repeat(25);
const run={
 task_id:'task_test',goal:'Test',state:'paused',step:10,max_cycles:5,
 pause_at:10,next_actor:null,messages:[
  {seq:101,actor:'human',kind:'instruction',body:'User task'},
  {seq:102,actor:'chatgpt',kind:'feedback',body:largeMessage}
 ]};
context.renderCollabRun(run);
if(byId('collabResume').hidden || byId('collabFinish').hidden)
 throw Error('Pause must offer Resume and Finish controls');
const cards=byId('collabLog').children;
if(cards.length!==2)throw Error('Expected two compact messages');
const detail=cards[1].children.find(child=>child.className==='collab-details');
if(!detail)throw Error('Long model answer was not collapsible');
const excerpt=detail.children[0].children[0].textContent;
if(!excerpt.endsWith('…') || excerpt.length>180)
 throw Error('Preview is not a short excerpt: '+excerpt);
detail.open=true;detail.listeners.toggle();
if(detail.children[1].textContent!==largeMessage)
 throw Error('Expansion lost the full original answer');

context.renderCollabRun({
 task_id:'task_parallel',goal:'Test',mode:'parallel',state:'active',
 step:0,max_cycles:5,pause_at:10,next_actor:null,messages:[]
});
if(byId('collabWorkPanel').hidden)
 throw Error('Parallel mode did not show planning panel');
if(byId('collabPlan').hidden)
 throw Error('Parallel mode did not offer a planning action');
context.renderWorkItems('task_parallel',[
 {item_id:'wi_1',position:0,title:'Audit logs',instructions:'Read safe logs',
  state:'needs_review',depends_on:[],attempt:1,result:'Observed two events.',review:''},
 {item_id:'wi_2',position:1,title:'Summary',instructions:'Compare sources',
  state:'queued',depends_on:['wi_1'],attempt:0,result:'',review:''}
]);
if(byId('collabWorkItems').children.length!==2)
 throw Error('Work item cards were not rendered');
const first=byId('collabWorkItems').children[0];
const report=first.children.find(child=>child.className==='collab-work-details' &&
  child.children[0]?.textContent?.startsWith('Результат DeepSeek'));
if(!report)throw Error('Work item report must be expandable');
report.open=true;
report.listeners.toggle();
context.renderWorkItems('task_parallel',[
 {item_id:'wi_1',position:0,title:'Audit logs',instructions:'Read safe logs',
  state:'accepted',depends_on:[],attempt:1,result:'Observed two events.',review:'Accepted'},
]);
const refreshed=byId('collabWorkItems').children[0].children.find(
  child=>child.className==='collab-work-details'&&
    child.children[0]?.textContent?.startsWith('Результат DeepSeek'));
if(!refreshed?.open)throw Error('Expanded work report collapsed after status refresh');
byId('collabStrategy').value='dialog';
byId('collabStrategy').listeners.change();
if(byId('collabCyclesLabel').hidden)throw Error('Dialog must offer cycle selector');
byId('collabStrategy').value='parallel';
byId('collabStrategy').listeners.change();
if(!byId('collabCyclesLabel').hidden)
 throw Error('Parallel planning must hide unused dialog cycle selector');

"""
        run=subprocess.run(["node","-e",script],
                           input=json.dumps([html, app]),
                           capture_output=True,text=True,encoding="utf-8",timeout=20)
        self.assertEqual(run.returncode,0,run.stderr)


if __name__=="__main__":
    unittest.main()
