"use strict";
/* Cybernova: local ChatGPT-like chat UI. No external JS, no model HTML. */
const $=id=>document.getElementById(id);
const state={sessionId:null,running:false,turns:0};
const descriptions={
  gateway_status:"Шлюз MCP",
  local_webui_health:"Проверка интерфейса",
  http_get:"Публичный GET",
  http_header_review:"Анализ HTTP-заголовков",
  ip_network_summary:"Расчёт подсети",
  python_static_review:"Анализ Python",
};
const node=(tag,cls,txt)=>{
  const n=document.createElement(tag);
  if(cls)n.className=cls;
  if(txt!==undefined)n.textContent=txt;
  return n;
};
function toBottom(){
  const scroller=document.querySelector(".conversation");
  scroller.scrollTop=scroller.scrollHeight;
}
function renderMessage(role,content,pending=false){
  const wrap=node("article","chat-msg "+(role==="user"?"from-user":"from-agent")+(pending?" working":""));
  const meta=node("div","message-meta");
  meta.append(node("span","avatar "+(role==="user"?"user":""),role==="user"?"U":"◈"),
              node("span","",role==="user"?"Вы":"Cybernova"));
  const body=node("div","message-body",content);
  wrap.append(meta,body);
  $("messages").append(wrap);toBottom();
  return {wrap,body};
}
function makeToolDetails(event){
  const d=node("details","");
  const sum=node("summary","",event.name||event.type||"Событие");
  if(event.is_error)sum.textContent+=" · Ошибка";
  d.append(sum,node("pre","",JSON.stringify({
    input:event.arguments||{},
    result:event.result||event.message||{},
  },null,2)));
  return d;
}
function approvalCard(event){
  const card=node("div","approval-card");
  const title=node("div","approval-title","Qwen запрашивает разрешение");
  const name=node("div","approval-tool",event.name||"MCP-инструмент");
  const explanation=[
    event.purpose||"Qwen предложила этот вызов для текущей задачи.",
    event.tool_description ? "Описание функции: "+event.tool_description : "",
    event.reason||"Необходимо отдельное разрешение",
    "Ни один вызов не был выполнен.",
  ].filter(Boolean).join("\n");
  const reason=node("p","approval-reason",explanation);
  const preview=node("pre","approval-args",JSON.stringify(event.arguments||{},null,2));
  const buttons=node("div","approval-buttons");
  const yes=node("button","approval-yes","Разрешить один раз");
  const no=node("button","approval-no","Отклонить");
  yes.type="button";no.type="button";
  const requestId=event.request_id;
  yes.addEventListener("click",()=>decideAction(requestId,"approve",card));
  no.addEventListener("click",()=>decideAction(requestId,"deny",card));
  buttons.append(yes,no);
  card.append(title,name,reason,preview,buttons);
  return card;
}
async function decideAction(requestId,decision,card){
  if(state.running||!state.sessionId)return;
  busy(true);
  card.querySelectorAll("button").forEach(button=>button.disabled=true);
  try{
    const reply=await requestJson("/api/approve",{
      session_id:state.sessionId,request_id:requestId,decision:decision
    });
    card.querySelector(".approval-buttons")?.remove();
    card.append(node("div","approval-state",
      decision==="approve"?"Разрешение использовано. Инструмент вызван.":"Действие отклонено."));
    if(decision==="approve"){
      state.turns=reply.turn||state.turns+1;
      const result=renderMessage("assistant",reply.answer||"Вызов завершён.");
      showEvents(reply.events,reply.tool_calls,reply.selected_by,result);
      void loadFollowups(state.sessionId,state.turns,result);
    }else{
      renderMessage("assistant","Действие отклонено. Инструмент не запускался.");
    }
  }catch(err){
    card.append(node("div","approval-error","Ошибка: "+String(err.message||err)));
    card.querySelectorAll("button").forEach(button=>button.disabled=false);
  }finally{
    busy(false);toBottom();
  }
}
function showEvents(events,count,mode,reply){
  const inspector=$("runList");
  inspector.replaceChildren();
  $("runCount").textContent=count?count+" вызовов":"Нет вызовов";
  if(!events || !events.length){
    inspector.append(node("p","muted","На этом шаге инструментов не было."));
    return;
  }
  let inline=null;
  if(reply)inline=node("div","inline-tools");
  for(const e of events){
    const item=makeToolDetails(e);
    inspector.append(item);
    if(inline)inline.append(makeToolDetails(e));
  }
  if(inline)reply.wrap.append(inline);
  if(reply){
    for(const event of events){
      if(event.type==="approval_required"&&event.request_id){
        reply.wrap.append(approvalCard(event));
      }else if(event.type==="scope_change_required"){
        const notice=node("div","approval-card scope-notice");
        notice.append(node("div","approval-title","Нужно расширить область доступа"),
          node("p","approval-reason","Qwen запросила внешний ресурс, которого нет в разрешённом scope MCP. "+
            "Добавить домен может только администратор системы. Самостоятельного обхода ограничений нет."),
          node("pre","approval-args",JSON.stringify(event.arguments||{},null,2)));
        reply.wrap.append(notice);
      }
    }
  }
  if(reply && count){
    const receipt=node("div","tool-receipt");
    receipt.append(node("strong","",count+" реальных вызовов MCP"),
      node("span","",mode==="native"?"· выбраны Qwen (native tools)":
        mode==="qwen_json_fallback"?"· план выбрала Qwen": "· выбран контроллером"));
    reply.wrap.insertBefore(receipt,inline);
  }
}
function renderFollowups(reply, questions){
  if(!Array.isArray(questions)||!questions.length)return;
  const box=node("div","followup-box");
  box.append(node("div","followup-label","Продолжить по теме"));
  const options=node("div","followup-questions");
  for(const text of questions.slice(0,3)){
    if(typeof text!=="string"||text.length>160)continue;
    const button=node("button","followup-question",text);
    button.type="button";
    button.dataset.prompt=text;
    options.append(button);
  }
  box.append(options);
  reply.wrap.append(box);
  toBottom();
}
async function loadFollowups(sid,turn,reply){
  try{
    const result=await requestJson("/api/followups",{session_id:sid,turn:turn});
    // Ignore late completions after a new message or session reset.
    if(state.sessionId!==sid||state.turns!==turn||!reply.wrap.isConnected)return;
    if(result.source!=="qwen"||result.turn!==turn)return;
    renderFollowups(reply,result.questions);
  }catch(_){
    // Suggestions are optional; a timeout must not affect the chat.
  }
}
function busy(on){
  state.running=on;
  $("sendButton").disabled=on;
  $("messageInput").disabled=on;
  $("newSession").disabled=on;
  $("sendStatus").textContent=on?"Qwen выполняет запрос…":"Готов";
}
async function requestJson(path,data){
  const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},
     body:JSON.stringify(data),cache:"no-store"});
  let body;
  try{body=await response.json();}catch(_){throw Error("Некорректный ответ сервера: "+response.status);}
  if(!response.ok)throw Error(body.detail||"HTTP "+response.status);
  return body;
}
async function send(){
  const text=$("messageInput").value.trim();
  if(!text||state.running)return;
  $("welcome")?.remove();
  renderMessage("user",text);
  $("messageInput").value="";
  const pending=renderMessage("assistant","Qwen формирует ответ…",true);
  busy(true);
  try{
    const result=await requestJson("/api/chat",{
      session_id:state.sessionId,message:text,
    });
    state.sessionId=result.session_id;
    state.turns=result.turn||state.turns+1;
    pending.wrap.classList.remove("working");
    pending.body.textContent=result.answer||"Ответ модели пуст.";
    showEvents(result.events,result.tool_calls,result.selected_by,pending);
    // Generate contextual next questions independently; do not delay Qwen reply.
    // A pending approval is the next user decision, not a generic follow-up.
    if(!result.events?.some(e=>e.type==="approval_required")){
      void loadFollowups(result.session_id,result.turn,pending);
    }
    if(state.turns===1){
      const label=text.length>32?text.substring(0,31)+"…":text;
      $("sessionItem").textContent=label;
    }
    $("sendStatus").textContent=result.tool_calls?
      result.tool_calls+" вызовов MCP":"Ответ без инструментов";
  }catch(exc){
    pending.wrap.classList.remove("working");
    pending.body.textContent="Ошибка: "+String(exc.message||exc);
    $("sendStatus").textContent="Ошибка подключения";
  }finally{
    busy(false);$("messageInput").focus();toBottom();
  }
}
function renderTools(tools,automatic=[]){
  const container=$("toolList");
  container.replaceChildren();
  $("toolCount").textContent=String(tools.length);
  if(!tools.length){
    container.append(node("p","muted","MCP сейчас недоступен."));
    return;
  }
  const allowed=new Set(automatic);
  for(const name of tools){
    const row=node("div","tool-item");
    const label=node("code","",name);
    label.title=descriptions[name]||"Подключённый MCP-инструмент";
    const indicator=node("span","tool-access",allowed.has(name)?"AUTO":"ASK");
    indicator.title=allowed.has(name)?"Qwen может запустить без подтверждения":
      "Qwen может выбрать; для исполнения потребуется подтверждение";
    row.append(label,indicator);
    container.append(row);
  }
}
async function status(){
  try{
    const response=await fetch("/api/status",{cache:"no-store"});
    if(!response.ok)throw Error("HTTP "+response.status);
    const info=await response.json();
    const ready=!!info.ollama_ready&&!!info.mcp_ready;
    $("modelName").textContent=info.model||"Qwen";
    $("ollamaState").textContent=info.ollama_ready?"Qwen подключена":"Qwen недоступна";
    $("mcpState").textContent=info.mcp_ready?"MCP подключён":"MCP недоступен";
    $("backendDot").className="dot "+(ready?"ok":"bad");
    $("backendStatus").textContent=ready?"Qwen и MCP подключены":
      info.ollama_ready?"Qwen подключена · MCP недоступен":"Проверь Ollama";
    renderTools(Array.isArray(info.tools)?info.tools:[],info.auto_executable||[]);
  }catch(_){
    $("backendDot").className="dot bad";
    $("backendStatus").textContent="Нет подключения к серверу";
    $("ollamaState").textContent="Qwen недоступна";
    $("mcpState").textContent="MCP недоступен";
    renderTools([]);
  }
}
async function reset(){
  if(state.running)return;
  if(state.sessionId){
    try{await requestJson("/api/reset",{session_id:state.sessionId});}
    catch(exc){$("sendStatus").textContent="Ошибка сброса сессии";return;}
  }
  state.sessionId=null;
  state.turns=0;
  $("sessionItem").textContent="Новый диалог";
  $("messages").replaceChildren(window.cybernovaWelcome.cloneNode(true));
  showEvents([],0,"none");
  $("messageInput").value="";
  $("sidebar").classList.remove("open");
  $("sendStatus").textContent="Готов";
}
function toolsPanel(show){
  $("inspector").hidden= !show;
  if(show)status();
}
function init(){
  window.cybernovaWelcome=$("welcome").cloneNode(true);
  $("sendButton").addEventListener("click",send);
  $("messageInput").addEventListener("keydown",e=>{
    if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send();}
  });
  $("newSession").addEventListener("click",reset);
  $("refreshStatus").addEventListener("click",status);
  $("navTools").addEventListener("click",()=>toolsPanel($("inspector").hidden));
  $("navChat").addEventListener("click",()=>toolsPanel(false));
  $("menuToggle").addEventListener("click",()=>$("sidebar").classList.toggle("open"));
  $("sessionItem").addEventListener("click",()=>$("sidebar").classList.remove("open"));
  $("messages").addEventListener("click",e=>{
    const sample=e.target.closest("[data-prompt]");
    if(sample&&!state.running){
      $("messageInput").value=sample.dataset.prompt;send();
    }
  });
  status();
}
document.addEventListener("DOMContentLoaded",init);
