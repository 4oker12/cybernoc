"use strict";
/* Cybernova local console: plain DOM only, no remote scripts, no HTML from models. */
const $ = id => document.getElementById(id);
const state = {sessionId: null, running: false, turns: 0};
const knownTools = {
  gateway_status:"Состояние шлюза",
  local_webui_health:"Диагностика WebUI",
  http_get:"Публичный HTTP GET",
  http_header_review:"Анализ заголовков",
  ip_network_summary:"Анализ CIDR",
  python_static_review:"Статический анализ Python"
};

function el(tag, className, text){
  const node=document.createElement(tag);
  if(className)node.className=className;
  if(text!==undefined)node.textContent=text;
  return node;
}
function scrollBottom(){
  const c=document.querySelector(".conversation");
  c.scrollTop=c.scrollHeight;
}
function renderMessage(who, content, pending=false){
  const wrap=el("article","chat-msg "+(who==="user"?"from-user":"from-agent")+(pending?" working":""));
  const meta=el("div","message-meta");
  const avatar=el("span","avatar "+(who==="user"?"user":""),who==="user"?"U":"◈");
  const author=el("span","",who==="user"?"Вы":"CYBERNOVA / QWEN");
  meta.append(avatar,author);
  const body=el("div","message-body",content);
  wrap.append(meta,body);
  $("messages").append(wrap);
  scrollBottom();
  return {wrap,body};
}
function showEvents(events, toolCount, selectedBy){
  const list=$("runList");list.replaceChildren();
  $("runCount").textContent=toolCount?String(toolCount)+" вызовов":"0 вызовов";
  if(!events || !events.length){
    list.append(el("p","empty-run","Модель ответила без вызова инструментов. Отчёт сформирован из доступного контекста."));
    return;
  }
  for(const item of events){
    const details=el("details","run-entry");
    const title=el("summary",item.is_error?"failed":"");
    title.append(el("span","",item.name || item.type || "diagnostic"));
    const code=el("span","",item.type==="tool_result"?(item.is_error?"ERROR":"CALLED"):"EVENT");
    title.append(code);
    const data={arguments:item.arguments||{},result:item.result||item.message||{},selected_by:selectedBy||"none"};
    const pre=el("pre","",JSON.stringify(data,null,2));
    details.append(title,pre);list.append(details);
  }
}
function receipt(message, count, selectedBy){
  if(!count)return;
  const row=el("div","tool-receipt");
  row.append(el("strong","",String(count)+" реальных вызовов MCP"));
  row.append(el("span",""," · выбор: "+(selectedBy==="native"?"Qwen tool_calls":selectedBy==="qwen_json_fallback"?"Qwen JSON plan":selectedBy)));
  message.wrap.append(row);
}
function setBusy(value){
  state.running=value;
  $("sendButton").disabled=value;
  $("messageInput").disabled=value;
  $("forceTools").disabled=value;
  $("publicGet").disabled=value;
  $("sendStatus").textContent=value?"Запрос выполняется…":"Готов к запросу";
}
async function api(path,payload){
  const res=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload),cache:"no-store"});
  let body;
  try{body=await res.json();}catch(_){throw new Error("Сервер вернул не-JSON ответ ("+res.status+")");}
  if(!res.ok)throw new Error(typeof body.detail==="string"?body.detail:"HTTP "+res.status);
  return body;
}
async function send(){
  const text=$("messageInput").value.trim();
  if(!text || state.running)return;
  if($("welcome"))$("welcome").remove();
  const publicGet=$("publicGet").checked;
  const forceTools=$("forceTools").checked;
  if(publicGet){
    // Explicit, one-turn opt in. No future turn inherits HTTP access.
    $("publicGet").checked=false;
  }
  renderMessage("user",text);
  $("messageInput").value="";
  const pending=renderMessage("assistant","Qwen анализирует запрос",true);
  const started=performance.now();
  setBusy(true);
  const dots=setInterval(()=>{
    const seconds=Math.round((performance.now()-started)/1000);
    pending.body.textContent="Qwen анализирует запрос · "+seconds+" сек.";
  },1000);
  try{
    const result=await api("/api/chat",{
      session_id:state.sessionId,
      message:text,
      public_get:publicGet,
      force_tools:forceTools
    });
    state.sessionId=result.session_id;
    state.turns=result.turn||state.turns+1;
    pending.wrap.classList.remove("working");
    pending.body.textContent=result.answer || "(Пустой ответ модели)";
    receipt(pending,result.tool_calls,result.selected_by);
    showEvents(result.events,result.tool_calls,result.selected_by);
    $("sessionLabel").textContent="Диалог · "+state.turns+" запросов";
    $("sendStatus").textContent=result.tool_calls?
      String(result.tool_calls)+" вызовов MCP":"Ответ без инструментов";
  }catch(err){
    pending.wrap.classList.remove("working");
    pending.body.textContent="Ошибка запроса: "+(err.message||String(err));
    $("sendStatus").textContent="Ошибка подключения";
  }finally{
    clearInterval(dots);
    setBusy(false);
    $("messageInput").focus();
    scrollBottom();
  }
}
function renderTools(names){
  const list=$("toolList");list.replaceChildren();
  $("toolCount").textContent=String(names.length);
  if(!names.length){
    list.append(el("span","muted","MCP недоступен или tools/list пуст."));
    return;
  }
  for(const name of names){
    const item=el("div","tool-item");
    const label=el("code","",name);
    label.title=knownTools[name]||"Неизвестный инструмент — не разрешён агенту";
    item.append(label,el("span","tool-dot"));
    list.append(item);
  }
}
async function updateStatus(){
  try{
    const res=await fetch("/api/status",{cache:"no-store"});
    if(!res.ok)throw new Error("HTTP "+res.status);
    const st=await res.json();
    $("modelName").textContent=st.model||"Qwen";
    $("ollamaState").textContent=st.ollama_ready?"ONLINE":"OFFLINE";
    $("mcpState").textContent=st.mcp_ready?"ONLINE":"OFFLINE";
    $("ollamaState").className="service-state "+(st.ollama_ready?"ok":"bad");
    $("mcpState").className="service-state "+(st.mcp_ready?"ok":"bad");
    const ok=st.ollama_ready && st.mcp_ready;
    $("backendStatus").textContent=ok?"Модель и MCP доступны":
       st.ollama_ready?"Модель доступна · MCP недоступен":"Проверить Ollama";
    $("backendDot").className="pulse "+(ok?"ok":"bad");
    renderTools(Array.isArray(st.tools)?st.tools:[]);
  }catch(err){
    $("backendStatus").textContent="Сервер недоступен";
    $("backendDot").className="pulse bad";
    $("ollamaState").textContent="—";
    $("mcpState").textContent="—";
    renderTools([]);
  }
}
async function resetSession(){
  if(state.running)return;
  if(state.sessionId){
    try{await api("/api/reset",{session_id:state.sessionId});}
    catch(err){$("sendStatus").textContent="Не удалось сбросить сессию";return;}
  }
  state.sessionId=null;state.turns=0;
  $("sessionLabel").textContent="Новый диалог";
  $("messages").replaceChildren();
  $("messages").append(buildWelcome());
  showEvents([],0,"none");
  $("messageInput").value="";
  $("publicGet").checked=false;
}
function buildWelcome(){
  // Re-using the initial welcome node keeps the same greeting without
  // interpreting untrusted model HTML. It's cached on startup.
  const template=window.cybernovaWelcomeTemplate;
  return template.cloneNode(true);
}
function bindSuggestions(){
  $("messages").addEventListener("click",event=>{
    const button=event.target.closest("[data-prompt]");
    if(!button)return;
    $("messageInput").value=button.dataset.prompt;
    send();
  });
}
function setInspectorVisible(visible){
  document.body.classList.toggle("show-inspector",visible);
  $("navTools").classList.toggle("active",visible);
  $("navChat").classList.toggle("active",!visible);
  if(visible)updateStatus();
}
function initialize(){
  window.cybernovaWelcomeTemplate=$("welcome").cloneNode(true);
  $("sendButton").addEventListener("click",send);
  $("messageInput").addEventListener("keydown",event=>{
    if(event.key==="Enter"&&!event.shiftKey){
      event.preventDefault();send();
    }
  });
  $("newSession").addEventListener("click",resetSession);
  $("refreshStatus").addEventListener("click",updateStatus);
  $("navTools").addEventListener("click",()=>setInspectorVisible(true));
  $("navChat").addEventListener("click",()=>setInspectorVisible(false));
  bindSuggestions();
  updateStatus();
}
document.addEventListener("DOMContentLoaded",initialize);
