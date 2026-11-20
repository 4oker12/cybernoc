"use strict";
/* Cybernova: local ChatGPT-like chat UI. No external JS, no model HTML. */
const $=id=>document.getElementById(id);
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const state={sessionId:null,taskId:null,lastSeq:0,running:false,turns:0,
  uploadLimit:MAX_UPLOAD_BYTES,mode:"qwen",qwenModel:"Активная модель",
  gptThreadId:null,gptConnected:false,gptPlanUsage:false,
  researchScope:{hosts:[],capture_detail:"evidence"},profileSettings:null,
  collabRun:null,collabLooping:false,collabStopRequested:false};
const descriptions={
  gateway_status:"Шлюз MCP",
  local_webui_health:"Проверка интерфейса",
  http_get:"Публичный GET",
  http_header_review:"Анализ HTTP-заголовков",
  ip_network_summary:"Расчёт подсети",
  python_static_review:"Анализ Python",
};
function displayModelName(modelId){
  const names={
    "deepseek-flash":"DeepSeek Flash",
    "deepseek-v4-pro":"DeepSeek V4 Pro",
    "brianmatzelle/qwen3-coder-heretic:30b":"Qwen3-Coder Heretic 30B",
    "cybernova-security:30b":"Qwen Heretic 30B",
  };
  return names[modelId]||modelId||"Активная модель";
}
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
function setFormatted(body,content){
  if(typeof window.CybernovaMarkdown?.render==="function"){
    body.replaceChildren(window.CybernovaMarkdown.render(String(content)));
  }else{body.textContent=String(content);}
}
function renderMessage(role,content,pending=false,containerId="messages"){
  const author=role==="chatgpt"?"ChatGPT":role==="user"?"Вы":state.qwenModel||"Исследователь";
  const wrap=node("article","chat-msg "+
    (role==="user"?"from-user":role==="chatgpt"?"from-chatgpt":"from-agent")+
    (pending?" working":""));
  const meta=node("div","message-meta");
  meta.append(node("span","avatar "+(role==="user"?"user":""),role==="user"?"U":role==="chatgpt"?"G":"◈"),
              node("span","",author));
  const body=node("div","message-body");
  if(role==="user"){body.textContent=String(content);}
  else{setFormatted(body,content);}
  wrap.append(meta,body);
  $(containerId).append(wrap);toBottom();
  return {wrap,body};
}
function makeToolDetails(event){
  const d=node("details","");
  d.open=!!state.profileSettings?.ui?.show_technical_details;
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
  const title=node("div","approval-title","Модель запрашивает разрешение");
  const name=node("div","approval-tool",event.name||"MCP-инструмент");
  const explanation=[
    event.purpose||"Модель предложила этот вызов для текущей задачи.",
    event.tool_description ? "Описание функции: "+event.tool_description : "",
    event.reason||"Необходимо отдельное разрешение",
    "Ни один вызов не был выполнен.",
  ].filter(Boolean).join("\n");
  const reason=node("p","approval-reason",explanation);
  const preview=node("pre","approval-args",JSON.stringify(event.arguments||{},null,2));
  const buttons=node("div","approval-buttons");
  const yes=node("button","approval-yes","Разрешить");
  const no=node("button","approval-no","Отклонить");
  const consult=node("button","approval-no","Обсудить с ChatGPT");
  yes.type="button";no.type="button";consult.type="button";
  yes.title="Одно конкретное действие с показанными параметрами. Не расширяет scope.";
  const requestId=event.request_id;
  yes.addEventListener("click",()=>decideAction(requestId,"approve",card));
  no.addEventListener("click",()=>decideAction(requestId,"deny",card));
  consult.addEventListener("click",async()=>{
    const packet=[
      "Cybernova — запрос модели на разрешение действия.",
      "Цель: "+(event.purpose||"Не указана"),
      "Инструмент: "+(event.name||"Неизвестен"),
      "Описание: "+(event.tool_description||"Не указано"),
      "Основание запроса: "+(event.reason||"Не указано"),
      "Параметры (секреты скрыты): "+JSON.stringify(event.arguments||{},null,2),
      "Статус: НЕ ВЫПОЛНЕНО. Ожидает решения.",
      "Проанализируй необходимость, последствия, границы полномочий и риски.",
      "Дай рекомендацию: разрешить, отклонить или разрешить с уточнением."
    ].join("\n");
    try{
      await navigator.clipboard.writeText(packet);
      consult.textContent="Скопировано для ChatGPT";
    }catch(_){
      const fallback=node("textarea","approval-args");
      fallback.value=packet;
      fallback.rows=8;
      fallback.setAttribute("aria-label","Запрос для ChatGPT — выдели и скопируй");
      card.append(fallback);
      fallback.focus();fallback.select();
      consult.textContent="Скопируй выделенный текст";
    }
  });
  buttons.append(yes,no,consult);
  card.append(title,name,reason,preview,
    node("div","approval-state","Ожидает решения. Один запрос = одно конкретное действие."),
    buttons);
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
          node("p","approval-reason","Модель запросила внешний ресурс, которого нет в разрешённом scope MCP. "+
            "Добавить домен может только администратор системы. Самостоятельного обхода ограничений нет."),
          node("pre","approval-args",JSON.stringify(event.arguments||{},null,2)));
        reply.wrap.append(notice);
      }
    }
  }
  if(reply && count){
    const receipt=node("div","tool-receipt");
    receipt.append(node("strong","",count+" реальных вызовов MCP"),
      node("span","",mode==="native"?"· выбрала модель (native tools)":
        mode==="model_json_fallback"?"· план выбрала модель": "· выбран контроллером"));
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
function kindForFile(file,source){
  const name=file.name.toLowerCase();
  if(/\.(pcap|cap)$/.test(name))return "pcap";
  if(/\.har$/.test(name))return "har";
  if(/\.js$/.test(name))return "javascript";
  if(/\.py$/.test(name))return "python";
  if(/\.(log|txt)$/.test(name))return "log";
  if(/\.(conf|cfg|ini|yaml|yml|env|toml)$/.test(name))return "config";
  if(/\.(pem|crt)$/.test(name))return "tls";
  if(/(?:package-lock|npm-shrinkwrap|sbom|composer|yarn|requirements)/.test(name))return "dependencies";
  if(/\.(lock|mod)$/.test(name))return "dependencies";
  if(/\.json$/.test(name)){
    try{
      const data=JSON.parse(source);
      if(data?.log?.entries)return "har";
      if(data?.openapi||data?.swagger)return "openapi";
      if(data?.packages||data?.dependencies||data?.components)return "dependencies";
    }catch(_){}
  }
  return null;
}
function readSelectedFile(file,binary){
  return new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onerror=()=>reject(Error("Ошибка чтения файла"));
    reader.onload=()=>{
      const result=String(reader.result||"");
      resolve(binary?result.split(",").slice(1).join(","):result);
    };
    if(binary)reader.readAsDataURL(file);
    else reader.readAsText(file,"utf-8");
  });
}
async function importArtifact(file){
  if(!file||state.running)return;
  if(file.size>state.uploadLimit){
    $("uploadStatus").textContent="Файл слишком большой (максимум "+
      Math.floor(state.uploadLimit/(1024*1024))+" МиБ)";
    return;
  }
  const binary=/\.(pcap|cap)$/i.test(file.name);
  $("uploadStatus").textContent="Анализируем файл локально…";
  busy(true);
  $("artifactFile").disabled=true;
  try{
    const content=await readSelectedFile(file,binary);
    const kind=kindForFile(file,content);
    if(!kind)throw Error("Формат не распознан. Используй .har, .js, .py, .json, .log, .conf, .pcap или .pem");
    const result=await requestJson("/api/import",{
      session_id:state.sessionId,kind,content
    });
    state.sessionId=result.session_id;
    state.taskId=result.task_id||state.taskId;
    void refreshChatGPT();
    void refreshTaskList();
    $("welcome")?.remove();
    renderMessage("user","Импортирован файл: "+file.name+
      "\nТип: "+kind+" · SHA-256: "+result.source_sha256.slice(0,16)+
      "\nСырые данные не сохраняются.");
    $("uploadStatus").textContent=file.name+" · обработан офлайн";
    $("messageInput").value="Проанализируй загруженный артефакт "+result.artifact_id+
      ". Сам выбери доступные traffic_* и research_* инструменты. "+
      "Покажи факты, гипотезы, взаимосвязи и следующие проверки. "+
      "Не называй уязвимость доказанной без подтверждения.";
  }catch(exc){
    $("uploadStatus").textContent="Ошибка импорта: "+String(exc.message||exc).slice(0,180);
  }finally{
    busy(false);
    $("artifactFile").disabled=false;
    $("artifactFile").value="";
    $("messageInput").focus();
  }
}
function busy(on){
  state.running=on;
  $("sendButton").disabled=on;
  $("messageInput").disabled=on;
  $("newSession").disabled=on;
  $("artifactFile").disabled=on;
  $("sendStatus").textContent=on?(state.mode==="gpt"?"ChatGPT отвечает…":"Модель выполняет запрос…"):"Готов";
  $("modeQwen").disabled=on;
  $("modeChatGPT").disabled=on;
  $("modeCollab").disabled=on;
  $("gptTopModel").disabled=on||!state.gptConnected||!state.gptPlanUsage||!$("gptTopModel").options.length;
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
  if(state.mode==="gpt")return sendGPT();
  const text=$("messageInput").value.trim();
  if(!text||state.running)return;
  $("welcome")?.remove();
  renderMessage("user",text);
  $("messageInput").value="";
  const pending=renderMessage("assistant",(state.qwenModel||"Модель")+" формирует ответ…",true);
  busy(true);
  try{
    const result=await requestJson("/api/chat",{
      session_id:state.sessionId,message:text,
    });
    state.sessionId=result.session_id;
    state.taskId=result.task_id||state.taskId;
    state.lastSeq=Math.max(state.lastSeq,result.event_seq||0);
    state.turns=result.turn||state.turns+1;
    pending.wrap.classList.remove("working");
    setFormatted(pending.body,result.answer||"Ответ модели пуст.");
    showEvents(result.events,result.tool_calls,result.selected_by,pending);
    // Generate contextual next questions independently; do not delay the model reply.
    // A pending approval is the next user decision, not a generic follow-up.
    if(!result.events?.some(e=>e.type==="approval_required")){
      void loadFollowups(result.session_id,result.turn,pending);
    }
    if(result.task_id)void refreshTaskList();
    if(result.events?.some(e=>e.name==="comm_request_review"&&e.result?.ok)){
      showTaskStatus("needs_review");
    }else{
      showTaskStatus("completed");
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
function gptWelcome(){
  $("gptMessages").replaceChildren(window.cybernovaGptWelcome.cloneNode(true));
}
function setMode(mode){
  if(state.running || !["qwen","gpt","collab"].includes(mode))return;
  state.mode=mode;
  const qwen=mode==="qwen", gpt=mode==="gpt", collab=mode==="collab";
  for(const [id,isActive] of [
    ["modeQwen",qwen],["modeChatGPT",gpt],["modeCollab",collab]
  ]){
    $(id).classList.toggle("selected",isActive);
    $(id).setAttribute("aria-pressed",String(isActive));
  }
  $("messages").hidden=!qwen;
  $("gptMessages").hidden=!gpt;
  $("collabMessages").hidden=!collab;
  $("qwenSidebar").hidden=!qwen;
  $("gptSidebar").hidden=!gpt;
  $("collabSidebar").hidden=!collab;
  $("gptTopModel").hidden=!gpt;
  $("modelName").hidden=gpt;
  $("modelName").textContent=collab?"ChatGPT ↔ DeepSeek":state.qwenModel;
  document.querySelector(".connection-label").hidden=!qwen;
  document.querySelector(".upload-button").hidden=!qwen;
  document.querySelector(".auto-tools-label").hidden=!qwen;
  const composerArea=document.querySelector(".composer-area");
  if(composerArea)composerArea.hidden=collab;
  $("artifactFile").disabled=!qwen;
  $("messageInput").placeholder=qwen?"Сообщение исследовательской модели или задача…":"Сообщение ChatGPT…";
  $("uploadStatus").textContent=qwen?
    "Импорт файлов до "+Math.floor(state.uploadLimit/(1024*1024))+" МиБ · модель":
    "ChatGPT · история сохраняется локально";
  $("sendStatus").textContent=!qwen&&!state.gptConnected?
    "Подключи ChatGPT через «Аккаунт GPT»":"Готов";
  $("sidebar").classList.remove("open");
  if(gpt)void refreshGPTThreads();
  if(collab)void refreshCollabRuns();
  toBottom();
}
async function refreshGPTThreads(){
  try{
    const response=await fetch("/api/siwc/chats",{cache:"no-store"});
    if(!response.ok)return;
    const data=await response.json();
    const container=$("gptThreadList");
    container.replaceChildren();
    for(const item of data.threads||[]){
      const button=node("button","task-item"+(item.thread_id===state.gptThreadId?" selected":""));
      button.type="button";
      button.append(node("span","task-title",item.title||"Чат ChatGPT"));
      button.addEventListener("click",()=>openGPTThread(item.thread_id));
      container.append(button);
    }
    if(!container.childNodes.length)
      container.append(node("p","muted","Пока нет диалогов. Напиши первое сообщение."));
  }catch(_){}
}
async function openGPTThread(threadId){
  if(state.running)return;
  setMode("gpt");
  busy(true);
  try{
    const response=await fetch("/api/siwc/chat?thread_id="+encodeURIComponent(threadId),{cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw Error(data.detail||"Не удалось загрузить диалог");
    state.gptThreadId=threadId;
    $("gptMessages").replaceChildren();
    for(const m of data.messages||[]){
      renderMessage(m.role==="user"?"user":"chatgpt",m.content,false,"gptMessages");
    }
    const model=data.thread?.model;
    if(model&&[...$("gptTopModel").options].some(x=>x.value===model))
      $("gptTopModel").value=model;
    $("sidebar").classList.remove("open");
  }catch(err){
    $("sendStatus").textContent="Ошибка загрузки GPT: "+String(err.message||err);
  }finally{busy(false);toBottom();}
}
async function sendGPT(){
  const message=$("messageInput").value.trim();
  if(!message||state.running)return;
  if(!state.gptConnected||!state.gptPlanUsage){
    $("sendStatus").textContent="Открой «Аккаунт GPT» и подключи ChatGPT.";
    return;
  }
  const model=$("gptTopModel").value;
  if(!model){
    $("sendStatus").textContent="Выбери модель ChatGPT наверху.";
    return;
  }
  $("gptWelcome")?.remove();
  renderMessage("user",message,false,"gptMessages");
  $("messageInput").value="";
  const pending=renderMessage("chatgpt","ChatGPT формирует ответ…",true,"gptMessages");
  busy(true);
  try{
    const result=await requestJson("/api/siwc/chat",{
      thread_id:state.gptThreadId,model,message
    });
    state.gptThreadId=result.thread_id;
    pending.wrap.classList.remove("working");
    setFormatted(pending.body,result.answer||"Ответ модели пуст.");
    if(Array.isArray(result.tool_events)&&result.tool_events.length){
      const details=node("div","inline-tools");
      for(const event of result.tool_events){
        details.append(makeToolDetails({
          name:event.name,
          arguments:event.arguments||{},
          result:event.result||event.summary||{},
          is_error:typeof event.is_error==="boolean"?event.is_error:!event.ok,
        }));
      }
      pending.wrap.append(details);
    }
    $("sendStatus").textContent="Ответ ChatGPT · диалог сохранён"+
      (result.tool_events && result.tool_events.length ? " · инструментов: "+result.tool_events.length : "");
    void refreshGPTThreads();
  void refreshCollabRuns();
  }catch(err){
    pending.wrap.classList.remove("working");
    pending.body.textContent="Ошибка: "+String(err.message||err);
    $("sendStatus").textContent="Ошибка GPT";
  }finally{busy(false);$("messageInput").focus();toBottom();}
}

function showResearchScope(profile){
  const scope=profile||{hosts:[],capture_detail:"evidence"};
  state.researchScope=scope;
  $("researchTargets").value=(scope.hosts||[]).join("\n");
  $("captureDetail").value=scope.capture_detail||"evidence";
  const count=(scope.hosts||[]).length;
  $("scopeIndicator").textContent=count?count+" целей":"не выбран";
  $("scopeStatus").textContent=count?
    "Разрешённые цели: "+scope.hosts.join(", ")+". Активные действия согласуются отдельно.":
    "Объект не выбран. Укажи домен или IP и нажми «Применить».";
}
async function applyResearchScope(){
  if(state.running)return;
  const hosts=$("researchTargets").value.split(/[,;\n]+/)
    .map(x=>x.trim()).filter(Boolean);
  if(hosts.length>20){
    $("scopeStatus").textContent="Не больше 20 точных целей в одном профиле.";
    return;
  }
  $("applyResearchScope").disabled=true;
  $("scopeStatus").textContent="Проверяю и сохраняю профиль…";
  try{
    const result=await requestJson("/api/research/scope",{
      session_id:state.sessionId,hosts,capture_detail:$("captureDetail").value
    });
    state.sessionId=result.session_id;
    showResearchScope(result.scope);
    $("sendStatus").textContent="Объекты исследования заданы";
  }catch(err){
    $("scopeStatus").textContent="Ошибка настройки: "+String(err.message||err);
  }finally{
    $("applyResearchScope").disabled=false;
  }
}

async function refreshTaskList(){
  try{
    const response=await fetch("/api/comm/tasks",{cache:"no-store"});
    if(!response.ok)return;
    const body=await response.json();
    const list=$("taskList");
    list.replaceChildren();
    for(const task of (body.tasks||[]).slice(0,25)){
      const button=node("button","task-item"+(task.task_id===state.taskId?" selected":""));
      button.type="button";
      button.dataset.taskId=task.task_id;
      const text=node("span","task-title",task.title||"Исследование");
      const status=node("span","task-state",task.status||"idle");
      button.append(text,status);
      button.addEventListener("click",()=>resumeTask(task.task_id));
      list.append(button);
    }
    if(!list.childNodes.length)list.append(node("p","muted","Пока нет исследований."));
  }catch(_){}
}
function showTaskStatus(status){
  $("commState").textContent=status==="needs_review"?
    "Нужна рецензия ChatGPT":status==="running"?"Модель исследует":
    status==="queued"?"В очереди модели":status==="blocked"?"Задача остановлена":
    status==="completed"?"Исследование завершено":status||"Общая очередь";
}
function displayTaskEvent(message){
  if(!message)return;
  if(message.actor==="chatgpt"&&["feedback","instruction","result"].includes(message.kind)){
    renderMessage("chatgpt",message.body);
  }else if(message.actor==="human"&&message.kind==="feedback"){
    renderMessage("user",message.body);
  }else if(message.actor==="qwen"&&message.kind==="result"){
    renderMessage("assistant",message.body);
  }else if(message.actor==="qwen"&&message.kind==="request_review"){
    renderMessage("assistant","Запрос независимой рецензии ChatGPT: "+message.body);
  }else if(message.actor==="controller"&&message.kind==="system"){
    renderMessage("assistant","Состояние задачи: "+message.body);
  }
}
async function resumeTask(taskId){
  if(state.running)return;
  busy(true);
  try{
    const result=await requestJson("/api/comm/resume",{task_id:taskId});
    state.sessionId=result.session_id;
    state.taskId=result.task.task_id;
    showResearchScope(result.scope);
    lastGptReview=null;
    $("chatgptToQwen").disabled=true;
    void refreshChatGPT();
    state.turns=result.turn||0;
    state.lastSeq=0;
    $("messages").replaceChildren();
    const messages=result.messages||[];
    for(const message of messages){
      if(message.actor==="human"&&message.kind==="instruction"){
        renderMessage("user",message.body);
      }else{
        displayTaskEvent(message);
      }
      state.lastSeq=Math.max(state.lastSeq,message.seq||0);
    }
    $("sessionItem").textContent=result.task.title;
    showTaskStatus(result.task.status);
    $("sidebar").classList.remove("open");
    await refreshTaskList();
  }catch(err){
    $("sendStatus").textContent="Ошибка открытия задачи: "+String(err.message||err);
  }finally{
    busy(false);toBottom();
  }
}
async function pollTask(){
  if(!state.sessionId||!state.taskId||state.running)return;
  const sid=state.sessionId,task=state.taskId;
  try{
    const response=await fetch("/api/comm/events?session_id="+encodeURIComponent(sid)+
      "&after_seq="+state.lastSeq,{cache:"no-store"});
    if(!response.ok)return;
    const data=await response.json();
    if(state.sessionId!==sid||state.taskId!==task||state.running)return;
    for(const message of data.messages||[]){
      displayTaskEvent(message);
      state.lastSeq=Math.max(state.lastSeq,message.seq||0);
    }
    showTaskStatus(data.task?.status);
    if((data.messages||[]).length)void refreshTaskList();
  }catch(_){}
}

async function copyReviewPacket(){
  if(!state.sessionId||!state.taskId){
    $("reviewStatus").textContent="Сначала создай или открой исследовательскую задачу.";
    return;
  }
  const sid=state.sessionId;
  $("reviewStatus").textContent="Собираю журнал рецензии…";
  try{
    const response=await fetch("/api/comm/review-packet?session_id="+
      encodeURIComponent(sid),{cache:"no-store"});
    if(!response.ok)throw Error("HTTP "+response.status);
    const data=await response.json();
    if(state.sessionId!==sid)return;
    const packet=data.packet||"";
    if(!packet)throw Error("Пакет пустой");
    try{
      await navigator.clipboard.writeText(packet);
      $("reviewStatus").textContent="Пакет скопирован. Вставь в обычный ChatGPT.";
      $("reviewPacketText").hidden=true;
    }catch(_){
      const field=$("reviewPacketText");
      field.hidden=false;
      field.value=packet;
      field.focus();
      field.select();
      $("reviewStatus").textContent="Буфер обмена запрещён. Скопируй выделенный текст Ctrl+C.";
    }
  }catch(err){
    $("reviewStatus").textContent="Ошибка: "+String(err.message||err);
  }
}
async function showEvidenceJournal(){
  if(!state.sessionId||!state.taskId){
    $("reviewStatus").textContent="Открой исследовательскую задачу.";
    return;
  }
  const response=await fetch("/api/comm/evidence?session_id="+
    encodeURIComponent(state.sessionId),{cache:"no-store"});
  if(!response.ok){
    $("reviewStatus").textContent="Журнал недоступен (HTTP "+response.status+").";
    return;
  }
  const data=await response.json();
  const out=$("evidenceOutput");
  out.hidden=false;
  out.textContent=JSON.stringify({
    claimed_by_qwen_not_verified:data.claims||[],
    controller_tool_receipts:data.tool_receipts||[],
  },null,2);
}
async function submitReviewerFeedback(){
  if(!state.sessionId||!state.taskId){
    $("reviewStatus").textContent="Сначала открой задачу.";
    return;
  }
  const text=$("reviewFeedbackInput").value.trim();
  if(!text){
    $("reviewStatus").textContent="Вставь замечания ChatGPT перед отправкой.";
    return;
  }
  if(state.running)return;
  busy(true);
  const sid=state.sessionId;
  try{
    const result=await requestJson("/api/comm/reviewer-feedback",{
      session_id:sid,
      message:text,
      event_key:"ui_review_"+Date.now()+"_"+Math.random().toString(36).slice(2),
    });
    if(state.sessionId!==sid)return;
    renderMessage("user","Замечания рецензента (вручную):\n"+text);
    state.lastSeq=Math.max(state.lastSeq,result.event_seq||0);
    $("reviewFeedbackInput").value="";
    $("reviewStatus").textContent="Замечания переданы. Модель продолжит задачу из очереди.";
    showTaskStatus("queued");
    await refreshTaskList();
  }catch(err){
    $("reviewStatus").textContent="Ошибка отправки: "+String(err.message||err);
  }finally{busy(false);}
}
function renderTools(tools,automatic=[],availableScanners=[]){
  const container=$("toolList");
  container.replaceChildren();
  $("toolCount").textContent=String(tools.length);
  if(!tools.length){
    container.append(node("p","muted","MCP сейчас недоступен."));
    return;
  }
  const allowed=new Set(automatic);
  const availability=new Map((Array.isArray(availableScanners)?availableScanners:[])
    .filter(x=>x&&typeof x.tool==="string")
    .map(x=>[x.tool,!!x.installed]));
  for(const name of tools){
    const row=node("div","tool-item");
    const label=node("code","",name);
    label.title=descriptions[name]||"Подключённый MCP-инструмент";
    const missing=availability.has(name)&&!availability.get(name);
    const indicator=node("span","tool-access"+(missing?" tool-missing":""),
      missing?"MISSING":allowed.has(name)?"AUTO":"ASK");
    indicator.title=missing?"Сканер не установлен в текущем окружении":
      allowed.has(name)?"Модель может запустить без подтверждения":
      "Модель может выбрать; для исполнения потребуется подтверждение";
    row.append(label,indicator);
    container.append(row);
  }
}

let lastGptReview=null;
async function refreshChatGPT(){
  const statusLine=$("chatgptStatus");
  try{
    const response=await fetch("/api/siwc/status",{cache:"no-store"});
    if(!response.ok)throw Error("HTTP "+response.status);
    const data=await response.json();
    const connected=!!data.connected;
    $("chatgptConnect").hidden=connected;
    $("chatgptDisconnect").hidden=!connected;
    $("chatgptReview").disabled=!connected||!data.plan_usage||!state.taskId;
    const callbackResult=new URLSearchParams(window.location.search).get("chatgpt");
    if(callbackResult)window.history.replaceState(null,"",window.location.pathname);
    statusLine.textContent=connected?
      (data.plan_usage?"Подключён: "+(data.email||"аккаунт ChatGPT")+
         " · использование подписки разрешено":
       "Аккаунт подключён, но использование подписки не разрешено."):
      "Не подключён. Авторизация проходит в браузере OpenAI.";
    if(callbackResult==="error")statusLine.textContent+=" Последняя авторизация не завершилась.";
    const picker=$("chatgptModel");
    const topPicker=$("gptTopModel");
    const collaborationPicker=$("collabModel");
    const priorModel=topPicker.value||picker.value;
    picker.replaceChildren();
    topPicker.replaceChildren();
    collaborationPicker.replaceChildren();
    picker.disabled=true;
    topPicker.disabled=true;
    state.gptConnected=connected;
    state.gptPlanUsage=!!data.plan_usage;
    if(connected&&data.plan_usage){
      const list=await fetch("/api/siwc/models",{cache:"no-store"});
      const body=await list.json();
      if(!list.ok)throw Error(body.detail||"Не удалось получить модели");
      const models=Array.isArray(body.models)?body.models:[];
      for(const item of models){
        const option=document.createElement("option");
        option.value=item.slug;
        option.textContent=item.display_name||item.slug;
        picker.append(option);
        topPicker.append(option.cloneNode(true));
        collaborationPicker.append(option.cloneNode(true));
      }
      if(models.some(item=>item.slug===priorModel)){
        picker.value=priorModel;
        topPicker.value=priorModel;
        collaborationPicker.value=priorModel;
      }
      picker.disabled=!models.length;
      topPicker.disabled=!models.length;
      collaborationPicker.disabled=!models.length;
      $("chatgptReview").disabled=!models.length||!state.taskId;
      if(!models.length)statusLine.textContent+=" · Нет доступных моделей в аккаунте.";
      if(state.mode==="gpt")$("sendStatus").textContent=models.length?"Готов":"Для чата нет доступных моделей.";
    }else{
      topPicker.disabled=true;
      collaborationPicker.disabled=true;
      if(state.mode==="gpt")$("sendStatus").textContent="Открой «Аккаунт GPT» для подключения.";
    }
  }catch(err){
    statusLine.textContent="Ошибка ChatGPT: "+String(err.message||err);
    state.gptConnected=false;
    state.gptPlanUsage=false;
    $("gptTopModel").disabled=true;
    $("collabModel").disabled=true;
    $("chatgptReview").disabled=true;
  }
}
async function connectChatGPT(){
  // OpenAI's OSS flow only accepts loopback callback; a remote tunnel
  // hostname cannot receive that callback on the user's computer.
  const host=window.location.hostname;
  const port=Number(window.location.port);
  if(host!=="127.0.0.1" || ![18794,18795].includes(port)){
    $("chatgptStatus").textContent="Для входа откройте Cybernova через http://127.0.0.1:18795 после SSH-проброса с Vast. Ссылка Cloudflare для этого не подходит.";
    return;
  }
  try{
    $("chatgptStatus").textContent="Создаю одноразовый запрос авторизации…";
    const data=await requestJson("/api/siwc/start",{});
    if(data.callback_uri!==window.location.origin+"/auth/callback")
      throw Error("Откройте Web UI по адресу "+data.callback_uri.replace("/auth/callback","/"));
    window.location.assign(data.authorization_url);
  }catch(err){
    $("chatgptStatus").textContent="Ошибка подключения: "+String(err.message||err);
  }
}
async function disconnectChatGPT(){
  if(!window.confirm("Отключить аккаунт ChatGPT от Cybernova?"))return;
  try{
    const result=await requestJson("/api/siwc/disconnect",{});
    lastGptReview=null;
    $("chatgptToQwen").disabled=true;
    state.gptThreadId=null;
    gptWelcome();
    await refreshChatGPT();
    if(result.remote_revocation_warning)
      $("chatgptStatus").textContent+=" Отзыв удалённой сессии не подтверждён — проверьте соединения в настройках ChatGPT.";
  }catch(err){
    $("chatgptStatus").textContent="Не удалось отключить: "+String(err.message||err);
  }
}
async function reviewWithChatGPT(){
  if(!state.sessionId||!state.taskId){
    $("chatgptStatus").textContent="Откройте исследование модели перед рецензией.";
    return;
  }
  const model=$("chatgptModel").value;
  if(!model||state.running)return;
  const sid=state.sessionId, task=state.taskId;
  busy(true);
  $("chatgptStatus").textContent="Получаю пакет исследования…";
  try{
    const response=await fetch("/api/comm/review-packet?session_id="+
      encodeURIComponent(state.sessionId),{cache:"no-store"});
    const data=await response.json();
    if(!response.ok||!data.packet)throw Error("Пакет исследования недоступен");
    if(data.packet.length>12000)
      throw Error("Пакет больше 12 000 символов. Уменьшите объём перед отправкой в облако.");
    // Explicit user click; never upload task context automatically.
    $("chatgptStatus").textContent="Отправляю выбранную задачу в GPT для рецензии…";
    const answer=await requestJson("/api/siwc/review",{
      session_id:sid,model,prompt:data.packet
    });
    if(state.sessionId!==sid||state.taskId!==task||answer.task_id!==task){
      $("chatgptStatus").textContent="Рецензия сохранена в исходной задаче. Откройте её для просмотра.";
      return;
    }
    lastGptReview=answer.answer||null;
    state.lastSeq=Math.max(state.lastSeq,answer.event_seq||0);
    renderMessage("chatgpt",answer.answer||"Ответ GPT пуст.");
    $("chatgptToQwen").disabled=!lastGptReview;
    $("chatgptStatus").textContent="Рецензия GPT получена. Можно отправить её модели.";
  }catch(err){
    $("chatgptStatus").textContent="Ошибка рецензии: "+String(err.message||err);
  }finally{busy(false);}
}
async function forwardGPTtoQwen(){
  if(!lastGptReview||!state.sessionId||!state.taskId||state.running)return;
  busy(true);
  try{
    const response=await requestJson("/api/comm/reviewer-feedback",{
      session_id:state.sessionId,
      message:lastGptReview.slice(0,6000),
      event_key:"siwc_ui_"+Date.now()+"_"+Math.random().toString(36).slice(2),
    });
    state.lastSeq=Math.max(state.lastSeq,response.event_seq||0);
    $("chatgptToQwen").disabled=true;
    lastGptReview=null;
    $("chatgptStatus").textContent="Рецензия передана модели через общую очередь.";
    showTaskStatus("queued");
    void refreshTaskList();
  }catch(err){
    $("chatgptStatus").textContent="Ошибка передачи модели: "+String(err.message||err);
  }finally{busy(false);}
}

async function status(){
  try{
    const response=await fetch("/api/status",{cache:"no-store"});
    if(!response.ok)throw Error("HTTP "+response.status);
    const info=await response.json();
    if(Number.isSafeInteger(info.upload_limit_bytes)&&info.upload_limit_bytes>0)
      state.uploadLimit=info.upload_limit_bytes;
    const hosted=info.model_provider==="openai_compatible";
    const modelReady=hosted?!!info.model_remote_configured:!!info.ollama_ready;
    const ready=modelReady&&!!info.mcp_ready;
    state.qwenModel=displayModelName(info.model);
    if(state.mode==="qwen")$("modelName").textContent=state.qwenModel;
    $("ollamaState").textContent=hosted?"Облачная LLM настроена (не проверена)":
      info.ollama_ready?"Ollama подключена":"Ollama недоступна";
    $("mcpState").textContent=info.mcp_ready?"MCP подключён":"MCP недоступен";
    $("backendDot").className="dot "+(ready?"ok":"bad");
    $("backendStatus").textContent=hosted?
      (info.mcp_ready?"Облачная модель настроена · MCP подключён":"Облачная модель настроена · MCP недоступен"):
      ready?"Ollama и MCP подключены":
      info.ollama_ready?"Ollama подключена · MCP недоступен":"Проверь Ollama";
    renderTools(Array.isArray(info.tools)?info.tools:[],info.auto_executable||[],info.lab_scanners?.engines||[]);
    if(!state.taskId)showTaskStatus(info.communication?.enabled?"Общая очередь":"Шлюз недоступен");
  }catch(_){
    $("backendDot").className="dot bad";
    $("backendStatus").textContent="Нет подключения к серверу";
    $("ollamaState").textContent="Модель недоступна";
    $("mcpState").textContent="MCP недоступен";
    renderTools([]);
  }
}
async function reset(){
  if(state.running)return;
  if(state.mode==="collab"){
    await newCollab();
    return;
  }
  if(state.mode==="gpt"){
    state.gptThreadId=null;
    gptWelcome();
    $("messageInput").value="";
    $("sendStatus").textContent="Новый чат GPT";
    $("sidebar").classList.remove("open");
    $("messageInput").focus();
    await refreshGPTThreads();
    return;
  }
  if(state.sessionId){
    try{await requestJson("/api/reset",{session_id:state.sessionId});}
    catch(exc){$("sendStatus").textContent="Ошибка сброса сессии";return;}
  }
  state.sessionId=null;
  state.taskId=null;
  showResearchScope({hosts:[],capture_detail:"evidence"});
  lastGptReview=null;
  $("chatgptReview").disabled=true;
  $("chatgptToQwen").disabled=true;
  state.lastSeq=0;
  state.turns=0;
  showTaskStatus("Общая очередь");
  void refreshTaskList();
  $("sessionItem").textContent="Новый диалог";
  $("messages").replaceChildren(window.cybernovaWelcome.cloneNode(true));
  showEvents([],0,"none");
  $("messageInput").value="";
  $("uploadStatus").textContent="Импорт локальных артефактов";
  $("sidebar").classList.remove("open");
  $("sendStatus").textContent="Готов";
}
function toolsPanel(show){
  $("inspector").hidden= !show;
  if(show)status();
}
const DEFAULT_PROFILE_SETTINGS={
  user:{display_name:"",role:"",about:"",preferences:""},
  privacy:{share_with_researcher:true,share_with_chatgpt:true},
  researcher:{description:"",instructions:""},
  chatgpt:{description:"",instructions:""},
  ui:{theme:"light",density:"comfortable",font_scale:100,sidebar_width:300,chat_width:1040,show_technical_details:false},
};
function applyInterfaceSettings(ui){
  const root=document.documentElement;
  if(!root)return;
  root.dataset.theme=ui.theme==="dark"?"dark":"light";
  root.dataset.density=["compact","comfortable","relaxed"].includes(ui.density)?ui.density:"comfortable";
  root.style.setProperty("--font-scale",String((Number(ui.font_scale)||100)/100));
  root.style.setProperty("--sidebar-width",(Number(ui.sidebar_width)||300)+"px");
  root.style.setProperty("--chat-width",(Number(ui.chat_width)||1040)+"px");
}
function selectProfileTab(name){
  document.querySelectorAll("[data-profile-tab]").forEach(button=>{
    const active=button.dataset.profileTab===name;
    button.classList.toggle("active",active);
    button.setAttribute("aria-selected",String(active));
  });
  document.querySelectorAll("[data-profile-panel]").forEach(panel=>{
    panel.hidden=panel.dataset.profilePanel!==name;
  });
}
function populateProfileSettings(settings){
  const d=DEFAULT_PROFILE_SETTINGS;
  const value=settings||d;
  const user=value.user||d.user, privacy=value.privacy||d.privacy;
  const researcher=value.researcher||d.researcher, chatgpt=value.chatgpt||d.chatgpt;
  const ui=value.ui||d.ui;
  $("profileName").value=user.display_name||"";
  $("profileRole").value=user.role||"";
  $("profileAbout").value=user.about||"";
  $("profilePreferences").value=user.preferences||"";
  $("shareResearcher").checked=privacy.share_with_researcher!==false;
  $("shareChatGPT").checked=privacy.share_with_chatgpt!==false;
  $("researcherDescription").value=researcher.description||"";
  $("researcherInstructions").value=researcher.instructions||"";
  $("chatgptDescription").value=chatgpt.description||"";
  $("chatgptInstructions").value=chatgpt.instructions||"";
  $("uiTheme").value=ui.theme||"light";
  $("uiDensity").value=ui.density||"comfortable";
  $("uiFontScale").value=String(ui.font_scale||100);
  $("uiSidebarWidth").value=String(ui.sidebar_width||300);
  $("uiChatWidth").value=String(ui.chat_width||1040);
  $("uiShowTechnical").checked=!!ui.show_technical_details;
  applyInterfaceSettings(ui);
}
function collectProfileSettings(){
  return {
    user:{
      display_name:$("profileName").value,
      role:$("profileRole").value,
      about:$("profileAbout").value,
      preferences:$("profilePreferences").value,
    },
    privacy:{
      share_with_researcher:$("shareResearcher").checked,
      share_with_chatgpt:$("shareChatGPT").checked,
    },
    researcher:{
      description:$("researcherDescription").value,
      instructions:$("researcherInstructions").value,
    },
    chatgpt:{
      description:$("chatgptDescription").value,
      instructions:$("chatgptInstructions").value,
    },
    ui:{
      theme:$("uiTheme").value,
      density:$("uiDensity").value,
      font_scale:Number($("uiFontScale").value),
      sidebar_width:Number($("uiSidebarWidth").value),
      chat_width:Number($("uiChatWidth").value),
      show_technical_details:$("uiShowTechnical").checked,
    },
  };
}
async function loadProfileSettings(){
  try{
    const response=await fetch("/api/profile-settings",{cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw Error(data.detail||"Не удалось загрузить профиль");
    state.profileSettings=data.settings||DEFAULT_PROFILE_SETTINGS;
    populateProfileSettings(state.profileSettings);
    $("profileSaveStatus").textContent="Настройки загружены.";
  }catch(err){
    state.profileSettings=DEFAULT_PROFILE_SETTINGS;
    populateProfileSettings(DEFAULT_PROFILE_SETTINGS);
    $("profileSaveStatus").textContent="Не удалось загрузить настройки: "+String(err.message||err);
  }
}
async function openProfileSettings(){
  if(!state.profileSettings)await loadProfileSettings();
  selectProfileTab("user");
  const dialog=$("profileDialog");
  if(typeof dialog.showModal==="function")dialog.showModal();
  else dialog.setAttribute("open","");
}
async function saveProfileSettings(){
  if(state.running)return;
  const button=$("profileSave");
  button.disabled=true;
  $("profileSaveStatus").textContent="Сохраняю настройки…";
  try{
    const result=await requestJson("/api/profile-settings",{settings:collectProfileSettings()});
    state.profileSettings=result.settings;
    populateProfileSettings(state.profileSettings);
    $("profileSaveStatus").textContent="Сохранено. Новые инструкции применятся к следующим сообщениям.";
    $("profileDialog").close();
  }catch(err){
    $("profileSaveStatus").textContent="Ошибка сохранения: "+String(err.message||err);
  }finally{button.disabled=false;}
}
function setSidebarCollapsed(collapsed){
  const sidebar=$("sidebar");
  sidebar.classList.toggle("collapsed",!!collapsed);
  $("sidebarExpand").hidden=!collapsed;
  $("sidebarCollapse").setAttribute("aria-expanded",String(!collapsed));
  $("sidebarCollapse").textContent=collapsed?"›":"‹";
  try{window.localStorage.setItem("cybernova_sidebar_collapsed",collapsed?"1":"0");}catch(_){}
}
function setUtilityPlaceholder(){
  const choice=$("utilityTool").value;
  $("utilityArgument").placeholder=choice==="safe_terminal"?
    "pwd · list · python --version · git status · git log":
    choice==="research_source_open"?"https://example.org/advisory":
    "Поиск CVE, ошибки, статьи или технического кейса";
}
async function runUtility(){
  const name=$("utilityTool").value;
  const argument=$("utilityArgument").value.trim();
  if(!argument)return;
  const btn=$("utilityRun");
  const output=$("utilityResult");
  btn.disabled=true;
  output.hidden=false;
  output.textContent="Выполняется безопасная операция…";
  try{
    const result=await requestJson("/api/tools/run",{name,argument});
    output.textContent=JSON.stringify(result.result,null,2);
  }catch(err){output.textContent="Ошибка: "+String(err.message||err);}
  finally{btn.disabled=false;}
}
const expandedCollabMessages = new Set();

function compactPreview(text, max=175){
  const clean=String(text||"").replace(/\s+/g," ").trim();
  return clean.length>max?clean.slice(0,max).trimEnd()+"…":clean;
}

function renderCollabEntry(message){
  const author=message.actor==="human"?"Вы":
    message.actor==="chatgpt"?"ChatGPT · наставник":"DeepSeek · исследователь";
  const article=node("article","collab-entry collab-"+message.actor);
  const heading=node("div","collab-author");
  heading.append(node("span","collab-author-icon",message.actor==="chatgpt"?"G":
    message.actor==="qwen"?"◈":"U"),node("strong","",author));
  article.append(heading);
  const full=String(message.body||"");
  const plain=full.replace(/\s+/g," ").trim();
  if(plain.length<=210){
    const body=node("div","collab-full");
    if(message.actor==="human")body.textContent=full;
    else setFormatted(body,full);
    article.append(body);
  }else{
    const details=node("details","collab-details");
    const summary=node("summary","collab-preview");
    summary.append(node("span","collab-snippet",compactPreview(full)),
                   node("span","collab-disclose","Показать полностью"));
    const body=node("div","collab-full");
    const key=String(message.seq||message.message_id||message.actor+"-"+plain.slice(0,35));
    let filled=false;
    function fill(){
      if(filled)return;
      if(message.actor==="human")body.textContent=full;
      else setFormatted(body,full);
      filled=true;
    }
    details.append(summary,body);
    if(expandedCollabMessages.has(key)){
      details.open=true;
      fill();
    }
    details.addEventListener("toggle",()=>{
      if(details.open){expandedCollabMessages.add(key);fill();}
      else expandedCollabMessages.delete(key);
    });
    article.append(details);
  }
  $("collabLog").append(article);
}

function renderCollabRun(run){
  if(!run)return;
  state.collabRun=run;
  $("collabForm").hidden=true;
  $("collabActiveBar").hidden=false;
  const active=run.state==="active",paused=run.state==="paused";
  $("collabStop").hidden=!active;
  $("collabResume").hidden=!paused||state.collabLooping;
  $("collabFinish").hidden=!(active||paused);
  $("collabResume").textContent="Продолжить ещё "+run.max_cycles+" обменов";
  const pairs=Math.floor(run.step/2);
  $("collabStatus").textContent=run.state==="completed"?
    "Диалог завершён · "+pairs+" обменов":
    paused?"Пауза · "+pairs+" обменов завершено, можно продолжить или закрыть":
    run.state==="blocked"?"Остановлено: требуется вмешательство":
    "В работе · "+run.step+"/"+run.pause_at+
    " сообщений в текущем пакете · следующий: "+
    (run.next_actor==="chatgpt"?"ChatGPT":"DeepSeek");
  const log=$("collabLog");
  log.replaceChildren();
  for(const m of run.messages||[]){
    if(m.actor==="human"&&m.kind==="instruction"||
       m.actor==="chatgpt"&&m.kind==="feedback"||
       m.actor==="qwen"&&m.kind==="result"){
      renderCollabEntry(m);
    }else if(m.actor==="controller"&&m.kind==="system"){
      log.append(node("p","collab-notice",m.body));
    }
  }
  toBottom();
}
async function refreshCollabRuns(){
  try{
    const response=await fetch("/api/collab/runs",{cache:"no-store"});
    if(!response.ok)return;
    const data=await response.json();
    const list=$("collabRunList");
    list.replaceChildren();
    for(const run of data.runs||[]){
      const button=node("button","task-item"+(run.task_id===state.collabRun?.task_id?" selected":""));
      button.type="button";
      button.append(node("span","task-title",compactPreview(run.goal||"Совместная задача",58)));
      if(run.last_preview)button.append(node("span","task-preview",compactPreview(run.last_preview,90)));
      button.title=(run.goal||"Совместная задача")+" · "+run.state+" · "+run.step+" сообщений";
      button.addEventListener("click",()=>openCollabRun(run.task_id));
      list.append(button);
    }
    if(!list.childNodes.length)list.append(node("p","muted","Пока нет совместных диалогов."));
  }catch(_){}
}
async function openCollabRun(taskId){
  if(state.collabLooping)return;
  try{
    const response=await fetch("/api/collab/run?task_id="+encodeURIComponent(taskId),{cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw Error(data.detail||"Нет совместной задачи");
    setMode("collab");
    renderCollabRun(data);
    $("sidebar").classList.remove("open");
  }catch(err){
    $("collabStatus").textContent="Ошибка: "+String(err.message||err);
  }
}
async function startCollab(){
  if(state.collabLooping)return;
  if(!state.gptConnected||!state.gptPlanUsage){
    $("collabStatus").textContent="Сначала подключи аккаунт ChatGPT через «Аккаунт GPT».";
    $("collabActiveBar").hidden=false;
    $("collabStop").hidden=true;
    return;
  }
  const goal=$("collabGoal").value.trim(), model=$("collabModel").value;
  if(!goal||!model)return;
  $("collabStart").disabled=true;
  try{
    const run=await requestJson("/api/collab/start",{
      goal,model,cycles:Number($("collabCycles").value),session_id:state.sessionId
    });
    state.collabStopRequested=false;
    renderCollabRun(run);
    void refreshCollabRuns();
    await continueCollab();
  }catch(err){
    $("collabActiveBar").hidden=false;
    $("collabStop").hidden=true;
    $("collabStatus").textContent="Ошибка запуска: "+String(err.message||err);
  }finally{$("collabStart").disabled=false;}
}
async function continueCollab(){
  if(state.collabLooping||!state.collabRun||
     !["active","paused"].includes(state.collabRun.state))return;
  state.collabLooping=true;
  state.collabStopRequested=false;
  $("collabResume").hidden=true;
  const taskId=state.collabRun.task_id;
  try{
    if(state.collabRun.state==="paused"){
      const resumed=await requestJson("/api/collab/resume",{task_id:taskId});
      if(state.collabRun?.task_id!==taskId)return;
      renderCollabRun(resumed);
    }
    while(state.collabRun?.state==="active"&&!state.collabStopRequested){
      $("collabStatus").textContent="Ожидаем ответ "+
        (state.collabRun.next_actor==="chatgpt"?"ChatGPT-наставника":"DeepSeek-исследователя")+"…";
      let response;
      try{
        response=await requestJson("/api/collab/step",{task_id:taskId});
      }catch(err){
        if(!state.collabStopRequested)throw err;
        break;
      }
      if(state.collabStopRequested||state.collabRun?.task_id!==taskId)break;
      renderCollabRun(response.run);
      await refreshCollabRuns();
    }
  }catch(err){
    $("collabStatus").textContent="Обмен прерван: "+String(err.message||err);
    // Read durable server state before offering a manual continuation.
    try{
      const resp=await fetch("/api/collab/run?task_id="+encodeURIComponent(taskId),{cache:"no-store"});
      if(resp.ok)renderCollabRun(await resp.json());
    }catch(_){}
  }finally{
    state.collabLooping=false;
    if(state.collabRun&&state.collabRun.task_id===taskId)renderCollabRun(state.collabRun);
    void refreshCollabRuns();
  }
}
async function stopCollab(){
  if(!state.collabRun)return;
  state.collabStopRequested=true;
  try{
    const run=await requestJson("/api/collab/stop",{task_id:state.collabRun.task_id});
    renderCollabRun(run);
    void refreshCollabRuns();
  }catch(err){
    $("collabStatus").textContent="Ошибка паузы: "+String(err.message||err);
  }
}
async function finishCollab(){
  if(!state.collabRun||!["active","paused"].includes(state.collabRun.state))return;
  state.collabStopRequested=true;
  try{
    const run=await requestJson("/api/collab/finish",{task_id:state.collabRun.task_id});
    renderCollabRun(run);
    void refreshCollabRuns();
  }catch(err){
    $("collabStatus").textContent="Ошибка завершения: "+String(err.message||err);
  }
}
async function newCollab(){
  if(state.collabRun?.state==="active")await stopCollab();
  state.collabRun=null;
  state.collabStopRequested=true;
  $("collabForm").hidden=false;
  $("collabActiveBar").hidden=true;
  $("collabLog").replaceChildren();
  $("collabGoal").value="";
  void refreshCollabRuns();
}
function init(){
  window.cybernovaWelcome=$("welcome").cloneNode(true);
  window.cybernovaGptWelcome=$("gptWelcome").cloneNode(true);
  showResearchScope({hosts:[],capture_detail:"evidence"});
  $("sendButton").addEventListener("click",send);
  $("artifactFile").addEventListener("change",event=>importArtifact(event.target.files?.[0]));
  $("messageInput").addEventListener("keydown",e=>{
    if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send();}
  });
  $("newSession").addEventListener("click",reset);
  $("sidebarCollapse").addEventListener("click",()=>setSidebarCollapsed(!$("sidebar").classList.contains("collapsed")));
  $("sidebarExpand").addEventListener("click",()=>setSidebarCollapsed(false));
  $("utilityTool").addEventListener("change",setUtilityPlaceholder);
  $("utilityRun").addEventListener("click",runUtility);
  setUtilityPlaceholder();
  try{setSidebarCollapsed(window.localStorage.getItem("cybernova_sidebar_collapsed")==="1");}
  catch(_){setSidebarCollapsed(false);}
  $("collabStart").addEventListener("click",startCollab);
  $("collabStop").addEventListener("click",stopCollab);
  $("collabFinish").addEventListener("click",finishCollab);
  $("collabResume").addEventListener("click",continueCollab);
  $("collabNew").addEventListener("click",newCollab);
  $("navProfile").addEventListener("click",openProfileSettings);
  $("profileClose").addEventListener("click",()=>$("profileDialog").close());
  $("profileCancel").addEventListener("click",()=>$("profileDialog").close());
  $("profileSave").addEventListener("click",saveProfileSettings);
  $("profileTabs").addEventListener("click",event=>{
    const tab=event.target.closest("[data-profile-tab]");
    if(tab)selectProfileTab(tab.dataset.profileTab);
  });
  void loadProfileSettings();
  $("applyResearchScope").addEventListener("click",applyResearchScope);
  $("modeQwen").addEventListener("click",()=>setMode("qwen"));
  $("modeChatGPT").addEventListener("click",()=>setMode("gpt"));
  $("modeCollab").addEventListener("click",()=>setMode("collab"));
  $("gptTopModel").addEventListener("change",()=>{
    if(state.mode==="gpt")$("sendStatus").textContent="Модель выбрана · изменения применятся к следующему сообщению";
  });
  $("refreshStatus").addEventListener("click",status);
  $("copyReviewPacket").addEventListener("click",copyReviewPacket);
  $("evidenceIndexButton").addEventListener("click",showEvidenceJournal);
  $("sendReviewFeedback").addEventListener("click",submitReviewerFeedback);
  $("navChatGPT").addEventListener("click",()=>{
    toolsPanel(true);
    document.querySelector(".chatgpt-connection").scrollIntoView({block:"start",behavior:"smooth"});
  });
  $("chatgptConnect").addEventListener("click",connectChatGPT);
  $("chatgptDisconnect").addEventListener("click",disconnectChatGPT);
  $("chatgptReview").addEventListener("click",reviewWithChatGPT);
  $("chatgptToQwen").addEventListener("click",forwardGPTtoQwen);
  void refreshChatGPT();
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
  void refreshTaskList();
  void refreshGPTThreads();
  void refreshCollabRuns();
  window.setInterval(()=>{void pollTask();},5000);
  window.setInterval(()=>{void refreshTaskList();},15000);
  window.setInterval(()=>{if(state.mode==="collab")void refreshCollabRuns();},15000);
}
document.addEventListener("DOMContentLoaded",init);
