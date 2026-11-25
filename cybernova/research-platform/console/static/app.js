"use strict";
/* Cybernova: local ChatGPT-like chat UI. No external JS, no model HTML. */
const $=id=>document.getElementById(id);
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const state={sessionId:null,taskId:null,lastSeq:0,running:false,qwenRunning:false,gptRunning:false,collabRunning:false,turns:0,
  diagnostics:{qwen:{session_ref:null,task_ref:null,run_id:null},gpt:{session_ref:null,task_ref:null,run_id:null}},
  uploadLimit:MAX_UPLOAD_BYTES,mode:"qwen",qwenModel:"Активная модель",
  gptThreadId:null,gptConnected:false,gptPlanUsage:false,
  researchScope:{hosts:[],capture_detail:"evidence"},profileSettings:null,
  toolGroups:[],toolGroupCatalog:[],toolsEnabled:true,
  usageTotals:{
    qwen:{input:0,output:0,total:0,measuredTurns:0},
    gpt:{input:0,output:0,total:0,measuredTurns:0}
  },
  lastUsage:{qwen:null,gpt:null},
  collabRun:null,collabLooping:false,collabStopRequested:false,
  ownerInputRequestId:null,ownerInputType:null};
const descriptions={
  gateway_status:"Шлюз MCP",
  local_webui_health:"Проверка Console API / MCP",
  http_get:"Публичный GET",
  http_header_review:"Анализ HTTP-заголовков",
  ip_network_summary:"Расчёт подсети",
  python_static_review:"Анализ Python",
};
const TOOL_GROUP_GLYPHS={
  browser:"◎",computer:"▣",terminal:">_",web:"⌕",network:"⇄",
  security:"⛨",traffic:"≋",developer:"⌘",github:"⑂",mcp:"⧉"
};
const TOOL_GROUP_FALLBACK=[
  {id:"browser",label:"Chrome / браузер",icon:"globe",description:"Открывать сайты, читать DOM, переходить по ссылкам, создавать вкладки, переключаться между ними, назад/вперёд, обновлять страницы, смотреть Console и DevTools Network."},
  {id:"computer",label:"Компьютер Windows",icon:"monitor",description:"Состояние ПК: CPU/RAM/диски, процессы и службы, автозагрузка, установленные программы, окна, Defender и локальные файлы."},
  {id:"terminal",label:"Терминал Windows",icon:"terminal",description:"Полноценные CMD и PowerShell для локальной работы. Доступны автоматически в автономном режиме."},
  {id:"web",label:"Интернет / Research",icon:"search",description:"Искать в интернете, получать выдачу с пагинацией, открывать найденные страницы, читать первоисточники и сопоставлять источники."},
  {id:"network",label:"Сеть / NOC",icon:"network",description:"DNS, TLS, IP, HTTP и сетевые проверки."},
  {id:"security",label:"Security",icon:"shield",description:"Проверки безопасности и лабораторные сканеры."},
  {id:"traffic",label:"Traffic / HAR",icon:"activity",description:"HAR, JavaScript, сессии и сетевые гипотезы."},
  {id:"developer",label:"Разработка",icon:"code",description:"Workspace, Git, файлы проекта и тесты."},
  {id:"github",label:"GitHub",icon:"git-branch",description:"Полный repo-scoped доступ: чтение и запись файлов, ветки, коммиты, Issues, PR, Releases, Actions и настройки."},
  {id:"mcp",label:"MCP / прочее",icon:"plug",description:"Подключённые MCP-сервисы и координация."}
];
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
function resizeComposer(){
  const input=$("messageInput");
  if(!input?.style)return;
  input.style.height="30px";
  const contentHeight=Number(input.scrollHeight)||30;
  input.style.height=Math.min(140,Math.max(30,contentHeight))+"px";
  input.style.overflowY=contentHeight>140?"auto":"hidden";
}
function showReviewStatus(message,review){
  if(!review||!message?.wrap)return;
  const meta=message.wrap.querySelector?.(".message-meta");
  if(!meta)return;
  if(review.status==="not_required")return;
  const complete=review.status==="completed";
  const badge=node("span","review-status "+(complete?"is-completed":"is-incomplete"),
    complete?"Проверка результата":"Проверка не завершена");
  badge.title=complete?
    "Второй проход сверил ответ с уже полученными данными инструментов; новых тестов он не выполнял":
    "Проверка результата не завершилась; это не означает, что инструментальные действия не выполнены.";
  meta.append(badge);
}
function renderMessage(role,content,pending=false,containerId="messages"){
  const author=role==="chatgpt"?"ChatGPT":role==="user"?"Вы":state.qwenModel||"Исследователь";
  const wrap=node("article","chat-msg "+
    (role==="user"?"from-user":role==="chatgpt"?"from-chatgpt":"from-agent")+
    (pending?" working":""));
  const meta=node("div","message-meta");
  meta.append(node("span","avatar "+(role==="user"?"user":""),role==="user"?"U":role==="chatgpt"?"G":"◈"),
              node("span","",author));
  if(role==="assistant")meta.append(node("span","agent-rank","Grandmaster · NOC / Development"));
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
  if(state.qwenRunning||!state.sessionId)return;
  busy(true,"qwen");
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
      recordUsage(reply.usage,"qwen",result);
      showEvents(reply.events,reply.tool_calls,reply.selected_by,result);
      void loadFollowups(state.sessionId,state.turns,result);
    }else{
      renderMessage("assistant","Действие отклонено. Инструмент не запускался.");
    }
  }catch(err){
    card.append(node("div","approval-error","Ошибка: "+String(err.message||err)));
    card.querySelectorAll("button").forEach(button=>button.disabled=false);
  }finally{
    busy(false,"qwen");toBottom();
  }
}
function buildToolBatch(events,count,mode){
  const rows=Array.isArray(events)?events.filter(event=>event&&typeof event==="object"):[];
  const total=Number.isSafeInteger(count)&&count>=0?count:rows.length;
  const errors=rows.filter(event=>event.is_error===true||event.result?.ok===false||
    ["agent_error","mcp_error","tool_catalog_error","tool_selection_error"].includes(event.type)).length;
  const pending=rows.filter(event=>["approval_required","scope_change_required"].includes(event.type)).length;
  const names=Array.from(new Set(rows.map(event=>String(event.name||event.type||"Событие")).filter(Boolean)));
  const preview=names.slice(0,3).join(" · ")+(names.length>3?" · +"+(names.length-3):"");
  const modeLabel=mode==="native"?"модель выбрала":
    mode==="dsml_content"?"модель выбрала (DSML)":
    mode==="model_json_fallback"?"план модели":
    mode==="google_research_fallback"?"автопоиск":
    mode==="evidence_first_fallback"?"первичная проверка":
    mode==="user_approved"?"разрешено пользователем":"контроллер";
  const batch=node("details","tool-batch");
  batch.setAttribute("aria-label","Инструменты: "+total+" вызовов");
  const summary=node("summary","tool-batch-summary");
  summary.append(
    node("span","tool-batch-title","Инструменты"),
    node("span","tool-batch-count",String(total)),
    node("span","tool-batch-state "+(pending?"is-pending":errors?"is-error":"is-success"),
      pending?pending+" ожидают решения":errors?errors+" с ошибкой":"выполнено"),
    node("span","tool-batch-mode",modeLabel),
    node("span","tool-batch-preview",preview||"Подробности недоступны")
  );
  const list=node("div","tool-batch-list");
  if(rows.length){
    for(const event of rows)list.append(makeToolDetails(event));
  }else{
    list.append(node("p","muted","Сервер не передал подробности вызовов."));
  }
  batch.append(summary,list);
  return batch;
}
function showEvents(events,count,mode,reply){
  const inspector=$("runList");
  const rows=Array.isArray(events)?events.filter(event=>event&&typeof event==="object"):[];
  const total=Number.isSafeInteger(count)&&count>=0?count:rows.length;
  inspector.replaceChildren();
  $("runCount").textContent=total?total+" вызовов":rows.length?rows.length+" событий":"Нет вызовов";
  if(rows.length||total>0){
    inspector.append(buildToolBatch(rows,total,mode));
    if(reply){
      const inline=node("div","inline-tools");
      inline.append(buildToolBatch(rows,total,mode));
      reply.wrap.append(inline);
    }
  }else{
    inspector.append(node("p","muted","На этом шаге инструментов не было."));
  }
  if(!reply)return;
  for(const event of rows){
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
function renderFollowups(reply, questions){
  if(!Array.isArray(questions)||!questions.length)return;
  const box=node("div","followup-box");
  box.append(node("div","followup-label","Следующие шаги"));
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
    if(!["qwen","offer"].includes(result.source)||result.turn!==turn)return;
    if(typeof result.answer_without_offer==="string"){
      setFormatted(reply.body,result.answer_without_offer);
    }
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
  if(!file||state.qwenRunning)return;
  if(file.size>state.uploadLimit){
    $("uploadStatus").textContent="Файл слишком большой (максимум "+
      Math.floor(state.uploadLimit/(1024*1024))+" МиБ)";
    return;
  }
  const binary=/\.(pcap|cap)$/i.test(file.name);
  $("uploadStatus").textContent="Анализируем файл локально…";
  busy(true,"qwen");
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
    setDiagnosticsContext(result.diagnostics||{},"qwen");
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
    busy(false,"qwen");
    $("artifactFile").disabled=false;
    $("artifactFile").value="";
    $("messageInput").focus();
  }
}
function updateBusyUI(){
  const anyModelRunning=state.qwenRunning||state.gptRunning;
  const activeRunning=state.mode==="gpt"?state.gptRunning:
    state.mode==="collab"?state.collabRunning:state.qwenRunning;
  state.running=!!activeRunning;
  $("sendButton").disabled=!!activeRunning;
  $("messageInput").disabled=false;
  $("newSession").disabled=!!activeRunning;
  $("artifactFile").disabled=state.mode!=="qwen"||state.qwenRunning||state.collabRunning;
  $("toolPickerToggle").disabled=anyModelRunning||state.collabRunning;
  const toolPickerGroups=$("toolPickerGroups");
  if(toolPickerGroups&&typeof toolPickerGroups.querySelectorAll==="function"){
    toolPickerGroups.querySelectorAll("input").forEach(input=>{
      input.disabled=anyModelRunning||state.collabRunning||input.dataset.available==="false";
    });
  }
  const active=[];
  if(state.qwenRunning)active.push("DeepSeek работает");
  if(state.gptRunning)active.push("ChatGPT работает");
  if(state.collabRunning)active.push("Совместная задача выполняется");
  $("sendStatus").textContent=active.length?active.join(" · "):
    state.mode==="gpt"&&!state.gptConnected?"Подключи ChatGPT через «Аккаунт GPT»":"Готов";
  $("modeQwen").disabled=state.collabRunning;
  $("modeChatGPT").disabled=state.collabRunning;
  $("modeCollab").disabled=anyModelRunning||state.collabRunning;
  const gptModelSelect=$("gptTopModel");
  const hasGptModelOptions=!!gptModelSelect.options&&gptModelSelect.options.length>0;
  gptModelSelect.disabled=!state.gptConnected||!state.gptPlanUsage||
    !hasGptModelOptions||state.gptRunning;
}
function busy(on,mode=state.mode){
  const key=mode==="gpt"?"gptRunning":mode==="collab"?"collabRunning":"qwenRunning";
  state[key]=!!on;
  updateBusyUI();
}
function resetUsage(mode){
  state.usageTotals[mode]={input:0,output:0,total:0,measuredTurns:0};
  state.lastUsage[mode]=null;
  if(state.mode===mode)$("tokenUsageStatus").textContent="Токены: —";
}
function formatTokens(value){
  return Number.isSafeInteger(value)&&value>=0?new Intl.NumberFormat("ru-RU").format(value):"—";
}
function recordUsage(usage,mode,reply){
  const available=!!usage&&usage.available===true;
  const receipt=node("div","token-usage-receipt");
  if(!available){
    receipt.append(node("strong","","Учёт токенов недоступен"),
      node("span","",usage?.provider?("· "+usage.provider):"· провайдер не передал usage"));
    if(usage?.requests)receipt.append(node("span","", "· запросов модели: "+usage.requests));
    reply?.wrap?.append(receipt);
    state.lastUsage[mode]={available:false};
    updateTokenUsageStatus(mode);
    return;
  }
  const input=Number.isSafeInteger(usage.input_tokens)?usage.input_tokens:null;
  const output=Number.isSafeInteger(usage.output_tokens)?usage.output_tokens:null;
  const total=Number.isSafeInteger(usage.total_tokens)?usage.total_tokens:
    (usage.complete!==false&&input!==null&&output!==null?input+output:null);
  receipt.append(
    node("strong","","Токены"),
    node("span","","Вход: "+formatTokens(input)),
    node("span","","Выход: "+formatTokens(output)),
    node("strong","","Всего: "+formatTokens(total))
  );
  if(usage.complete===false)receipt.append(node("span","","· частичный учёт"));
  if(Number.isSafeInteger(usage.requests))receipt.append(node("span","","· запросов модели: "+usage.requests));
  if(usage.provider)receipt.append(node("span","","· "+usage.provider));
  reply?.wrap?.append(receipt);
  const totals=state.usageTotals[mode];
  if(input!==null)totals.input+=input;
  if(output!==null)totals.output+=output;
  if(total!==null)totals.total+=total;
  totals.measuredTurns+=1;
  state.lastUsage[mode]={available:true,input,output,total,complete:usage.complete!==false};
  updateTokenUsageStatus(mode);
}
function updateTokenUsageStatus(mode){
  const last=state.lastUsage[mode],totals=state.usageTotals[mode];
  if(!last){$("tokenUsageStatus").textContent="Токены: —";return;}
  if(!last.available){$("tokenUsageStatus").textContent="Токены: нет usage от провайдера";return;}
  $("tokenUsageStatus").textContent=
    "Токены · вход: "+formatTokens(last.input)+" · выход: "+
    formatTokens(last.output)+" · всего: "+formatTokens(last.total);
  $("tokenUsageStatus").title=
    "Фактический учёт по usage провайдера. Вход: "+formatTokens(totals.input)+
    "; выход: "+formatTokens(totals.output)+
    "; суммарно по сеансу: "+formatTokens(totals.total)+
    "; учтённых ходов: "+totals.measuredTurns;
}
function toolPickerOpen(open){
  const panel=$("toolPicker"),toggle=$("toolPickerToggle");
  panel.hidden=!open;
  toggle.setAttribute("aria-expanded",String(!!open));
  if(open)$("toolPickerClose").focus();
}
function updateToolPickerSummary(){
  const selected=state.toolGroups;
  const off=$("toolPickerOff");
  if(off)off.setAttribute("aria-pressed",String(!state.toolsEnabled));
  const hint=$("qwenAutoTools");
  if(hint)hint.hidden=!state.toolsEnabled;
  if(!state.toolsEnabled){
    $("toolSelectionBadge").textContent="Выкл";
    $("toolPickerSummary").textContent="Инструменты отключены: схемы и локальные вызовы не передаются модели.";
    return;
  }
  if(!selected.length){
    $("toolSelectionBadge").textContent="Авто";
    $("toolPickerSummary").textContent="Автономный режим: все группы и инструменты доступны модели, включая CMD и PowerShell. Обычные действия выполняются без подтверждения каждого шага.";
    return;
  }
  const labels=state.toolGroupCatalog.filter(x=>selected.includes(x.id)).map(x=>x.label);
  $("toolSelectionBadge").textContent=String(selected.length);
  $("toolPickerSummary").textContent="Ограничено выбранным: "+labels.join(" · ");
}
function persistToolGroups(){
  try{
    window.localStorage.setItem("cybernova_tool_groups",JSON.stringify(state.toolGroups));
    window.localStorage.setItem("cybernova_tools_enabled",state.toolsEnabled?"true":"false");
  }catch(_){}
}
function renderToolPicker(groups){
  const catalog=Array.isArray(groups)&&groups.length?groups:TOOL_GROUP_FALLBACK;
  state.toolGroupCatalog=catalog;
  const container=$("toolPickerGroups");
  container.replaceChildren();
  for(const group of catalog){
    const count=Number.isSafeInteger(group.count)?group.count:null;
    const available=group.available!==false&&count!==0;
    const selected=state.toolGroups.includes(group.id);
    const label=node("label","tool-group-option"+(selected?" selected":""));
    const input=node("input");
    input.type="checkbox";input.checked=selected;
    input.dataset.toolGroup=group.id;
    input.dataset.available=String(available);
    input.disabled=!available||state.qwenRunning||state.gptRunning||state.collabRunning;
    input.addEventListener("change",()=>{
      const next=new Set(state.toolGroups);
      if(input.checked)next.add(group.id);else next.delete(group.id);
      state.toolGroups=catalog.map(item=>item.id).filter(id=>next.has(id));
      state.toolsEnabled=true;
      persistToolGroups();
      renderToolPicker(catalog);
    });
    const icon=node("span","tool-group-icon",TOOL_GROUP_GLYPHS[group.id]||"＋");
    icon.setAttribute("aria-hidden","true");
    const copy=node("span","tool-group-copy");
    const title=node("span","tool-group-name",group.label||group.id);
    title.append(node("span","tool-group-count",count===null?"":String(count)+" инструментов"));
    const scope=node("span","tool-group-description",group.description||"Инструменты этой группы.");
    const hint=node("span","tool-group-hint",group.id==="browser"?"ВКЛАДКИ · НАВИГАЦИЯ · NETWORK":
      group.id==="computer"?"WINDOWS · ПРОЦЕССЫ · DEFENDER":
      group.id==="web"?"ПОИСК · СТРАНИЦЫ · ИСТОЧНИКИ":
      group.id==="terminal"?"CMD · POWERSHELL · ДИАГНОСТИКА":
      group.id==="network"?"DNS · TLS · IP · HTTP":
      group.id==="github"?"REPOS · BRANCHES · ISSUES · PR · ACTIONS":"ГРУППА ИНСТРУМЕНТОВ");
    copy.append(title,scope,hint);
    label.append(icon,copy,input);
    if(!available)label.title="В этой конфигурации группа сейчас не обнаружена";
    container.append(label);
  }
  updateToolPickerSummary();
}
function newRunId(){
  if(window.crypto?.randomUUID)return window.crypto.randomUUID().replace(/-/g,"");
  if(window.crypto?.getRandomValues){
    const bytes=new Uint8Array(16);window.crypto.getRandomValues(bytes);
    return Array.from(bytes,x=>x.toString(16).padStart(2,"0")).join("");
  }
  throw Error("Secure random generator unavailable");
}

function activeDiagnosticsContext(){
  return state.mode==="gpt"?state.diagnostics.gpt:state.diagnostics.qwen;
}
function diagnosticsHref(scope,context=activeDiagnosticsContext()){
  const params=new URLSearchParams();
  if(scope==="task"&&context.task_ref)params.set("task_ref",context.task_ref);
  else if(scope==="session"&&context.session_ref)params.set("session_ref",context.session_ref);
  else if(scope==="run"&&context.run_id)params.set("run_id",context.run_id);
  const query=params.toString();
  return "/api/diagnostics/export"+(query?"?"+query:"");
}
function setDiagnosticsContext(value,mode=state.mode){
  const key=mode==="gpt"?"gpt":"qwen";
  const source=value&&typeof value==="object"?value:{};
  state.diagnostics[key]={
    session_ref:typeof source.session_ref==="string"?source.session_ref:null,
    task_ref:typeof source.task_ref==="string"?source.task_ref:null,
    run_id:typeof source.run_id==="string"?source.run_id:null
  };
  updateDiagnosticsLinks();
}
function updateDiagnosticsLinks(){
  const context=activeDiagnosticsContext();
  const scope=context.task_ref?"task":context.session_ref?"session":context.run_id?"run":null;
  const href=scope?diagnosticsHref(scope,context):null;
  for(const id of ["chatDiagnosticsDownload","diagnosticsDownload"]){
    const link=$(id);
    if(!link)continue;
    if(href){
      link.href=href;
      link.setAttribute("aria-disabled","false");
      link.download=scope==="task"?"cybernova-diagnostics-task.jsonl":
        scope==="session"?"cybernova-diagnostics-session.jsonl":"cybernova-diagnostics-run.jsonl";
    }else{
      if(typeof link.removeAttribute==="function")link.removeAttribute("href");else link.href="#";
      link.setAttribute("aria-disabled","true");
    }
    if(id==="diagnosticsDownload"){
      link.textContent=scope==="task"?"Скачать журнал текущей задачи (.jsonl)":
        scope==="session"?"Скачать журнал текущей сессии (.jsonl)":
        scope==="run"?"Скачать журнал текущего запуска (.jsonl)":
        "Сначала запусти задачу для выгрузки журнала";
    }
  }
  const runLink=$("diagnosticsRunDownload");
  if(runLink){
    if(context.run_id){
      runLink.href=diagnosticsHref("run",context);
      runLink.setAttribute("aria-disabled","false");
    }else{
      if(typeof runLink.removeAttribute==="function")runLink.removeAttribute("href");else runLink.href="#";
      runLink.setAttribute("aria-disabled","true");
    }
  }
  const fullLink=$("diagnosticsDownloadAll");
  if(fullLink){
    fullLink.href="/api/diagnostics/export";
    fullLink.setAttribute("aria-disabled","false");
  }
}

function showUsageProgress(progress,mode){
  if(!progress||state.mode!==mode)return;
  const usage=progress.usage||{};
  if(usage.available===true){
    $("tokenUsageStatus").textContent=
      (progress.status==="running"?"Сейчас · ":"Токены · ")+
      "вход "+formatTokens(usage.input_tokens)+" · выход "+
      formatTokens(usage.output_tokens)+" · всего "+formatTokens(usage.total_tokens);
    $("tokenUsageStatus").title="Промежуточный usage от провайдера "+
      (usage.provider||"")+". "+(usage.complete===false?"Учёт частичный.":"");
  }else if(progress.status==="running"){
    $("tokenUsageStatus").textContent="Модель работает · ждём usage провайдера";
  }
}
async function watchUsageProgress(runId,mode="gpt"){
  const isRunning=()=>mode==="gpt"?state.gptRunning:state.qwenRunning;
  const started=Date.now();
  let failures=0,delay=1200;
  while(isRunning()){
    await new Promise(resolve=>setTimeout(resolve,delay));
    if(!isRunning())break;
    try{
      const response=await fetch("/api/usage-progress?run_id="+encodeURIComponent(runId),
        {cache:"no-store",headers:{"Accept":"application/json"},signal:AbortSignal.timeout(8000)});
      if(!response.ok){
        if(response.status===404&&Date.now()-started<10000)continue;
        throw Object.assign(Error("HTTP "+response.status),{permanent:response.status<500});
      }
      const progress=await response.json();
      showUsageProgress(progress,mode);
      failures=0;delay=1500;
      if(progress.status!=="running")break;
    }catch(error){
      failures++;
      delay=Math.min(8000,1500*Math.pow(2,Math.min(failures,3)));
      if(state.mode===mode&&(error.permanent||failures>=3))
        $("tokenUsageStatus").textContent="Учёт токенов недоступен: "+String(error.message||error);
      if(error.permanent)break;
    }
  }
}
async function requestJson(path,data,signal){
  const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},
     body:JSON.stringify(data),cache:"no-store",signal});
  let body;
  try{body=await response.json();}catch(_){
    throw Object.assign(Error("Некорректный ответ сервера: "+response.status),{status:response.status});
  }
  if(!response.ok)throw Object.assign(Error(body.detail||"HTTP "+response.status),{status:response.status});
  return body;
}
async function requestChatTurn(data,pending){
  const receipt=newRunId();
  const deadline=Date.now()+15*60*1000;
  let accepted=false, failures=0;
  const request={...data,receipt};
  try{
    await requestJson("/api/chat/start",request,AbortSignal.timeout(10000));
    accepted=true;
  }catch(exc){
    if(!(exc instanceof TypeError)&&exc.name!=="TimeoutError"&&!(exc.status>=500))throw exc;
  }
  pending.body.textContent=accepted?"Задача в очереди…":"Проверяем, принял ли сервер задачу…";
  while(Date.now()<deadline){
    await new Promise(resolve=>setTimeout(resolve,Math.min(8000,1000*Math.pow(2,Math.min(failures,3)))));
    let job;
    try{
      job=await requestJson("/api/chat/result",{receipt},AbortSignal.timeout(10000));
    }catch(exc){
      const transient=exc instanceof TypeError||exc.name==="TimeoutError"||
        exc.status>=500||(!accepted&&exc.status===404);
      if(!transient||++failures>=15)throw exc;
      if(!accepted&&exc.status===404&&failures>=2){
        try{
          await requestJson("/api/chat/start",request,AbortSignal.timeout(10000));
          accepted=true;
        }catch(startError){
          if(startError.status===409||startError.status===422)throw startError;
        }
      }
      pending.body.textContent="Связь прервалась. Проверяем статус задачи…";
      continue;
    }
    showUsageProgress(job.usage_progress,"qwen");
    renderOwnerInput(job.owner_input);
    if(job.status==="completed")return job.result;
    if(job.status==="failed")throw Error(job.detail||"Выполнение задачи завершилось ошибкой");
    const progress=job.progress;
    if(job.state==="waiting_for_owner_input"){
      pending.body.textContent="Ожидаем защищённый ввод владельца…";
    }else if(job.state==="queued"){
      pending.body.textContent="Задача в очереди…";
    }else if(progress?.event==="model_request_start"){
      pending.body.textContent="Ожидаем ответ модели…";
    }else if(progress?.event==="tool_call_start"&&progress.tool){
      pending.body.textContent="Выполняется инструмент "+progress.tool+"…";
    }else if(["tool_call_completed","tool_call_failed"].includes(progress?.event)&&progress.tool){
      pending.body.textContent=progress.tool+(progress.status==="ok"?" завершил работу.":" завершился с ошибкой.");
    }else if(!accepted||failures){
      pending.body.textContent="Задача принята. Ожидаем результат…";
    }
    accepted=true;
    failures=0;
  }
  throw Error("Истекло время ожидания результата. Задача может продолжаться на сервере.");
}
function resetOwnerInputValues(){
  $("ownerInputValue").value="";
  $("ownerInputSaveToVault").checked=false;
  $("ownerInputPaymentFields").replaceChildren();
  $("ownerInputPaymentFrameList").replaceChildren();
  $("ownerInputPaymentFrames").hidden=true;
  $("ownerInputPaymentFields").hidden=true;
  $("ownerInputPaymentMerchant").hidden=true;
  $("ownerInputConfirmationPanel").hidden=true;
  $("ownerInputSingleField").hidden=false;
  $("ownerInputVaultOption").hidden=true;
}
function renderOwnerPaymentFields(item){
  const container=$("ownerInputPaymentFields");
  container.replaceChildren();
  const available=new Set(item.payment_fields||[]);
  const configs=[
    ["cardholder_name","Имя владельца карты","text","text",80],
    ["card_number","Номер банковской карты","password","numeric",23],
    ["expiry_month","Месяц окончания (MM)","text","numeric",2],
    ["expiry_year","Год окончания (YY или YYYY)","text","numeric",4],
    ["cvv","CVV / CVC","password","numeric",4],
    ["billing_address_line1","Платёжный адрес, строка 1","text","text",120],
    ["billing_city","Город платёжного адреса","text","text",80],
    ["billing_region","Область / штат","text","text",80],
    ["billing_country","Страна платёжного адреса","text","text",80],
    ["billing_postal_code","Почтовый индекс для оплаты","text","text",20]
  ];
  for(const [key,label,type,inputMode,maxLength] of configs){
    const needed=available.has(key)||
      ((key==="expiry_month"||key==="expiry_year")&&
       (available.has("expiry")||available.has("expiry_month")||available.has("expiry_year")));
    if(!needed)continue;
    const wrap=document.createElement("div");
    wrap.className="owner-payment-field";
    const caption=document.createElement("label");
    const id="ownerPayment_"+key;
    caption.htmlFor=id;
    caption.textContent=label;
    const input=document.createElement("input");
    input.id=id;
    input.type=type;
    input.inputMode=inputMode;
    input.maxLength=maxLength;
    input.autocomplete="off";
    input.spellcheck=false;
    input.required=true;
    input.dataset.paymentField=key;
    if(key==="expiry_month")input.placeholder="MM";
    if(key==="expiry_year")input.placeholder="YY";
    wrap.append(caption,input);
    container.append(wrap);
  }
  container.hidden=false;
  const first=container.querySelector("[data-payment-field='card_number']")||
    container.querySelector("input");
  first?.focus();
}
function renderOwnerPaymentFrames(item){
  const container=$("ownerInputPaymentFrames"),list=$("ownerInputPaymentFrameList");
  list.replaceChildren();
  const hosts=Array.isArray(item.payment_frame_hosts)?item.payment_frame_hosts:[];
  container.hidden=hosts.length===0;
  for(const host of hosts){
    const label=document.createElement("label");
    label.className="owner-payment-frame-option";
    const checkbox=document.createElement("input");
    checkbox.type="checkbox";
    checkbox.dataset.paymentFrameHost=host;
    const text=document.createElement("span");
    text.textContent="Разрешить платёжной форме на "+host+" получить данные карты";
    label.append(checkbox,text);
    list.append(label);
  }
}
function renderOwnerInput(item){
    if(!item||item.request_id===state.ownerInputRequestId)return;
    state.ownerInputRequestId=item.request_id;
    state.ownerInputType=item.input_type;
    resetOwnerInputValues();
    $("ownerInputPurpose").textContent=item.purpose||"Нужны данные владельца";
    $("ownerInputFieldLabel").textContent=item.field_label||"Значение";
    $("ownerInputError").textContent="";
    const type=item.input_type;
    $("ownerInputCancel").textContent=
      type==="payment_confirmation"?"Отклонить действие":
      type==="payment_card"?"Отмена":"Отмена задачи";
    if(type==="payment_card"){
      $("ownerInputSingleField").hidden=true;
      $("ownerInputVaultOption").hidden=true;
      $("ownerInputPaymentMerchant").textContent="Сайт: "+(item.expected_origin||"Не определён");
      $("ownerInputPaymentMerchant").hidden=false;
      $("ownerInputNote").textContent=
        "Данные карты передаются только в указанную платёжную форму и отмеченные платёжные домены. Cybernova не сохраняет номер карты и CVV, не добавляет их в историю и не передаёт модели.";
      $("ownerInputSubmit").textContent="Передать и заполнить форму";
      renderOwnerPaymentFields(item);
      renderOwnerPaymentFrames(item);
    }else if(type==="payment_confirmation"){
      $("ownerInputSingleField").hidden=true;
      $("ownerInputConfirmationPanel").hidden=false;
      $("ownerInputMerchantOrigin").textContent=item.expected_origin||"Не определён";
      $("ownerInputActionButton").textContent=item.action_button||item.field_label||"Неизвестная кнопка";
      $("ownerInputActionOrigin").textContent=item.action_origin||"Не определён";
      $("ownerInputActionSummary").textContent=item.purpose||"Описание не предоставлено";
      $("ownerInputNote").textContent=
        "Подтверждение разрешает ровно одну отправку указанной формы. Если сумма, периодичность или назначение не совпадают с ожиданиями — откажи.";
      $("ownerInputSubmit").textContent="Подтвердить действие";
    }else{
      const input=$("ownerInputValue");
      input.value="";
      input.type=type==="password"?"password":"text";
      input.inputMode=type==="otp"?"numeric":(type==="contact"?"email":"text");
      input.maxLength=type==="otp"?8:512;
      input.autocomplete="off";
      $("ownerInputVaultOption").hidden=!(type==="password"&&item.vault_save_available===true);
      $("ownerInputSaveToVault").checked=false;
      $("ownerInputVaultLabel").textContent=item.account_label?
        "Сохранить пароль для "+item.account_label+" в зашифрованном хранилище Cybernova":
        "Сохранить пароль в зашифрованном хранилище Cybernova";
      $("ownerInputNote").textContent=
        "Введённое значение передаётся локальному исполнителю и не добавляется в переписку. Сохранение пароля возможно только при отдельном выборе выше.";
      $("ownerInputSubmit").textContent="Передать и продолжить";
      input.focus();
    }
    if($("ownerInputDialog").open)$("ownerInputDialog").close();
    $("ownerInputDialog").showModal();
}
async function submitOwnerInput(){
  if(!state.sessionId||!state.ownerInputRequestId)return;
  const type=state.ownerInputType;
  let paymentCardPayload=null;
  let payload={session_id:state.sessionId,request_id:state.ownerInputRequestId};
  if(type==="payment_card"){
    const card={};
    for(const input of $("ownerInputPaymentFields").querySelectorAll("[data-payment-field]")){
      card[input.dataset.paymentField]=input.value;
      if(!input.value.trim()){
        $("ownerInputError").textContent="Заполни все поля, показанные для этой платёжной формы.";
        input.focus();
        return;
      }
    }
    const frameChecks=[...$("ownerInputPaymentFrameList").querySelectorAll("[data-payment-frame-host]")];
    const notApproved=frameChecks.find(item=>!item.checked);
    if(notApproved){
      $("ownerInputError").textContent="Подтверди платёжный домен "+notApproved.dataset.paymentFrameHost+" или отмени передачу данных.";
      return;
    }
    paymentCardPayload=card;
    payload.payment_card=paymentCardPayload;
    payload.approved_frame_hosts=frameChecks.map(item=>item.dataset.paymentFrameHost);
  }else if(type==="payment_confirmation"){
    payload.decision=true;
  }else{
    const value=$("ownerInputValue").value;
    if(!value)return;
    payload.value=value;
    payload.save_to_vault=$("ownerInputSaveToVault").checked;
  }
  $("ownerInputSubmit").disabled=true;
  try{
    const response=await fetch("/api/owner-input/submit",{
      method:"POST",headers:{"Content-Type":"application/json"},
      cache:"no-store",credentials:"same-origin",referrerPolicy:"no-referrer",
      body:JSON.stringify(payload)
    });
    const data=await response.json();
    if(!response.ok)throw Error(data.detail||"Не удалось передать данные");
    $("ownerInputDialog").close();
    resetOwnerInputValues();
    state.ownerInputRequestId=null;
    state.ownerInputType=null;
    payload=null;
  }catch(error){
    $("ownerInputError").textContent=String(error.message||error);
  }finally{
    if(paymentCardPayload){
      for(const key of Object.keys(paymentCardPayload))paymentCardPayload[key]="";
      Object.keys(paymentCardPayload).forEach(key=>delete paymentCardPayload[key]);
      paymentCardPayload=null;
    }
    $("ownerInputSubmit").disabled=false;
  }
}
async function cancelOwnerInput(){
  if(!state.sessionId||!state.ownerInputRequestId||$("ownerInputCancel").disabled)return;
  $("ownerInputCancel").disabled=true;
  try{
    await requestJson("/api/owner-input/cancel",{
      session_id:state.sessionId,request_id:state.ownerInputRequestId
    },AbortSignal.timeout(10000));
    $("ownerInputDialog").close();
    resetOwnerInputValues();
    state.ownerInputRequestId=null;
    state.ownerInputType=null;
  }catch(error){
    $("ownerInputError").textContent="Отмена не подтверждена: "+String(error.message||error);
  }finally{
    $("ownerInputCancel").disabled=false;
  }
}
async function send(){
  if(state.mode==="gpt")return sendGPT();
  const text=$("messageInput").value.trim();
  if(!text||state.qwenRunning)return;
  $("welcome")?.remove();
  renderMessage("user",text);
  $("messageInput").value="";
  resizeComposer();
  const pending=renderMessage("assistant",(state.qwenModel||"Модель")+" формирует ответ…",true);
  const runId=newRunId();
  setDiagnosticsContext({...state.diagnostics.qwen,run_id:runId},"qwen");
  state.sessionId=state.sessionId||newRunId();
  busy(true,"qwen");
  try{
    const result=await requestChatTurn({
      session_id:state.sessionId,message:text,tool_groups:state.toolGroups,
      tools_enabled:state.toolsEnabled,run_id:runId,
    },pending);
    state.sessionId=result.session_id;
    state.taskId=result.task_id||state.taskId;
    setDiagnosticsContext(result.diagnostics||{run_id:runId},"qwen");
    state.lastSeq=Math.max(state.lastSeq,result.event_seq||0);
    state.turns=result.turn||state.turns+1;
    pending.wrap.classList.remove("working");
    setFormatted(pending.body,result.answer||"Ответ модели пуст.");
    showReviewStatus(pending,result.review);
    recordUsage(result.usage,"qwen",pending);
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
    pending.body.textContent="Ошибка: "+String(exc.message||exc)+" | ID: "+runId;
    $("sendStatus").textContent="Ошибка подключения";
  }finally{
    if($("ownerInputDialog").open)$("ownerInputDialog").close();
    $("ownerInputValue").value="";
    state.ownerInputRequestId=null;
    busy(false,"qwen");$("messageInput").focus();toBottom();
  }
}
function gptWelcome(){
  $("gptMessages").replaceChildren(window.cybernovaGptWelcome.cloneNode(true));
}
function setMode(mode){
  if((mode==="collab"&&(state.qwenRunning||state.gptRunning||state.collabRunning)) || (state.collabRunning&&mode!=="collab") || !["qwen","gpt","collab"].includes(mode))return;
  state.mode=mode;
  updateDiagnosticsLinks();
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
  $("modelQuickSettings").hidden=!qwen || $("modelQuickSettings").dataset.deepseek!=="true";
  $("modelName").textContent=collab?"ChatGPT ↔ DeepSeek":state.qwenModel;
  document.querySelector(".connection-label").hidden=!qwen;
  document.querySelector(".upload-button").hidden=!qwen;
  document.querySelector(".auto-tools-label").hidden=!qwen;
  const composerArea=document.querySelector(".composer-area");
  if(composerArea)composerArea.hidden=collab;
  $("artifactFile").disabled=!qwen;
  $("messageInput").placeholder=qwen?"Сообщение исследовательской модели или задача…":"Сообщение ChatGPT…";
  $("uploadStatus").textContent=qwen?
    "Файлы до "+Math.floor(state.uploadLimit/(1024*1024))+" МиБ · Ctrl+V — вставить вывод":
    "GPT-диалог локальный · Ctrl+V — вставить вывод";
  $("sendStatus").textContent=!qwen&&!state.gptConnected?
    "Подключи ChatGPT через «Аккаунт GPT»":"Готов";
  $("sidebar").classList.remove("open");
  if(qwen){void refreshTaskList();void pollTask();}
  if(gpt)void refreshGPTThreads();
  if(collab)void refreshCollabRuns();
  if(!collab)updateTokenUsageStatus(mode);
  updateBusyUI();
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
  if(state.gptRunning)return;
  setMode("gpt");
  busy(true,"gpt");
  try{
    const response=await fetch("/api/siwc/chat?thread_id="+encodeURIComponent(threadId),{cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw Error(data.detail||"Не удалось загрузить диалог");
    state.gptThreadId=threadId;
    setDiagnosticsContext(data.diagnostics||{session_ref:null},"gpt");
    resetUsage("gpt");
    $("gptMessages").replaceChildren();
    const savedToolEvents=data.tool_events||[];
    for(const m of data.messages||[]){
      const rendered=renderMessage(m.role==="user"?"user":"chatgpt",m.content,false,"gptMessages");
      const events=savedToolEvents.filter(event=>event.message_seq===m.seq);
      if(events.length){
        const details=node("div","inline-tools");
        for(const event of events)details.append(makeToolDetails(event));
        rendered.wrap.append(details);
      }
    }
    const model=data.thread?.model;
    if(model&&[...$("gptTopModel").options].some(x=>x.value===model))
      $("gptTopModel").value=model;
    $("sidebar").classList.remove("open");
  }catch(err){
    $("sendStatus").textContent="Ошибка загрузки GPT: "+String(err.message||err);
  }finally{busy(false,"gpt");toBottom();}
}
async function sendGPT(){
  const message=$("messageInput").value.trim();
  if(!message||state.gptRunning)return;
  if(!state.gptThreadId)resetUsage("gpt");
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
  const userMessage=renderMessage("user",message,false,"gptMessages");
  $("messageInput").value="";
  resizeComposer();
  const pending=renderMessage("chatgpt","ChatGPT формирует ответ…",true,"gptMessages");
  const runId=newRunId();
  setDiagnosticsContext({...state.diagnostics.gpt,run_id:runId},"gpt");
  busy(true,"gpt");
  const usageWatch=watchUsageProgress(runId,"gpt");
  try{
    const result=await requestJson("/api/siwc/chat",{
      thread_id:state.gptThreadId,model,message,tool_groups:state.toolGroups,
      tools_enabled:state.toolsEnabled,run_id:runId
    });
    state.gptThreadId=result.thread_id;
    setDiagnosticsContext(result.diagnostics||{run_id:runId},"gpt");
    pending.wrap.classList.remove("working");
    setFormatted(pending.body,result.answer||"Ответ модели пуст.");
    recordUsage(result.usage,"gpt",pending);
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
      userMessage.wrap.append(details);
    }
    $("sendStatus").textContent=(result.source==="chatgpt_plan_responses_partial"?
      "ChatGPT прервал цикл · частичные результаты сохранены | ID: "+runId:
      "Ответ ChatGPT · диалог сохранён")+
      (result.tool_events && result.tool_events.length ? " · инструментов: "+result.tool_events.length : "");
    void refreshGPTThreads();
  void refreshCollabRuns();
  }catch(err){
    pending.wrap.classList.remove("working");
    pending.body.textContent="Ошибка: "+String(err.message||err)+" | ID: "+runId;
    $("sendStatus").textContent="Ошибка GPT";
  }finally{busy(false,"gpt");await usageWatch;$("messageInput").focus();toBottom();}
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
  if(state.qwenRunning)return;
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

function taskStatusLabel(status){
  const labels={
    idle: "Создано",
    queued: "В очереди",
    running: "В работе",
    needs_review: "Нужна проверка",
    completed: "Готово",
    blocked: "Остановлено"
  };
  return labels[String(status||"idle").toLowerCase()]||"Неизвестный статус";
}
let taskListInFlight=false,taskPollInFlight=false,collabListInFlight=false;
async function refreshTaskList(){
  if(taskListInFlight)return true;
  taskListInFlight=true;
  try{
    const response=await fetch("/api/comm/tasks",{cache:"no-store",signal:AbortSignal.timeout(8000)});
    if(!response.ok)throw Error("HTTP "+response.status);
    const body=await response.json();
    const list=$("taskList");
    list.replaceChildren();
    for(const task of (body.tasks||[]).slice(0,25)){
      const button=node("button","task-item"+(task.task_id===state.taskId?" selected":""));
      button.type="button";
      button.dataset.taskId=task.task_id;
      const taskName=String(task.title||"Исследование");
      const taskStatus=String(task.status||"idle").toLowerCase();
      const statusLabel=taskStatusLabel(taskStatus);
      const text=node("span","task-title",taskName);
      text.title=taskName;
      const status=node("span","task-state",statusLabel);
      status.dataset.status=taskStatus;
      button.title=taskName+" · "+statusLabel;
      button.setAttribute("aria-label","Открыть исследование: "+taskName+". Статус: "+statusLabel);
      button.append(text,status);
      button.addEventListener("click",()=>resumeTask(task.task_id));
      list.append(button);
    }
    if(!list.childNodes.length)list.append(node("p","muted","Пока нет исследований."));
    return true;
  }catch(error){
    if(state.mode==="qwen"&&!state.qwenRunning)
      $("sendStatus").textContent="Не удалось обновить задачи: "+String(error.message||error);
    return false;
  }finally{taskListInFlight=false;}
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
  if(state.qwenRunning)return;
  busy(true,"qwen");
  try{
    const result=await requestJson("/api/comm/resume",{task_id:taskId});
    state.sessionId=result.session_id;
    state.taskId=result.task.task_id;
    setDiagnosticsContext(result.diagnostics||{},"qwen");
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
    busy(false,"qwen");toBottom();
  }
}
async function pollTask(){
  if(!state.sessionId||!state.taskId||state.qwenRunning||taskPollInFlight)return true;
  taskPollInFlight=true;
  const sid=state.sessionId,task=state.taskId;
  try{
    const response=await fetch("/api/comm/events?session_id="+encodeURIComponent(sid)+
      "&after_seq="+state.lastSeq,{cache:"no-store",signal:AbortSignal.timeout(8000)});
    if(!response.ok)throw Error("HTTP "+response.status);
    const data=await response.json();
    if(state.sessionId!==sid||state.taskId!==task||state.qwenRunning)return;
    for(const message of data.messages||[]){
      displayTaskEvent(message);
      state.lastSeq=Math.max(state.lastSeq,message.seq||0);
    }
    showTaskStatus(data.task?.status);
    if((data.messages||[]).length)void refreshTaskList();
    return true;
  }catch(error){
    if(state.mode==="qwen")$("commState").textContent="Ошибка обновления задачи: "+String(error.message||error);
    return false;
  }finally{taskPollInFlight=false;}
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
  if(state.qwenRunning)return;
  busy(true,"qwen");
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
  }finally{busy(false,"qwen");}
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
    const accessClass=missing?"tool-missing":allowed.has(name)?"tool-auto":"tool-ask";
    const indicator=node("span","tool-access "+accessClass,
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
    setDiagnosticsContext({},"gpt");
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
  if(!model||state.gptRunning)return;
  const sid=state.sessionId, task=state.taskId;
  busy(true,"gpt");
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
    const reviewReply=renderMessage("chatgpt",answer.answer||"Ответ GPT пуст.");
    recordUsage(answer.usage,"gpt",reviewReply);
    $("chatgptToQwen").disabled=!lastGptReview;
    $("chatgptStatus").textContent="Рецензия GPT получена. Можно отправить её модели.";
  }catch(err){
    $("chatgptStatus").textContent="Ошибка рецензии: "+String(err.message||err);
  }finally{busy(false,"gpt");}
}
async function forwardGPTtoQwen(){
  if(!lastGptReview||!state.sessionId||!state.taskId||state.qwenRunning)return;
  busy(true,"qwen");
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
  }finally{busy(false,"qwen");}
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
    renderToolPicker(Array.isArray(info.tool_groups)?info.tool_groups:[]);
    if(!state.taskId)showTaskStatus(info.communication?.enabled?"Общая очередь":"Шлюз недоступен");
  }catch(_){
    $("backendDot").className="dot bad";
    $("backendStatus").textContent="Нет подключения к серверу";
    $("ollamaState").textContent="Модель недоступна";
    $("mcpState").textContent="MCP недоступен";
    renderTools([]);
    renderToolPicker([]);
  }
}
async function reset(){
  if(state.mode==="gpt"?state.gptRunning:state.mode==="collab"?state.collabRunning:state.qwenRunning)return;
  if(state.mode==="collab"){
    await newCollab();
    return;
  }
  if(state.mode==="gpt"){
    state.gptThreadId=null;
    setDiagnosticsContext({},"gpt");
    resetUsage("gpt");
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
  setDiagnosticsContext({},"qwen");
  resetUsage("qwen");
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
  $("uploadStatus").textContent="Файлы · Ctrl+V — вставить вывод · Enter — отправить";
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
  researcher:{description:"",instructions:"",behavior:{autonomy:80,initiative:75,skepticism:85,vigilance:85,neutrality:95,brevity:80}},
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
  const behavior={...d.researcher.behavior,...(researcher.behavior||{})};
  const ui=value.ui||d.ui;
  $("profileName").value=user.display_name||"";
  $("profileRole").value=user.role||"";
  $("profileAbout").value=user.about||"";
  $("profilePreferences").value=user.preferences||"";
  $("shareResearcher").checked=privacy.share_with_researcher!==false;
  $("shareChatGPT").checked=privacy.share_with_chatgpt!==false;
  $("researcherDescription").value=researcher.description||"";
  $("researcherInstructions").value=researcher.instructions||"";
  for(const key of ["autonomy","initiative","skepticism","vigilance","neutrality","brevity"]){
    const input=$("researcher"+key[0].toUpperCase()+key.slice(1));
    const output=$(input.id+"Value");
    input.value=String(behavior[key]);
    output.textContent=input.value;
  }
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
      behavior:{
        autonomy:Number($("researcherAutonomy").value),
        initiative:Number($("researcherInitiative").value),
        skepticism:Number($("researcherSkepticism").value),
        vigilance:Number($("researcherVigilance").value),
        neutrality:Number($("researcherNeutrality").value),
        brevity:Number($("researcherBrevity").value),
      },
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
async function openProfileSettings(tabName="user"){
  if(!state.profileSettings)await loadProfileSettings();
  selectProfileTab(tabName);
  const dialog=$("profileDialog");
  if(typeof dialog.showModal==="function")dialog.showModal();
  else dialog.setAttribute("open","");
  if(tabName==="model")window.dispatchEvent(new Event("cybernova:open-model-settings"));
}
async function saveProfileSettings(){
  if(state.qwenRunning||state.gptRunning||state.collabRunning)return;
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
  if(collabListInFlight)return true;
  collabListInFlight=true;
  try{
    const response=await fetch("/api/collab/runs",{cache:"no-store",signal:AbortSignal.timeout(8000)});
    if(!response.ok)throw Error("HTTP "+response.status);
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
    return true;
  }catch(error){
    if(state.mode==="collab")$("collabStatus").textContent="Ошибка обновления диалогов: "+String(error.message||error);
    return false;
  }finally{collabListInFlight=false;}
}
let backgroundTimer=null,backgroundPolling=false,backgroundFailures=0;
async function pollBackground(){
  if(backgroundPolling)return;
  backgroundPolling=true;
  let ok=true;
  try{
    if(document.visibilityState!=="hidden"){
      if(state.mode==="qwen"){
        if(state.taskId)ok=(await pollTask())!==false&&ok;
        ok=(await refreshTaskList())!==false&&ok;
      }else if(state.mode==="collab"){
        ok=(await refreshCollabRuns())!==false&&ok;
      }
    }
  }finally{
    backgroundPolling=false;
    backgroundFailures=ok?0:Math.min(4,backgroundFailures+1);
    const base=document.visibilityState==="hidden"?60000:
      state.mode==="qwen"&&state.taskId?10000:30000;
    backgroundTimer=setTimeout(()=>{void pollBackground();},
      Math.min(60000,base*Math.pow(2,backgroundFailures)));
  }
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
  if(state.collabLooping||state.qwenRunning||state.gptRunning)return;
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
  state.collabRunning=true;
  updateBusyUI();
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
    state.collabRunning=false;
    updateBusyUI();
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
  let savedEnabled=null;
  try{
    const profileVersion=window.localStorage.getItem("cybernova_tool_profile_version");
    if(profileVersion!=="2"){
      state.toolGroups=[];
      state.toolsEnabled=true;
      window.localStorage.setItem("cybernova_tool_groups","[]");
      window.localStorage.setItem("cybernova_tools_enabled","true");
      window.localStorage.setItem("cybernova_tool_profile_version","2");
      savedEnabled="true";
    }else{
      const saved=JSON.parse(window.localStorage.getItem("cybernova_tool_groups")||"[]");
      if(Array.isArray(saved))state.toolGroups=saved.filter(id=>
        TOOL_GROUP_FALLBACK.some(group=>group.id===id));
      savedEnabled=window.localStorage.getItem("cybernova_tools_enabled");
    }
  }catch(_){state.toolGroups=[];savedEnabled="true";}
  state.toolsEnabled=savedEnabled===null?true:savedEnabled==="true";
  renderToolPicker([]);
  updateDiagnosticsLinks();
  $("toolPickerToggle").addEventListener("click",()=>{
    toolPickerOpen($("toolPicker").hidden);
  });
  $("toolPickerClose").addEventListener("click",()=>toolPickerOpen(false));
  $("toolPickerAuto").addEventListener("click",()=>{
    state.toolsEnabled=true;state.toolGroups=[];persistToolGroups();renderToolPicker(state.toolGroupCatalog);
  });
  $("toolPickerOff").addEventListener("click",()=>{
    state.toolsEnabled=false;persistToolGroups();renderToolPicker(state.toolGroupCatalog);
  });
  document.addEventListener("click",event=>{
    if(!$("toolPicker").hidden&&
       !event.target.closest("#toolPicker")&&
       !event.target.closest("#toolPickerToggle"))toolPickerOpen(false);
  });
  document.addEventListener("keydown",event=>{
    if(event.key==="Escape"&&!$("toolPicker").hidden)toolPickerOpen(false);
  });
  $("sendButton").addEventListener("click",send);
  $("artifactFile").addEventListener("change",event=>importArtifact(event.target.files?.[0]));
  $("messageInput").addEventListener("input",resizeComposer);
  resizeComposer();
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
  $("navProfile").addEventListener("click",()=>openProfileSettings());
  $("modelQuickSettings").addEventListener("click",()=>openProfileSettings("model"));
  $("ownerInputSubmit").addEventListener("click",submitOwnerInput);
  $("ownerInputCancel").addEventListener("click",cancelOwnerInput);
  $("ownerInputDialog").addEventListener("cancel",event=>{event.preventDefault();void cancelOwnerInput();});
  $("ownerInputValue").addEventListener("keydown",event=>{
    if(event.key==="Enter"){event.preventDefault();void submitOwnerInput();}
  });
  $("profileClose").addEventListener("click",()=>$("profileDialog").close());
  $("profileCancel").addEventListener("click",()=>$("profileDialog").close());
  $("profileSave").addEventListener("click",saveProfileSettings);
  $("profileTabs").addEventListener("click",event=>{
    const tab=event.target.closest("[data-profile-tab]");
    if(tab)selectProfileTab(tab.dataset.profileTab);
  });
  for(const id of ["researcherAutonomy","researcherInitiative","researcherSkepticism","researcherVigilance","researcherNeutrality","researcherBrevity"]){
    $(id).addEventListener("input",()=>{$(id+"Value").textContent=$(id).value;});
  }
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
    if(sample&&!state.qwenRunning){
      $("messageInput").value=sample.dataset.prompt;send();
    }
  });
  status();
  void refreshTaskList();
  backgroundTimer=setTimeout(()=>{void pollBackground();},15000);
  document.addEventListener("visibilitychange",()=>{
    if(document.visibilityState!=="hidden"&&!backgroundPolling){
      clearTimeout(backgroundTimer);
      backgroundTimer=setTimeout(()=>{void pollBackground();},0);
    }
  });
}
window.addEventListener("cybernova:model-config-applied",event=>{
  state.qwenModel=displayModelName(event.detail?.model||state.qwenModel);
  if(state.mode==="qwen")$("modelName").textContent=state.qwenModel;
});
document.addEventListener("DOMContentLoaded",init);
