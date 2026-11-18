/* Cybernova Research Console — intentionally no external dependencies.
 * Tool descriptions are declarative; all user/source content uses textContent.
 * The browser cannot execute arbitrary target commands or scripts.
 */
"use strict";
const $ = (selector) => document.querySelector(selector);
const ui = {tools:{},planned:[],selected:"plan_build",filter:"ready",search:"",view:"overview",
            status:null,project:null,findings:[],report:""};
const CSRF = document.querySelector('meta[name="cybernova-csrf"]').content;

function node(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined && value !== null) element.textContent = String(value);
  return element;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
function appendText(parent, tag, className, text) {
  const child=node(tag,className,text); parent.appendChild(child); return child;
}
async function request(path, options) {
  const response = await fetch(path, Object.assign({cache:"no-store"},options||{}));
  let data;
  try { data=await response.json(); }
  catch (_e) { throw new Error("Некорректный ответ локального сервера"); }
  if (!response.ok || data.ok===false) throw new Error(data.error || "Ошибка ответа");
  return data;
}
function toast(text) {
  const t=$("#toast"); t.textContent=String(text); t.classList.add("show");
  if (toast.timer) clearTimeout(toast.timer);
  toast.timer=setTimeout(()=>t.classList.remove("show"),3500);
}
function setConnection(online) {
  $("#serviceLabel").textContent=online?"Контроллер доступен":"Нет соединения";
  const dot=$(".connection-status .dot");
  dot.style.background=online?"#94dbb2":"#ee987d";
}
function route(name) {
  ui.view=name;
  document.querySelectorAll(".page-view").forEach(e=>e.classList.toggle("is-hidden",e.id!=="view-"+name));
  document.querySelectorAll(".nav-button").forEach(e=>e.classList.toggle("is-current",e.dataset.nav===name));
  const titles={overview:"Обзор",tools:"Инструменты",cases:"Гипотезы и факты",report:"Отчёт"};
  $("#pageBreadcrumb").textContent=titles[name]||name;
  if (name==="cases") refreshCases();
  if (name==="report") refreshReport();
}
function renderOverview() {
  const project=ui.project||{};
  $("#metricReady").textContent=Object.keys(ui.tools).length || "—";
  $("#metricCatalog").textContent=(ui.status && ui.status.result
      ? ui.status.result.registered_capabilities : Object.keys(ui.tools).length+ui.planned.length) || "—";
  $("#metricFindings").textContent=ui.findings.length;
  $("#scopeBadge").textContent=String(project.status||"UNKNOWN").toUpperCase();
  $("#projectName").textContent=project.name||"Нет выбранного проекта";
  const assets=$("#assetRows"); clear(assets);
  for (const a of project.assets||[]) {
    const row=node("div","asset");
    const detail=node("div");
    appendText(detail,"span","asset-name",a.hostname||"unknown");
    appendText(detail,"span","asset-label",a.label||"");
    row.appendChild(detail);
    appendText(row,"span","asset-status",a.in_scope?"в списке scope":"не разрешено");
    assets.appendChild(row);
  }
  $("#projectMini").textContent=project.name||"Исследование";
  $("#projectMiniState").textContent="Статус: "+String(project.status||"unknown").toUpperCase();
}
function renderTools() {
  const list=$("#toolList"); clear(list);
  const filter=ui.filter, q=ui.search.toLowerCase().trim();
  const entries=[];
  if (filter!=="planned") for (const [name, info] of Object.entries(ui.tools)) {
    entries.push(Object.assign({name,ready:true},info));
  }
  if (filter!=="ready") for (const info of ui.planned) entries.push(Object.assign({ready:false},info));
  const groups=new Map();
  for (const item of entries) {
    if (q && !(item.name+" "+(item.label||"")+" "+(item.description||"")).toLowerCase().includes(q)) continue;
    const group=item.group||"Запланированные";
    if (!groups.has(group)) groups.set(group,[]);
    groups.get(group).push(item);
  }
  if (!groups.size) {appendText(list,"div","empty-state","По запросу ничего не найдено");return;}
  for (const [group,items] of groups.entries()) {
    appendText(list,"div","tool-group-heading",group.toUpperCase()+" / "+items.length);
    for (const item of items) {
      const button=node("button","tool-card"+(item.ready?"":" is-planned")+
                        (ui.selected===item.name?" selected":""));
      button.type="button";
      button.setAttribute("aria-label",(item.label||item.name)+" — "+(item.ready?"готов":"запланирован"));
      const content=node("div");
      appendText(content,"span","tool-card-title",item.label||item.name);
      appendText(content,"span","tool-card-code",item.name);
      button.appendChild(content);
      appendText(button,"span","tool-card-mark",item.ready?"● ГОТОВ":"○ PLAN");
      button.addEventListener("click",()=>selectTool(item.name));
      list.appendChild(button);
    }
  }
}
const choices = {
  scheme:["https","http"],
  impact:["low","medium","high"],
  likelihood:["low","medium","high"],
  confidence:["low","medium","high"],
  state:["observation","hypothesis","verified","rejected"]
};
function selectTool(name) {
  ui.selected=name;
  const ready=Object.prototype.hasOwnProperty.call(ui.tools,name);
  const item=ready?ui.tools[name]:ui.planned.find(x=>x.name===name);
  if (!item) return;
  $("#activeToolName").textContent=item.label||name;
  $("#activeToolCode").textContent=name;
  $("#activeToolDescription").textContent=item.description||"Описание отсутствует";
  $("#toolMode").textContent=ready?"OFFLINE / READY":"PLANNED / NOT INSTALLED";
  $("#toolMode").className=ready?"status ready":"status neutral";
  $("#toolContextText").textContent=ready?
      "Локальная проверка. Сеть и shell не используются.":
      "Адаптер не реализован. Запуск отключён.";
  const container=$("#toolFields"); clear(container);
  const button=$("#runTool"); button.disabled=!ready;
  button.textContent=ready?"Выполнить проверку →":"Инструмент ещё не подключён";
  if (ready) for (const fld of item.fields||[]) {
    const wrapper=node("div","form-field");
    const label=node("label","form-label",fld.label||fld.name);
    const id="field-"+fld.name;
    label.setAttribute("for",id);
    wrapper.appendChild(label);
    let input;
    if (fld.type==="textarea"||fld.type==="code"||fld.type==="json") {
      input=node("textarea","field-input");
      input.rows=fld.type==="json"?7:5;
    } else if (fld.type==="select") {
      input=node("select","field-input");
      const list=choices[fld.name]||[];
      for (const opt of list) {
        const option=node("option","",opt);
        option.value=opt;
        input.appendChild(option);
      }
    } else {
      input=node("input","field-input"); input.type="text";
    }
    input.id=id; input.name=fld.name; input.required=!!fld.required;
    input.placeholder=fld.placeholder||"";
    if (fld.default!==null && fld.default!==undefined) input.value=fld.default;
    wrapper.appendChild(input);
    container.appendChild(wrapper);
  }
  $("#resultState").textContent=ready?
      "Результат следующего локального запуска появится здесь.":
      "Недоступен: это только запись реестра, а не действующая функция.";
  $("#resultOutput").textContent="";
  renderTools();
}
async function runTool(ev) {
  ev.preventDefault();
  const name=ui.selected;
  if (!Object.prototype.hasOwnProperty.call(ui.tools,name)) {
    toast("Инструмент не реализован");return;
  }
  const args={};
  for (const fld of ui.tools[name].fields||[]) {
    const field=$("#field-"+fld.name);
    if (field) args[fld.name]=field.value;
  }
  const button=$("#runTool"); button.disabled=true; button.textContent="Проверка...";
  $("#resultState").textContent="Выполняется локальная проверка...";
  try {
    const result=await request("/api/run",{method:"POST",
      headers:{"Content-Type":"application/json","X-Cybernova-CSRF":CSRF},
      body:JSON.stringify({tool:name,arguments:args})});
    $("#resultOutput").textContent=JSON.stringify(result,null,2);
    $("#resultState").textContent="Получен фактический ответ контроллера.";
    if (name==="finding_create"||name==="finding_verify") refreshCases();
    toast("Инструмент выполнен: "+name);
  } catch (error) {
    $("#resultOutput").textContent="";
    $("#resultState").textContent="Ошибка: "+error.message;
    toast("Проверка не выполнена: "+error.message);
  } finally {
    button.disabled=false;
    button.textContent="Выполнить проверку →";
  }
}
async function refreshCases() {
  try {
    const [caseData,eventData]=await Promise.all([request("/api/findings"),request("/api/events")]);
    ui.findings=caseData.items||[];
    $("#casesCount").textContent=ui.findings.length+" записей";
    $("#metricFindings").textContent=ui.findings.length;
    const target=$("#caseItems"); clear(target);
    if (!ui.findings.length) appendText(target,"div","empty-state","Пока нет гипотез. Добавь первое наблюдение с указанием актива и источника.");
    for (const item of ui.findings) {
      const row=node("article","case-entry");
      appendText(row,"div","case-title",item.title);
      const meta=node("div","case-meta");
      appendText(meta,"span","",item.id);
      appendText(meta,"span","",item.state.toUpperCase());
      appendText(meta,"span","",item.asset);
      appendText(meta,"span","",item.confidence+" confidence");
      row.appendChild(meta);
      appendText(row,"div","case-desc",item.summary);
      target.appendChild(row);
    }
    const events=$("#eventItems"); clear(events);
    if (!(eventData.items||[]).length) appendText(events,"div","empty-state","Журнал пока пуст.");
    for (const event of eventData.items||[]) {
      const row=node("div","event-entry");
      appendText(row,"span","",event.timestamp.slice(0,19));
      appendText(row,"span","",event.action);
      appendText(row,"span","",event.status);
      events.appendChild(row);
    }
  } catch (error) { toast("Не удалось получить записи: "+error.message); }
}
async function refreshReport() {
  try {
    const data=await request("/api/report");
    ui.report=data.result.markdown||"";
    $("#reportOutput").textContent=ui.report;
  } catch (error) { $("#reportOutput").textContent="Ошибка: "+error.message; }
}
async function copyText(text) {
  if (!text) {toast("Нет содержимого для копирования");return;}
  try {await navigator.clipboard.writeText(text);toast("Скопировано");}
  catch (_e) {toast("Браузер не разрешил копирование");}
}
async function init() {
  document.querySelectorAll(".nav-button").forEach(b=>b.addEventListener("click",()=>route(b.dataset.nav)));
  document.querySelectorAll(".filter").forEach(b=>b.addEventListener("click",()=>{
    ui.filter=b.dataset.filter;
    document.querySelectorAll(".filter").forEach(x=>x.classList.toggle("active",x===b));
    renderTools();
  }));
  $("#toolSearch").addEventListener("input",e=>{ui.search=e.target.value;renderTools();});
  $("#toolForm").addEventListener("submit",runTool);
  $("#quickPlan").addEventListener("click",()=>{route("tools");selectTool("plan_build");});
  $("#newFinding").addEventListener("click",()=>{route("tools");selectTool("finding_create");});
  $("#refreshCases").addEventListener("click",refreshCases);
  $("#refreshReport").addEventListener("click",refreshReport);
  $("#copyReport").addEventListener("click",()=>copyText(ui.report));
  $("#copyOutput").addEventListener("click",()=>copyText($("#resultOutput").textContent));
  try {
    const [status,tools,project,findings]=await Promise.all([
      request("/api/status"),request("/api/tools"),request("/api/project"),request("/api/findings")]);
    ui.status={result:{registered_capabilities:tools.registered_total}};
    ui.tools=tools.available||{};
    ui.planned=tools.planned||[];
    ui.project=project;
    ui.findings=findings.items||[];
    setConnection(true);
    renderOverview();
    selectTool("plan_build");
  } catch (error) {
    setConnection(false);
    toast("Не удалось загрузить контроллер: "+error.message);
    $("#resultState").textContent=error.message;
  }
}
document.addEventListener("DOMContentLoaded",init);
