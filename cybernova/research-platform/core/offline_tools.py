"""Cybernova's small *working* offline capability layer.

Not a scanner. This intentionally provides independently verifiable analysis
utilities and case management before privileged adapters are connected.
UI and future MCP wrappers call the same dispatch_tool interface.
"""
from __future__ import annotations

import ast
from collections import Counter
import ipaddress
import json
import re
from urllib.parse import urlsplit

from core import policy, evidence

def field(name, label, kind="text", required=True, placeholder="", default=None):
    return {"name":name,"label":label,"type":kind,"required":required,
            "placeholder":placeholder,"default":default}

SPECS = {
    "gateway_status": {"label":"Состояние лаборатории","group":"Контроль","fields":[],
        "description":"Реальный статус локального контроллера и текущей области"},
    "tool_catalog": {"label":"Реестр инструментов","group":"Контроль","fields":[],
        "description":"Что реализовано, что только запланировано"},
    "engagement_validate": {"label":"Проверка допуска","group":"Контроль","fields":[],
        "description":"Проверить согласование целей и ограничения профиля"},
    "scope_check": {"label":"Проверка цели","group":"Контроль",
        "fields":[field("url","Адрес объекта",placeholder="https://example.org/")],
        "description":"Проверка соответствия точному FQDN и пути; без сетевого обращения"},
    "plan_build": {"label":"Создать план","group":"Исследование","fields":[],
        "description":"Пошаговая схема аудита со статусом доступа"},
    "plan_validate": {"label":"Проверить план","group":"Контроль",
        "fields":[field("steps","Шаги: JSON-массив","json",
        placeholder='[{"tool":"http_get","url":"https://example.org/"}]')],
        "description":"Dry-run допуска инструментов; не выполняет действия"},
    "asset_inventory": {"label":"Карта активов","group":"Исследование","fields":[],
        "description":"Кандидаты, scope и доверенные границы из профиля проекта"},
    "threat_model_build": {"label":"Модель угроз","group":"Исследование",
        "fields":[field("components","Компоненты системы, по одному в строке","textarea",
                        placeholder="Браузер\nReverse proxy\nWeb API\nБиллинг"),
                  field("trust_boundaries","Границы доверия","textarea",False,
                        "Браузер ↔ Web API\nWeb API ↔ Биллинг")],
        "description":"Список компонентов, границ и вопросов к архитектуре"},
    "ip_network_summary": {"label":"Расчёт подсети","group":"Офлайн-анализ",
        "fields":[field("cidr","IP / CIDR",placeholder="192.0.2.0/24")],
        "description":"IPv4/IPv6 без сетевых запросов"},
    "http_header_review": {"label":"HTTP-заголовки","group":"Офлайн-анализ",
        "fields":[field("raw_headers","Заголовки ответа","textarea",
                        placeholder="HTTP/1.1 200 OK\nContent-Type: text/html\n..."),
                  field("scheme","Схема","select",False,default="https")],
        "description":"Разбор вставленных заголовков без подключения к сайту"},
    "python_static_review": {"label":"Python SAST","group":"Офлайн-анализ",
        "fields":[field("source","Исходный код Python","code",
                        placeholder="import sqlite3\n...")],
        "description":"AST-анализ ограниченного набора опасных конструкций"},
    "api_schema_import": {"label":"Карта API из OpenAPI","group":"Офлайн-анализ",
        "fields":[field("schema","OpenAPI 3.x / Swagger 2.x JSON","json",
                        placeholder='{"openapi":"3.0.3","paths":{"/health":{"get":{}}}}')],
        "description":"Локальный импорт API схемы, без HTTP запросов"},
    "evidence_hash": {"label":"Хеш доказательства","group":"Доказательства",
        "fields":[field("content","Данные артефакта (не сохраняются)","textarea")],
        "description":"SHA-256 строки; сырое содержание не сохраняется в журнале"},
    "evidence_redact": {"label":"Маскировка данных","group":"Доказательства",
        "fields":[field("content","Текст для маскирования","textarea")],
        "description":"Приближённая маскировка; не заменяет ручную проверку PII"},
    "risk_assess": {"label":"Матрица риска","group":"Исследование",
        "fields":[field("impact","Потенциальное влияние: low / medium / high","select",default="medium"),
                  field("likelihood","Вероятность: low / medium / high","select",default="medium")],
        "description":"Качественная оценка, не CVSS и не доказательство"},
    "finding_create": {"label":"Новая гипотеза","group":"Доказательства",
        "fields":[field("title","Заголовок"),
                  field("asset","Объект (без токенов/параметров)"),
                  field("summary","Описание наблюдения","textarea"),
                  field("state","Состояние","select",False,default="hypothesis"),
                  field("confidence","Уверенность","select",False,default="low")],
        "description":"Сохранить наблюдение; подтверждение требует отдельного ревью"},
    "finding_verify": {"label":"Ревью вывода","group":"Доказательства",
        "fields":[field("finding_id","ID гипотезы",placeholder="F-..."),
                  field("state","Итог: verified / rejected","select",default="rejected"),
                  field("reviewer","Кто проверил"),
                  field("evidence_sha256","SHA-256 доказательства","text",False)],
        "description":"Подтверждение требует reviewer и SHA-256 артефакта"},
    "finding_list": {"label":"Список выводов","group":"Доказательства","fields":[],
        "description":"Реально сохранённые findings из локальной базы"},
    "audit_event_log": {"label":"Журнал событий","group":"Контроль","fields":[],
        "description":"Метаданные о запуске действий без сырых секретов"},
    "report_generate": {"label":"Сформировать отчёт","group":"Отчёт","fields":[],
        "description":"Markdown отчёт по сохранённым выводам и статусам проверки"},
}
GROUPS = ["Контроль", "Исследование", "Офлайн-анализ", "Доказательства", "Отчёт"]
RISK_LEVELS = {"low":1,"medium":2,"high":3}

class ToolError(ValueError):
    pass


def _str(args, name, maximum=60000, minimum=0):
    value = args.get(name, "")
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ToolError(f"{name}: expected text length {minimum}..{maximum}")
    return value


def _choice(args, name, choices, default):
    val = args.get(name, default)
    if val not in choices:
        raise ToolError(f"{name}: must be one of {', '.join(choices)}")
    return val


def _json_input(args, name, max_len=60000):
    raw = args.get(name)
    if isinstance(raw, str):
        if len(raw.encode("utf-8")) > max_len:
            raise ToolError(f"{name}: input too large")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise ToolError(f"{name}: invalid JSON") from None
    return raw


def _headers(args, ctx):
    raw=_str(args,"raw_headers",40000)
    scheme=_choice(args,"scheme",("http","https"),"https")
    observed={}
    for line in raw.splitlines():
        if ":" not in line or line.strip().startswith("HTTP/"):
            continue
        key, value = line.split(":",1)
        key=key.strip().lower()
        if re.fullmatch(r"[a-z0-9-]{1,70}",key):
            observed[key]=value.strip()[:400]
    kept=evidence.redact_headers(observed)
    controls={}
    for key in ("strict-transport-security","content-security-policy",
                "x-content-type-options","x-frame-options","referrer-policy",
                "permissions-policy","cache-control"):
        controls[key]="observed" if key in kept else "not_observed_in_supplied_headers"
    return {"scheme":scheme,"count":len(observed),"safe_headers":kept,
            "controls":controls,"classification":"configuration_observation_not_verified_vulnerability",
            "warning":"Completeness depends on the supplied response and route; no target was contacted"}


def _static(args,ctx):
    source=_str(args,"source",50000)
    try:
        tree=ast.parse(source)
    except SyntaxError as ex:
        return {"parse_ok":False,"error":"SyntaxError","line":ex.lineno,
                "observation_count":0}
    observations=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.Call):
            func=node.func
            fullname=""
            if isinstance(func,ast.Name):
                fullname=func.id
            elif isinstance(func,ast.Attribute):
                fullname=func.attr
                if isinstance(func.value,ast.Name):
                    fullname=func.value.id+"."+func.attr
            if fullname in {"eval","exec","pickle.loads","yaml.load",
                            "os.system","subprocess.Popen","subprocess.run"}:
                observations.append({"line":node.lineno,"kind":"dangerous_api_indicator",
                    "symbol":fullname,"confidence":"low","note":"Requires context and dataflow verification"})
            if fullname in {"execute","executemany"}:
                if node.args and isinstance(node.args[0],ast.BinOp):
                    observations.append({"line":node.lineno,"kind":"dynamic_sql_candidate",
                        "symbol":fullname,"confidence":"low","note":"Check parameterized SQL usage"})
    return {"parse_ok":True,"lines":len(source.splitlines()),"observations":observations[:50],
            "observation_count":len(observations),
            "classification":"static_heuristic_not_confirmed_vulnerability"}


def _ip(args,ctx):
    raw=_str(args,"cidr",100,1)
    try:
        net=ipaddress.ip_network(raw,strict=False)
    except ValueError:
        raise ToolError("cidr: invalid network") from None
    return {"network":str(net),"version":net.version,"prefixlen":net.prefixlen,
            "network_address":str(net.network_address),
            "last_address":str(net.broadcast_address),
            "total_addresses":net.num_addresses,"is_global":net.is_global,
            "note":"Offline calculation; no hosts probed"}


def _api_schema(args,ctx):
    data=_json_input(args,"schema",50000)
    if not isinstance(data,dict) or not (
        isinstance(data.get("openapi"),str) or isinstance(data.get("swagger"),str)):
        raise ToolError("schema must be an OpenAPI 3.x or Swagger JSON object")
    paths=data.get("paths")
    if not isinstance(paths,dict) or len(paths)>1000:
        raise ToolError("paths must be a JSON object of at most 1000 entries")
    methods=("get","post","put","patch","delete","head","options","trace")
    endpoints=[]
    for path,entry in paths.items():
        if not isinstance(path,str) or not path.startswith("/") or not isinstance(entry,dict):
            continue
        for method in methods:
            operation=entry.get(method)
            if isinstance(operation,dict):
                endpoints.append({"path":path[:180],"method":method.upper(),
                    "operation_id":str(operation.get("operationId",""))[:100],
                    "declares_security":bool(operation.get("security", data.get("security", [])))})
            if len(endpoints)>1500:
                raise ToolError("too many endpoints")
    return {"openapi_version":data.get("openapi",data.get("swagger")),
            "declared_servers":len(data.get("servers",[])) if isinstance(data.get("servers"),list) else 0,
            "path_count":len(paths),"endpoint_count":len(endpoints),
            "endpoints":endpoints[:120],
            "truncated":len(endpoints)>120,
            "note":"A schema describes intended APIs; no endpoint was contacted and no exposure was established"}


def _assets(args,ctx):
    eng=ctx["engagement"]
    nodes=[]
    for asset in eng.get("assets",[]):
        if isinstance(asset,dict):
            nodes.append({"hostname":asset.get("hostname"),"label":asset.get("label",""),
                          "in_scope":asset.get("in_scope") is True,
                          "notes":asset.get("notes","")[:200]})
    return {"project":eng.get("project"),"authorization_status":eng.get("status"),
            "assets":nodes,
            "warning":"Candidate != approved; ownership and authorization must be verified"}


def _threat(args,ctx):
    components=[s.strip()[:100] for s in _str(args,"components",4000,2).splitlines() if s.strip()]
    boundaries=[s.strip()[:140] for s in _str(args,"trust_boundaries",3000).splitlines() if s.strip()]
    if len(components)>40 or len(boundaries)>50:
        raise ToolError("too many components or trust boundaries")
    return {"components":list(dict.fromkeys(components)),
            "trust_boundaries":list(dict.fromkeys(boundaries)),
            "questions":[
                "Where is server-side authorization enforced?",
                "Which component holds secrets and sensitive data?",
                "Where is identity translated into object ownership?",
                "How are mutations, logs, audit records and retries handled?",
                "Where can untrusted data cross a trust boundary?"
            ],"status":"draft_model_not_verified"}


def _build_plan(args,ctx):
    stages=[
        {"stage":"S0","title":"Авторизация и точный scope","gate":"required"},
        {"stage":"S1","title":"Инвентарь активов и зависимости","gate":"offline_first"},
        {"stage":"S2","title":"Карта маршрутов и потоков данных","gate":"authorization_before_network"},
        {"stage":"S3","title":"Границы доверия и модель угроз","gate":"offline"},
        {"stage":"S4","title":"Конфигурация HTTP/DNS/TLS","gate":"authorization_before_network"},
        {"stage":"S5","title":"Идентификация, сессии, роли","gate":"test_accounts_required"},
        {"stage":"S6","title":"Контроль доступа к объектам API","gate":"synthetic_objects_required"},
        {"stage":"S7","title":"Валидация входов и бизнес-логика","gate":"staging_first"},
        {"stage":"S8","title":"Код, зависимости и инфраструктура","gate":"separate_scope"},
        {"stage":"S9","title":"Доказательства и опровержения","gate":"evidence_required"},
        {"stage":"S10","title":"Исправления и повторная проверка","gate":"owner_review"}
    ]
    return {"project":ctx["engagement"].get("project"),"stage_count":len(stages),
            "stages":stages,"next_step":"Agree a Rules of Engagement document before active checks",
            "execution":"planning_only"}


def _scope(args,ctx):
    url=_str(args,"url",2048,4)
    target,error=policy._scope_target(ctx["engagement"],url)
    return {"in_listed_scope":error=="", "reason":error or "listed_asset",
            "authorization_status":ctx["engagement"].get("status"),
            "can_execute_network":False,
            "message":"Listing a target is not legal or operational authorization"}


def _risk(args,ctx):
    impact=_choice(args,"impact",tuple(RISK_LEVELS),"medium")
    likelihood=_choice(args,"likelihood",tuple(RISK_LEVELS),"medium")
    score=RISK_LEVELS[impact]*RISK_LEVELS[likelihood]
    return {"impact":impact,"likelihood":likelihood,
            "qualitative_risk":"high" if score>=6 else "medium" if score>=3 else "low",
            "score":score,"note":"Informal triage only, not CVSS or validated impact"}


def _make_finding(args,ctx):
    title=_str(args,"title",180,5)
    asset=_str(args,"asset",300,3)
    summary=_str(args,"summary",1200,5)
    for val in (title,asset,summary):
        if evidence.redact_text(val)!=val or re.search(r"(?i)(authorization:\s*|set-cookie:\s*)",val):
            raise ToolError("Sensitive-looking content detected; redact it before saving")
    if "?" in asset or "#" in asset or "@" in asset:
        raise ToolError("asset must not contain URL query, fragment or credentials")
    confidence=_choice(args,"confidence",("low","medium","high"),"low")
    state=_choice(args,"state",("observation","hypothesis"),"hypothesis")
    fid=ctx["store"].add_finding(title,asset,summary,state,confidence)
    return {"id":fid,"state":state,"saved":True,
            "warning":"No vulnerability has been confirmed by creating a record"}


def _verify(args,ctx):
    fid=_str(args,"finding_id",96,3)
    reviewer=_str(args,"reviewer",90,3)
    state=_choice(args,"state",("verified","rejected"),"rejected")
    digest=_str(args,"evidence_sha256",64)
    ctx["store"].review_finding(fid,state,reviewer,digest or None)
    return {"id":fid,"state":state,"reviewed_by":reviewer,
            "note":"Hash and human review are metadata; independently validate artifact authenticity and impact"}


def _report(args,ctx):
    eng=ctx["engagement"]
    findings=ctx["store"].list_findings(100)
    counts=Counter(f["state"] for f in findings)
    lines=["# Cybernova — исследовательский отчёт",
           "",f"Проект: {eng.get('project','?')}",
           f"Статус разрешения: {eng.get('status','?')}",
           f"Всего записей: {len(findings)}; подтверждено: {counts.get('verified',0)}; гипотез: {counts.get('hypothesis',0)}",
           "",
           "## Выводы"]
    for f in findings:
        lines.extend(["",f"### {f['id']}: {f['title']}",
                      f"Актив: {f['asset']}",
                      f"Состояние: {f['state']}; уверенность: {f['confidence']}",
                      f"Наблюдение: {f['summary']}",
                      f"Артефакт SHA-256: {f['evidence_sha256'] or 'не указан'}"])
    lines.extend(["","## Ограничения",
       "Доступность активов и отсутствие ошибок не подтверждались автоматически.",
       "Гипотезы не являются доказанными уязвимостями.",
       "Отчёт построен из локально предоставленных сведений; реальные тесты не запускались."])
    return {"markdown":"\n".join(lines),"findings":len(findings),
            "verified":counts.get("verified",0),"source":"local_case_store_only"}


def _dispatch(name,args,ctx):
    if name=="gateway_status":
        implemented=list(SPECS)
        return {"service":"Cybernova Research Controller","status":"offline_ready",
                "project":ctx["engagement"].get("project"),
                "engagement":ctx["engagement"].get("status"),
                "implemented_offline_tools":len(implemented),
                "network_scanning_available":False,
                "tool_names":implemented}
    if name=="tool_catalog":
        expected=ctx["catalog"].get("tools",[])
        return {"registered_capabilities":len(expected),
                "offline_executable_here":list(SPECS),
                "not_executable_here":[t["name"] for t in expected if t["name"] not in SPECS],
                "note":"Manifest entries and remote MCP programs are not automatically executable here"}
    if name=="engagement_validate":
        eng=ctx["engagement"]
        return {"valid_structure":not policy.validate_engagement(eng),
                "errors":policy.validate_engagement(eng),
                "status":eng.get("status"),"network_authorized":False}
    if name=="scope_check":return _scope(args,ctx)
    if name=="plan_build":return _build_plan(args,ctx)
    if name=="plan_validate":
        steps=_json_input(args,"steps",30000)
        return policy.validate_plan(ctx["engagement"],ctx["catalog"],steps)
    if name=="asset_inventory":return _assets(args,ctx)
    if name=="threat_model_build":return _threat(args,ctx)
    if name=="ip_network_summary":return _ip(args,ctx)
    if name=="http_header_review":return _headers(args,ctx)
    if name=="python_static_review":return _static(args,ctx)
    if name=="api_schema_import":return _api_schema(args,ctx)
    if name=="evidence_hash":
        raw=_str(args,"content",60000,1).encode("utf-8")
        return {"algorithm":"SHA-256","sha256":evidence.sha256_hex(raw),
                "bytes_hashed":len(raw),"raw_content_saved":False}
    if name=="evidence_redact":
        content=_str(args,"content",20000)
        return {"redacted":evidence.redact_text(content),
                "warning":"Best-effort masking; inspect manually before sharing"}
    if name=="risk_assess":return _risk(args,ctx)
    if name=="finding_create":return _make_finding(args,ctx)
    if name=="finding_verify":return _verify(args,ctx)
    if name=="finding_list":return {"findings":ctx["store"].list_findings()}
    if name=="audit_event_log":return {"events":ctx["store"].list_events()}
    if name=="report_generate":return _report(args,ctx)
    raise ToolError("Unknown or unimplemented tool")


def dispatch_tool(name:str,args:dict,ctx:dict):
    if not isinstance(name,str) or name not in SPECS:
        raise ToolError("Tool unavailable in this runtime")
    if not isinstance(args,dict) or len(args)>20:
        raise ToolError("Arguments must be a small JSON object")
    # Only this fixed set of offline tools is callable. No shell/network adapters.
    try:
        result=_dispatch(name,args,ctx)
    except (KeyError,TypeError) as exc:
        raise ToolError("Invalid arguments: "+type(exc).__name__) from None
    return {"ok":True,"tool":name,"mode":"offline","result":result}
