"""Cybernova Traffic Intelligence: offline, credential-blind HAR/JS analysis.

Processes a user-supplied copy of their own browser export. Does not fetch
network targets, replay requests, execute JS, or retain request/response values.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re
from urllib.parse import urlsplit, parse_qsl

MAX_SOURCE_BYTES = 6_000_000
MAX_ENTRIES = 2500
MAX_RESPONSE_SCHEMA_BYTES = 180_000
MAX_JS_ENDPOINTS = 180
MAX_GRAPH_ITEMS = 160
MAX_FIELD_NAMES = 90
SEGMENT_SECRET = re.compile(
    r"^(?:[0-9]{4,}|[a-f0-9]{16,}|[0-9a-f]{8}-[0-9a-f-]{27,}|[^/@]+@[^/@]+)$", re.I
)
FIELD_NAME = re.compile(r"^[A-Za-z_$][\w.$-]{0,72}$")
INTERESTING = re.compile(
    r"(?:^|_)(?:user|client|account|contract|subscriber|customer|invoice|"
    r"payment|billing|balance|tariff|plan|token|password|secret|role|"
    r"permission|is_admin|access|radius|device|mac|ip|session|order|"
    r"transaction|receipt|internal|employee|staff|credit|debit)(?:_|$)", re.I
)
ID_HINT = re.compile(r"(?:^|[_-])(?:id|uid|user_id|account_id|contract_id|client_id|subscriber_id)(?:$|[_-])", re.I)
AUTH_KEY = re.compile(r"(?:authorization|cookie|x-api-key|proxy-authorization)", re.I)
SENSITIVE_QUERY = re.compile(r"(?:password|passwd|token|secret|authorization|api_key|access_key|session)", re.I)
API_PATH = re.compile(r"(?:/api(?:/|$)|/graphql(?:/|$)|/rest(?:/|$)|/v\d+(?:/|$)|/ajax(?:/|$)|/billing(?:/|$))", re.I)
JS_SOURCES = {
    "location_source": re.compile(r"\b(?:location\.(?:hash|search|href)|document\.URL|URLSearchParams)\b"),
    "postmessage_source": re.compile(r"\b(?:addEventListener\s*\(\s*['\"]message|onmessage\s*=)\b"),
    "storage_source": re.compile(r"\b(?:localStorage|sessionStorage)\b"),
}
JS_SINKS = {
    "html_sink": re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b"),
    "dynamic_execution": re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"])"),
    "network_request": re.compile(r"\b(?:fetch\s*\(|XMLHttpRequest|axios\s*\.|\.ajax\s*\()\b"),
}
JS_URL = re.compile(
    r"""(?:(?:["'])(?P<path>/(?:api|rest|graphql|v[0-9]+|ajax|billing)/[A-Za-z0-9_./{}:$?-]{0,200}|/(?:graphql|api|rest))(?:["']))""",
    re.I,
)


class TrafficError(ValueError):
    pass


def _text(value: object, cap: int = 120) -> str:
    return str(value or "").replace("\r", "").replace("\n", " ")[:cap]


def safe_path(value: object) -> str:
    """Keep only path structure. No query, fragment, userinfo or path IDs."""
    if not isinstance(value, str) or len(value) > 4000:
        return "/[invalid]"
    try:
        u = urlsplit(value)
    except ValueError:
        return "/[invalid]"
    path = u.path or "/"
    if not path.startswith("/"):
        return "/[relative]"
    parts = []
    for segment in path.split("/")[1:18]:
        if not segment:
            continue
        if SEGMENT_SECRET.match(segment) or len(segment) > 64 or "%" in segment:
            parts.append("{object}")
        else:
            parts.append(re.sub(r"[^A-Za-z0-9._{}:-]", "_", segment)[:64])
    return "/" + "/".join(parts)


def safe_host(value: object) -> str:
    try:
        u = urlsplit(str(value))
        host = (u.hostname or "").lower()
        if u.scheme not in ("http", "https") or not host or len(host) > 150:
            return "[invalid-host]"
        if not re.fullmatch(r"[a-z0-9.\-:\[\]]+", host):
            return "[invalid-host]"
        return host
    except (ValueError, TypeError):
        return "[invalid-host]"


def _headers(raw) -> dict:
    """Header names and safe flags only; never return cookie/token values."""
    items = raw if isinstance(raw, list) else []
    out = {}
    for h in items[:150]:
        if not isinstance(h, dict):
            continue
        name = _text(h.get("name"), 80).lower()
        if not re.fullmatch(r"[a-z0-9-]{1,70}", name):
            continue
        if name not in out:
            out[name] = str(h.get("value") or "")[:16000]
    return out


def _json_fieldnames(blob, depth=0, out=None) -> set:
    if out is None:
        out = set()
    if depth > 7 or len(out) >= MAX_FIELD_NAMES:
        return out
    if isinstance(blob, dict):
        for key, val in list(blob.items())[:150]:
            if isinstance(key, str) and FIELD_NAME.fullmatch(key):
                out.add(key)
            _json_fieldnames(val, depth + 1, out)
    elif isinstance(blob, list):
        for val in blob[:3]:
            _json_fieldnames(val, depth + 1, out)
    return out


def _body_keys(content: object) -> list[str]:
    if not isinstance(content, dict):
        return []
    mime = str(content.get("mimeType") or "").lower()
    body = content.get("text")
    if not isinstance(body, str) or not body or len(body) > MAX_RESPONSE_SCHEMA_BYTES:
        return []
    if "json" not in mime and not body.lstrip().startswith(("{", "[")):
        return []
    try:
        return sorted(_json_fieldnames(json.loads(body)))[:MAX_FIELD_NAMES]
    except (TypeError, ValueError, RecursionError):
        return []


def _post_keys(raw: object) -> list[str]:
    if not isinstance(raw, dict):
        return []
    keys = set()
    for item in raw.get("params", [])[:150] if isinstance(raw.get("params", []), list) else []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            if FIELD_NAME.fullmatch(item["name"]):
                keys.add(item["name"])
    keys.update(_body_keys(raw))
    return sorted(keys)[:MAX_FIELD_NAMES]


def _cookie_flags(headers: object) -> list[dict]:
    entries = []
    for row in headers if isinstance(headers, list) else []:
        if not isinstance(row, dict) or str(row.get("name", "")).lower() != "set-cookie":
            continue
        value = row.get("value")
        if not isinstance(value, str):
            continue
        first = value.split(";", 1)[0].split("=", 1)[0].strip()
        name = first if FIELD_NAME.fullmatch(first) else "[opaque-cookie]"
        lower = value.lower()
        secure = bool(re.search(r"(?:^|;)\s*secure(?:;|$)", lower))
        httponly = bool(re.search(r"(?:^|;)\s*httponly(?:;|$)", lower))
        match = re.search(r"(?:^|;)\s*samesite\s*=\s*(strict|lax|none)", lower)
        entries.append({"name": name[:70], "secure": secure,
                        "httponly": httponly, "samesite": match.group(1) if match else None})
        if len(entries) >= 60:
            break
    return entries


def _summary_observation(kind: str, description: str, evidence_ids: list[str], *, confidence="medium") -> dict:
    return {"type": kind, "status": "hypothesis", "confidence": confidence,
            "description": description, "evidence_ids": evidence_ids[:8],
            "verified_vulnerability": False}


def _safe_url_fields(url):
    host = safe_host(url)
    path = safe_path(url)
    try:
        query = urlsplit(url).query
        fields = sorted({
            k for k, _ in parse_qsl(query, keep_blank_values=True)
            if FIELD_NAME.fullmatch(k)
        })[:50]
    except (ValueError, TypeError):
        fields = []
    return host, path, fields


def analyze_har(source: str) -> dict:
    if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise TrafficError("har_too_large")
    fingerprint = hashlib.sha256(source.encode("utf-8")).hexdigest()
    try:
        root = json.loads(source)
    except (ValueError, TypeError) as exc:
        raise TrafficError("invalid_har_json") from exc
    if not isinstance(root, dict) or not isinstance(root.get("log"), dict):
        raise TrafficError("invalid_har_structure")
    entries = root["log"].get("entries")
    if not isinstance(entries, list):
        raise TrafficError("missing_har_entries")
    if len(entries) > MAX_ENTRIES:
        raise TrafficError("too_many_har_entries")
    hosts = Counter()
    methods = Counter()
    statuses = Counter()
    endpoints = {}
    cookies = {}
    candidate = []
    timings = []
    path_to_evidence = defaultdict(list)
    for i, row in enumerate(entries):
        if not isinstance(row, dict):
            continue
        req = row.get("request") if isinstance(row.get("request"), dict) else {}
        resp = row.get("response") if isinstance(row.get("response"), dict) else {}
        url = req.get("url", "")
        host, path, qnames = _safe_url_fields(url)
        method = str(req.get("method") or "UNKNOWN").upper()[:14]
        if not re.fullmatch(r"[A-Z]{2,14}", method):
            method = "UNKNOWN"
        status = resp.get("status")
        status = status if type(status) is int and 100 <= status <= 599 else 0
        evidence = "har:" + hashlib.sha256(
            f"{fingerprint}:{i}:{host}:{path}:{method}:{status}".encode()
        ).hexdigest()[:16]
        hosts[host] += 1
        methods[method] += 1
        statuses[str(status)] += 1
        request_headers = _headers(req.get("headers"))
        response_headers = _headers(resp.get("headers"))
        mime = str((resp.get("content") or {}).get("mimeType", "") if isinstance(resp.get("content"), dict) else "")[:80].split(";")[0].lower()
        auth_present = any(AUTH_KEY.search(k) for k in request_headers)
        response_fields = _body_keys(resp.get("content", {}))
        request_fields = _post_keys(req.get("postData", {}))
        t = row.get("time")
        if type(t) in (int, float) and 0 <= t <= 300_000:
            timings.append(round(float(t), 2))
        key = (host, path, method)
        if key not in endpoints and len(endpoints) < 400:
            endpoints[key] = {
                "host": host, "path": path, "method": method, "count": 0,
                "statuses": Counter(), "query_keys": set(), "request_keys": set(),
                "response_keys": set(), "auth_header_present": False,
                "api_like": bool(API_PATH.search(path)), "evidence_ids": [],
                "response_content_types": set(),
            }
        entry = endpoints.get(key)
        if entry:
            entry["count"] += 1
            entry["statuses"][str(status)] += 1
            entry["query_keys"].update(qnames)
            entry["request_keys"].update(request_fields)
            entry["response_keys"].update(response_fields)
            entry["auth_header_present"] |= auth_present
            entry["response_content_types"].add(mime)
            if len(entry["evidence_ids"]) < 4:
                entry["evidence_ids"].append(evidence)
        path_to_evidence[key].append(evidence)
        for cookie in _cookie_flags(resp.get("headers")):
            cookies[(host, cookie["name"])] = cookie
        if any(SENSITIVE_QUERY.search(k) for k in qnames):
            candidate.append(_summary_observation(
                "sensitive_query_key", "В URL обнаружено имя параметра, обычно связанного с секретами. "
                "Значение параметра не сохранялось.", [evidence]))
        if auth_present and response_headers.get("cache-control", "").lower().find("public") >= 0:
            candidate.append(_summary_observation(
                "authenticated_public_cache", "Ответ на запрос с авторизационным заголовком "
                "содержит Cache-Control: public; требуется анализ контекста.", [evidence]))
    ordered = sorted(endpoints.values(), key=lambda x: (-x["count"], x["host"], x["path"]))
    api = []
    for e in ordered:
        api.append({
            **{k: e[k] for k in ("host", "path", "method", "count",
                                "auth_header_present", "api_like", "evidence_ids")},
            "statuses": dict(e["statuses"]),
            "query_keys": sorted(e["query_keys"])[:40],
            "request_keys": sorted(e["request_keys"])[:40],
            "response_keys": sorted(e["response_keys"])[:60],
            "response_content_types": sorted(e["response_content_types"])[:5],
        })
        if any(ID_HINT.search(k) for k in (*e["query_keys"], *e["request_keys"])):
            candidate.append(_summary_observation(
                "object_identifier", "В запросе есть идентификатор объекта; контроль прав "
                "на сервере нельзя подтвердить только по HAR.", e["evidence_ids"]))
        notable = sorted(set(x for x in e["response_keys"] if INTERESTING.search(x)))
        if notable:
            candidate.append(_summary_observation(
                "business_or_internal_fields", "Ответ содержит имена полей, связанных с "
                "договором, биллингом или правами: " + ", ".join(notable[:8]) +
                ". Само наличие полей не доказывает утечку.", e["evidence_ids"], confidence="low"))
        if e["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            candidate.append(_summary_observation(
                "state_changing_endpoint", "Обнаружен метод изменения состояния. "
                "Идемпотентность, порядок транзакций и серверную авторизацию "
                "необходимо изучать на тестовых данных.", e["evidence_ids"], confidence="low"))
    for (host, name), f in cookies.items():
        missing = [k for k in ("secure", "httponly", "samesite")
                   if not f[k]]
        if missing:
            candidate.append(_summary_observation(
                "cookie_attribute_review", "В ответе для " + host +
                " обнаружен Set-Cookie без " + ", ".join(missing) +
                ". Применимость зависит от назначения cookie.",
                [], confidence="medium"))
    grouped = {}
    for item in candidate:
        key = (item["type"], item["description"])
        if key not in grouped:
            grouped[key] = item
        else:
            grouped[key]["evidence_ids"] = sorted(
                set(grouped[key]["evidence_ids"] + item["evidence_ids"]))[:8]
    report = {
        "kind": "har", "schema_version": 1,
        "source_sha256": fingerprint,
        "raw_data_retained": False,
        "scope": "offline_user_supplied_capture",
        "requests_analyzed": len(entries),
        "hosts": dict(hosts.most_common(30)),
        "methods": dict(methods),
        "status_codes": dict(statuses),
        "endpoints": api[:400],
        "cookies": [{"host": h, **v} for (h, _), v in list(cookies.items())[:60]],
        "observations": list(grouped.values())[:100],
        "timings_ms": {
            "min": min(timings), "max": max(timings),
            "median": sorted(timings)[len(timings) // 2],
        } if timings else None,
        "limitations": [
            "Виден лишь зафиксированный браузером трафик одного контекста",
            "Никаких запросов к исходным серверам не выполнялось",
            "Роли, фактический доступ к чужим объектам и гонки платежей не проверялись",
            "HTTP тела, значения параметров и cookies не сохранены",
        ],
    }
    return report


def analyze_js(source: str) -> dict:
    if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise TrafficError("js_too_large")
    sha = hashlib.sha256(source.encode()).hexdigest()
    lines = source.splitlines()
    found = {}
    for match in JS_URL.finditer(source):
        path = safe_path(match.group("path"))
        found[path] = found.get(path, 0) + 1
        if len(found) >= MAX_JS_ENDPOINTS:
            break
    counts = {}
    observations = []
    for name, regex in {**JS_SOURCES, **JS_SINKS}.items():
        hits = list(regex.finditer(source))[:150]
        counts[name] = len(hits)
        if hits:
            positions = []
            for m in hits[:8]:
                line = source.count("\n", 0, m.start()) + 1
                positions.append("js:" + sha[:12] + ":L" + str(line))
            if name in JS_SINKS and name != "network_request":
                observations.append(_summary_observation(
                    "javascript_" + name, "Код содержит потенциально значимую "
                    "DOM/динамическую операцию; достижимость и источник "
                    "данных не установлены.", positions, confidence="low"))
    if any(counts[x] for x in JS_SOURCES) and (
        counts["html_sink"] or counts["dynamic_execution"]
    ):
        observations.append(_summary_observation(
            "source_sink_candidate", "В одном файле найдены источники "
            "внешних данных и потенциальные sinks. Это не доказывает "
            "существование пути source→sink или XSS.", [], confidence="low"))
    return {
        "kind": "javascript", "schema_version": 1,
        "source_sha256": sha, "raw_data_retained": False,
        "scope": "offline_user_supplied_script",
        "size_bytes": len(source.encode()),
        "line_count": len(lines),
        "api_paths": [{"path": p, "occurrences": n} for p, n in sorted(found.items())],
        "patterns": counts,
        "observations": observations,
        "limitations": [
            "Лексический анализ без исполнения JavaScript",
            "Не доказывает достижимость source→sink, XSS или уязвимость зависимости",
            "Динамически вычисляемые URL могут отсутствовать в результате",
            "Никакие секреты, исходный JS-код или значения переменных не сохранены",
        ],
    }


def api_graph(artifacts: list[dict]) -> dict:
    """Build offline graph of observed hosts, endpoints and shared field names."""
    nodes, edges, by_field = {}, [], defaultdict(set)
    for report in artifacts:
        if report.get("kind") == "har":
            for item in report.get("endpoints", [])[:MAX_GRAPH_ITEMS]:
                host = item["host"]
                endpoint = host + " " + item["method"] + " " + item["path"]
                host_id = "host:" + host
                ep_id = "api:" + endpoint
                nodes[host_id] = {"id": host_id, "kind": "host", "label": host}
                nodes[ep_id] = {"id": ep_id, "kind": "endpoint", "label": endpoint}
                edges.append({"from": host_id, "to": ep_id,
                              "relation": "observed_request",
                              "evidence_ids": item["evidence_ids"][:3]})
                for field in set(item["query_keys"] + item["request_keys"] + item["response_keys"]):
                    if ID_HINT.search(field) or INTERESTING.search(field):
                        by_field[field].add(ep_id)
        if report.get("kind") == "javascript":
            for item in report.get("api_paths", [])[:MAX_GRAPH_ITEMS]:
                path = item["path"]
                ep_id = "jsroute:" + path
                nodes[ep_id] = {"id": ep_id, "kind": "js_route", "label": path}
    for field, ids in list(by_field.items())[:40]:
        if len(ids) < 2:
            continue
        fid = "field:" + field
        nodes[fid] = {"id": fid, "kind": "field_name", "label": field}
        for endpoint in sorted(ids)[:15]:
            edges.append({"from": endpoint, "to": fid,
                          "relation": "mentions_field_name",
                          "evidence_ids": []})
    return {
        "kind": "api_graph", "nodes": list(nodes.values())[:500],
        "edges": edges[:700],
        "limitations": [
            "Общие имена параметров не доказывают связь объектов или доступ к данным",
            "Никаких запросов к API не выполнялось",
        ],
    }


def hypotheses(artifacts: list[dict]) -> dict:
    kinds = defaultdict(list)
    total = 0
    for report in artifacts:
        for item in report.get("observations", []):
            total += 1
            kinds[item["type"]].append(item)
    classes = {
        "IDOR/BOLA": ["object_identifier"],
        "Excessive Data Exposure": ["business_or_internal_fields"],
        "Session & Authentication": ["cookie_attribute_review", "sensitive_query_key", "authenticated_public_cache"],
        "Race Conditions / Business Logic": ["state_changing_endpoint"],
        "Stored/DOM XSS": ["javascript_html_sink", "javascript_dynamic_execution",
                           "source_sink_candidate"],
    }
    out = []
    for title, markers in classes.items():
        evidence = sorted(set(
            ref for kind in markers for item in kinds[kind]
            for ref in item.get("evidence_ids", [])
        ))[:12]
        seen = sorted(k for k in markers if kinds[k])
        out.append({
            "class": title,
            "state": "hypothesis" if seen else "not_observed",
            "signal_types": seen, "evidence_ids": evidence,
            "verified": False,
            "next_step": "Сопоставить с серверными правилами доступа или "
                         "проверить на специально выделенных тестовых объектах"
                         if seen else "Недостаточно наблюдений для проверки",
        })
    return {"kind": "hypothesis_matrix", "observation_count": total,
            "classes": out, "confirmed_vulnerabilities": 0}


def audit_report(artifacts: list[dict]) -> dict:
    graph = api_graph(artifacts)
    hypotheses_map = hypotheses(artifacts)
    return {
        "kind": "offline_audit_report",
        "artifact_hashes": [a["source_sha256"] for a in artifacts],
        "coverage": {
            "har_files": sum(a.get("kind") == "har" for a in artifacts),
            "javascript_files": sum(a.get("kind") == "javascript" for a in artifacts),
            "requests": sum(a.get("requests_analyzed", 0) for a in artifacts),
            "observed_endpoints": len([n for n in graph["nodes"]
                                       if n["kind"] == "endpoint"]),
        },
        "observations": hypotheses_map,
        "graph_summary": {"nodes": len(graph["nodes"]), "edges": len(graph["edges"])},
        "verified_findings": [],
        "confidence": "preliminary_offline",
        "next_steps": [
            "Проверить корректность карты API по собственным данным",
            "Сопоставить границы доверия, роли и бизнес-операции",
            "Для проверок авторизации и платежей использовать тестовые объекты",
            "Отделять наблюдения, предположения и подтверждённые дефекты",
        ],
    }
