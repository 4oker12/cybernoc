"""Cybernova panel read model. No arbitrary commands, paths, or target hosts."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone
import json
import re
import os
import subprocess
from urllib.request import build_opener, ProxyHandler, Request

SID = re.compile(r'^[0-9a-f]{32}$')
JOB_ID = re.compile(r'^[0-9a-f]{16}$')
MODEL = 'brianmatzelle/qwen3-coder-heretic:30b'
SAFE_EVENT = {'start', 'decision', 'tool_result', 'completed', 'failed', 'stopped', 'model_error', 'needs_human'}
SECRET = re.compile(r'(?i)(authorization|password|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;]+')

@dataclass(frozen=True)
class Paths:
    updater: Path = Path('/workspace/cybernova-updater')
    agent: Path = Path('/workspace/cybernova-agent')
    session_script: Path = Path('/workspace/cybernova-mcp-addon/session_ops.py')
    python: Path = Path('/venv/main/bin/python')


def read_json(path: Path, limit: int = 131072):
    """Refuse symlink records and oversized data; fail closed to absent."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if type(value) is dict else None
    except (OSError, UnicodeError, ValueError):
        return None


def safe_text(value, size=160):
    return SECRET.sub('[redacted]', str(value or ''))[:size]


def sessions(paths: Paths):
    root = paths.updater / 'sessions'
    if root.is_symlink() or not root.is_dir():
        return []
    out = []
    try:
        folders = list(root.iterdir())[:500]
    except OSError:
        return []
    for folder in folders:
        if not SID.fullmatch(folder.name) or folder.is_symlink() or not folder.is_dir():
            continue
        record = read_json(folder / 'session.json')
        if not record or record.get('session_id') != folder.name:
            continue
        result = read_json(folder / 'result.json')
        started = record.get('started_at', 0)
        if type(started) not in (int, float) or started < 0:
            continue
        state = safe_text((result or {}).get('state', 'running'), 24)
        if state == 'running' and (datetime.now(timezone.utc).timestamp() - started) > 1200:
            state = 'stalled'
        out.append({
            'id': folder.name,
            'started_at': started,
            'state': state,
            'passed': (result or {}).get('passed') is True,
            'reason': safe_text((result or {}).get('reason'), 60),
            'qwen_actions': (result or {}).get('qwen_successful_actions') if type((result or {}).get('qwen_successful_actions')) is int else None,
            'evidence': (result or {}).get('evidence_manifests_verified') if type((result or {}).get('evidence_manifests_verified')) is int else None,
            'external_requests': (result or {}).get('external_target_requests') if type((result or {}).get('external_target_requests')) is int else None,
            'scripted_adapters': [x for x in (result or {}).get('scripted_adapters', []) if type(x) is str][:10],
            'qwen_adapters': [x for x in (result or {}).get('qwen_adapters', []) if type(x) is str][:10],
        })
    out.sort(key=lambda x: x['started_at'], reverse=True)
    return out[:16]


def agent_jobs(paths: Paths):
    root = paths.agent / 'jobs'
    if root.is_symlink() or not root.is_dir():
        return []
    out = []
    try:
        dirs = list(root.iterdir())[:500]
    except OSError:
        return []
    for folder in dirs:
        if not JOB_ID.fullmatch(folder.name) or folder.is_symlink() or not folder.is_dir():
            continue
        state = read_json(folder / 'state.json', 30000)
        if not state:
            continue
        out.append({'id': folder.name, 'state': safe_text(state.get('status'), 28),
                    'step': safe_text(state.get('step'), 60), 'project': safe_text(state.get('project'), 60),
                    'updated_at': safe_text(state.get('updated_at'), 50),
                    'error': safe_text(state.get('error'), 250)})
    out.sort(key=lambda x: x['updated_at'], reverse=True)
    return out[:10]


def agent_events(paths: Paths, jobs: list, limit=30):
    """Surface event names and timestamps; never show model text or raw tool output."""
    result = []
    for job in jobs[:5]:
        path = paths.agent / 'jobs' / job['id'] / 'events.jsonl'
        try:
            if path.is_symlink() or not path.is_file():
                continue
            with path.open('rb') as f:
                f.seek(0, 2)
                end = f.tell()
                f.seek(max(0, end - 40000))
                data = f.read(40000)
            lines = data.decode('utf-8', 'replace').splitlines()
            if end > 40000:
                lines = lines[1:]
            for line in lines[-40:]:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if type(event) is not dict or event.get('event') not in SAFE_EVENT:
                    continue
                result.append({'time': safe_text(event.get('ts'), 36),
                               'type': event['event'], 'source': 'agent', 'id': job['id']})
        except OSError:
            continue
    result.sort(key=lambda x: x['time'], reverse=True)
    return result[:limit]


def ollama_status():
    try:
        opener = build_opener(ProxyHandler({}))
        with opener.open(Request('http://127.0.0.1:11434/api/tags'), timeout=1.7) as r:
            tags = json.load(r)
        with opener.open(Request('http://127.0.0.1:11434/api/ps'), timeout=1.7) as r:
            running = json.load(r)
        names = [x.get('name', '') for x in tags.get('models', []) if type(x) is dict]
        loaded = [x.get('name', '') for x in running.get('models', []) if type(x) is dict]
        return {'reachable': True, 'installed': MODEL in names, 'loaded': MODEL in loaded}
    except (OSError, ValueError, TimeoutError):
        return {'reachable': False, 'installed': False, 'loaded': False}


def snapshot(paths: Paths, *, demo=False):
    if demo:
        return demo_snapshot()
    updater = read_json(paths.updater / 'state.json', 30000) or {}
    ss = sessions(paths)
    jobs = agent_jobs(paths)
    ollama = ollama_status()
    latest = ss[0] if ss else None
    active = next((x for x in ss if x['state'] == 'running'), None)
    agent_active = next((x for x in jobs if x['state'] == 'running'), None)
    checks = {
        'updater': {'state': safe_text(updater.get('status', 'unknown'), 30),
                    'commit': safe_text(updater.get('deployed_commit', ''), 40),
                    'error': safe_text(updater.get('error'), 150)},
        'qwen': ollama,
        'latest_session': latest,
        'latest_agent': jobs[0] if jobs else None,
    }
    ring = [
      {'id': 'trigger', 'name': 'TRIGGER', 'role': 'NumpadEnter / событие', 'state': 'manual', 'note': 'Локальный контроллер Windows'},
      {'id': 'chatgpt', 'name': 'ChatGPT', 'role': 'Аналитик / стратегия', 'state': 'external', 'note': 'Обычный чат; статус не отслеживается'},
      {'id': 'session', 'name': 'SESSION', 'role': 'Управление сессиями', 'state': 'running' if active else 'ready', 'note': 'Фиксированный local_qwen_baseline'},
      {'id': 'qwen', 'name': 'QWEN', 'role': 'Исполнитель на Vast', 'state': 'ready' if ollama['reachable'] and ollama['installed'] else 'offline', 'note': 'Загружен в GPU' if ollama['loaded'] else 'Ожидает запроса'},
      {'id': 'tools', 'name': 'TOOLS', 'role': 'Локальные адаптеры', 'state': 'running' if active else 'ready', 'note': '7 контрольных адаптеров'},
      {'id': 'observer', 'name': 'OBSERVER', 'role': 'Логи / доказательства', 'state': 'ready' if ss else 'unknown', 'note': 'Отчёты и события на Vast'},
      {'id': 'decision', 'name': 'DECISION', 'role': 'Анализ результатов', 'state': 'manual', 'note': 'Автоцикл пока не активирован'},
    ]
    return {'mode': 'LIVE', 'generated_at': datetime.now(timezone.utc).isoformat(),
            'scope': 'LOCAL_LAB_ONLY', 'ring': ring, 'checks': checks,
            'sessions': ss, 'jobs': jobs, 'events': agent_events(paths, jobs),
            'summary': {'sessions': len(ss), 'passed': sum(x['passed'] for x in ss),
                        'failed': sum(x['state'] == 'failed' or (x['state'] == 'completed' and not x['passed']) for x in ss),
                        'active': bool(active or agent_active)}}


def demo_snapshot():
    t = datetime.now(timezone.utc).isoformat()
    # Explicit demo marker: never present simulated data as live.
    return {'mode': 'DEMO', 'generated_at': t, 'scope': 'LOCAL_LAB_ONLY',
      'ring': [
      {'id':'trigger','name':'TRIGGER','role':'NumpadEnter / событие','state':'manual','note':'Ручной запуск'},
      {'id':'chatgpt','name':'ChatGPT','role':'Аналитик / стратегия','state':'external','note':'В обычном чате'},
      {'id':'session','name':'SESSION','role':'Управление сессиями','state':'ready','note':'Локальные пакеты'},
      {'id':'qwen','name':'QWEN','role':'Исполнитель на Vast','state':'ready','note':'30B · лаборатория'},
      {'id':'tools','name':'TOOLS','role':'Проверки и инструменты','state':'ready','note':'7 адаптеров'},
      {'id':'observer','name':'OBSERVER','role':'Логи и доказательства','state':'ready','note':'Журнал действий'},
      {'id':'decision','name':'DECISION','role':'Управление циклом','state':'manual','note':'Нужен просмотр результатов'},
      ], 'checks': {'updater':{'state':'active','commit':'demo-commit','error':''},
                   'qwen':{'reachable':True,'installed':True,'loaded':False},
                   'latest_session':{'id':'demo-session-001','state':'completed','passed':True,'reason':'all_checks_passed','evidence':12,'qwen_actions':2},
                   'latest_agent':{'id':'demo-agent','state':'failed','error':'Repeated identical action three times'}},
      'sessions': [{'id':'a01f5e6cb8134782a4f6b5b63df5f0a1','started_at':1794974151,'state':'completed',
                    'passed':True,'reason':'all_checks_passed','qwen_actions':2,'evidence':12,
                    'external_requests':0,'scripted_adapters':['curl.http','httpx.http','openssl.x509','jq.json','python.ip','python.syntax','dnspython.zone'],
                    'qwen_adapters':['python.ip','python.syntax']}],
      'jobs':[{'id':'a1b2c3d4e5f60708','state':'failed','project':'demo7', 'step':'stopped',
               'updated_at':t,'error':'Repeated identical action three times'}],
      'events':[{'time':t,'type':'completed','source':'agent','id':'a1b2c3d4e5f60708'},
                {'time':t,'type':'tool_result','source':'agent','id':'a1b2c3d4e5f60708'},
                {'time':t,'type':'decision','source':'agent','id':'a1b2c3d4e5f60708'}],
      'summary':{'sessions':1,'passed':1,'failed':0,'active':False}}


def start_local_baseline(paths: Paths):
    """Only the existing fixed session tool; never interpolate user input into shell."""
    if paths.session_script.is_symlink() or not paths.session_script.is_file():
        return {'ok':False,'reason':'session_runner_missing'}
    try:
        proc = subprocess.run([str(paths.python), str(paths.session_script), 'start'],
                              stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, shell=False, check=False, timeout=20,
                              env={'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'HOME':'/nonexistent'})
        if proc.returncode and not proc.stdout:
            return {'ok':False,'reason':'session_runner_failed'}
        data = json.loads(proc.stdout[:12000])
        if type(data) is not dict:
            return {'ok':False,'reason':'unexpected_runner_response'}
        return {k:v for k,v in data.items() if k in ('ok','reason','session_id','state','scope','error')}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'ok':False,'reason':'session_runner_unavailable'}