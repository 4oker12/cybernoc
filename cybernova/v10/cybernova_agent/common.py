from __future__ import annotations
import json, os, re, time, uuid
from datetime import datetime, timezone
from pathlib import Path

MODEL = 'brianmatzelle/qwen3-coder-heretic:30b'
BASE = Path(os.environ.get('CYBERNOVA_AGENT_HOME', '/workspace/cybernova-agent'))
PROJECTS = Path(os.environ.get('CYBERNOVA_PROJECTS', '/workspace/cybernova-projects'))
JOBS = BASE / 'jobs'
JOB_RE = re.compile(r'^[0-9a-f]{16}$')
NAME_RE = re.compile(r'^[a-z][a-z0-9_-]{0,39}$')
SECRET_PATTERNS = [
    (re.compile(r'sk-(?:proj-)?[a-zA-Z0-9_-]{10,}'), 'sk-[REDACTED]'),
    (re.compile(r'hf_[A-Za-z0-9]{15,}'), 'hf_[REDACTED]'),
    (re.compile(r'(?i)(authorization\s*:\s*bearer\s+)\S+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)((?:api[_-]?key|access[_-]?token|password|secret)\s*[=:]\s*)[^\s,;]+'), r'\1[REDACTED]'),
]

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def scrub(s):
    s = str(s)
    for regex, replacement in SECRET_PATTERNS:
        s = regex.sub(replacement, s)
    return s

def jidpath(job_id: str) -> Path:
    if not JOB_RE.fullmatch(job_id):
        raise ValueError('Invalid job ID')
    return JOBS / job_id

def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.{uuid.uuid4().hex}.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def state_update(job_id: str, **changes):
    p=jidpath(job_id)/'state.json'
    try: data=json.loads(p.read_text(encoding='utf8'))
    except (OSError, ValueError): data={'job_id':job_id}
    data.update(changes)
    data['updated_at']=now()
    write_json(p,data)
    return data

def event(job_id: str, event_name: str, **details):
    record={'ts':now(),'event':event_name,**details}
    p=jidpath(job_id)/'events.jsonl'
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('a',encoding='utf8') as f:
        f.write(scrub(json.dumps(record,ensure_ascii=False,default=str))+'\n')
    with (jidpath(job_id)/'output.log').open('a',encoding='utf8') as f:
        f.write(f'[{record["ts"]}] {scrub(event_name)} {scrub(str(details))[:1400]}\n')
