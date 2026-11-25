"""Read-only summary of Cybernova local development agent for existing MCP tool."""
from __future__ import annotations
import json,os,re
from pathlib import Path

ROOT=Path(os.environ.get('CYBERNOVA_AGENT_HOME','/workspace/cybernova-agent'))/'jobs'
VALID=re.compile(r'^[0-9a-f]{16}$')

def snapshot():
    res={'agent_version':'0.8','agent_available':True,'agent_job_found':False}
    if not ROOT.exists():return res
    recent=[]
    try:
        for path in ROOT.iterdir():
            if not path.is_dir() or path.is_symlink() or not VALID.fullmatch(path.name):continue
            p=path/'state.json'
            if not p.is_file() or p.is_symlink() or p.stat().st_size>30000:continue
            try:st=json.loads(p.read_text(encoding='utf8'))
            except (ValueError,OSError):continue
            if not isinstance(st,dict):continue
            x={'job_id':path.name,'status':str(st.get('status',''))[:35], 'step':str(st.get('step',''))[:100],
                'updated_at':str(st.get('updated_at',''))[:60], 'steps':st.get('steps',0),
                'error':str(st.get('error',''))[:350],'question':str(st.get('question',''))[:350],
                'summary':str(st.get('summary',''))[:500], 'project':str(st.get('project',''))[:60]}
            recent.append((x,path))
    except (OSError,ValueError):return res
    recent.sort(key=lambda p:p[0]['updated_at'],reverse=True)
    if not recent:return res
    active=[p for p in recent if p[0]['status'] in ('queued','running','needs_human')]
    item,path=(active or recent)[0]
    log=path/'output.log'
    tail=''
    try:
        if log.is_file() and not log.is_symlink():
            with log.open('rb') as f:
                f.seek(0,2);n=f.tell();f.seek(max(0,n-12000));tail=f.read().decode('utf8','replace')[-6500:]
    except OSError:pass
    try:
        from cybernova_observability import _redact
        tail=_redact(tail)
        item={k:(_redact(v) if isinstance(v,str) else v) for k,v in item.items()}
    except ImportError:pass
    res.update({'agent_job_found':True,'agent_job_id':item['job_id'],'agent_status':item['status'],
                'agent_step':item['step'],'agent_project':item['project'],'agent_error':item['error'],
                'agent_question':item['question'],'agent_summary':item['summary'],'agent_log_tail':tail,
                'agent_recent_jobs':[p[0] for p in recent[:6]]})
    return res
