#!/usr/bin/env python3
"""Cybernova local agent command-line interface."""
from __future__ import annotations
import argparse,fcntl,json,os,signal,subprocess,sys,uuid
from pathlib import Path
from cybernova_agent.common import BASE,PROJECTS,JOBS,NAME_RE,jidpath,write_json,now,state_update,scrub
from cybernova_agent.model import ollama_health


def start(goal,name='demo',steps=18,minutes=20):
    if not NAME_RE.fullmatch(name):
        return {'ok':False,'error':'Invalid project name'}
    if not isinstance(goal,str) or not 5<=len(goal)<=3000:
        return {'ok':False,'error':'Goal must be 5..3000 characters'}
    if not 1<=steps<=30 or not 2<=minutes<=60:
        return {'ok':False,'error':'Budget outside allowed bounds'}
    JOBS.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (JOBS/'.start.lock').open('a+') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        for p in JOBS.iterdir():
            if not p.is_dir() or len(p.name)!=16:continue
            try: s=json.loads((p/'state.json').read_text(encoding='utf8'))
            except (ValueError,OSError):continue
            if s.get('status') not in ('queued','running'):continue
            pid=s.get('pid')
            if isinstance(pid,int) and pid>1:
                try:os.kill(pid,0);return {'ok':False,'error':'Another job is active','job_id':p.name}
                except ProcessLookupError:pass
                except PermissionError:return {'ok':False,'error':'Another job is active','job_id':p.name}
        job_id=uuid.uuid4().hex[:16]
        folder=jidpath(job_id);folder.mkdir(mode=0o700)
        write_json(folder/'state.json',{'job_id':job_id,'workflow':'local_development','status':'queued','step':'start','goal':goal,'project':name,'max_steps':steps,'max_seconds':minutes*60,'created_at':now(),'updated_at':now(),'steps':0})
        env={k:v for k,v in os.environ.items() if not (k.upper().endswith('TOKEN') or k.upper().endswith('SECRET') or k.upper().endswith('API_KEY'))}
        child=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'worker',job_id],cwd=str(BASE),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
        state_update(job_id,pid=child.pid)
        return {'ok':True,'job_id':job_id,'status':'queued','project':name}


def status(job_id=None):
    if job_id:
        p=jidpath(job_id)/'state.json'
        if not p.is_file():return {'ok':False,'error':'No such job'}
        return {'ok':True,**json.loads(p.read_text(encoding='utf8'))}
    if not JOBS.exists():return {'ok':True,'jobs':[]}
    items=[]
    for p in JOBS.iterdir():
        if p.is_dir() and len(p.name)==16 and (p/'state.json').is_file():
            try:
                item=json.loads((p/'state.json').read_text(encoding='utf8'))
                items.append({k:item.get(k) for k in ('job_id','status','step','steps','updated_at','error','question','summary')})
            except(ValueError,OSError):pass
    return {'ok':True,'jobs':sorted(items,key=lambda x:x.get('updated_at') or '',reverse=True)[:20]}


def logs(job_id,lines=50):
    p=jidpath(job_id)/'output.log'
    if not p.is_file():return {'ok':False,'error':'No such log'}
    with p.open('rb') as f:
        f.seek(0,2);size=f.tell();f.seek(max(0,size-100000));txt=f.read().decode('utf8','replace')
    return {'ok':True,'job_id':job_id,'tail':scrub('\n'.join(txt.splitlines()[-max(1,min(150,lines)):]))[-12000:]}


def stop(job_id):
    s=status(job_id)
    if not s['ok']:return s
    if s['status'] not in ('queued','running'):return {'ok':False,'error':'Job not active','status':s['status']}
    (jidpath(job_id)/'STOP').write_text('stop',encoding='utf8')
    pid=s.get('pid')
    if isinstance(pid,int) and pid>1:
        try:os.killpg(pid,signal.SIGTERM)
        except ProcessLookupError:pass
    return {'ok':True,'status':'stop_requested','job_id':job_id}


def doctor():
    payload={'ok':True,'version':'1.0.0','projects_root':str(PROJECTS),'jobs_root':str(JOBS),'model': 'brianmatzelle/qwen3-coder-heretic:30b'}
    try:payload['ollama']=ollama_health()
    except Exception as e:
        payload['ollama']={'reachable':False,'error':type(e).__name__}
        payload['ok']=False
    if not payload['ollama'].get('model_installed',False):payload['ok']=False
    return payload


def main():
    ap=argparse.ArgumentParser(description='Cybernova bounded local Qwen Agent')
    subs=ap.add_subparsers(dest='cmd',required=True)
    subs.add_parser('doctor')
    s=subs.add_parser('start');s.add_argument('--goal',required=True);s.add_argument('--project',default='demo');s.add_argument('--steps',type=int,default=18);s.add_argument('--minutes',type=int,default=20)
    p=subs.add_parser('status');p.add_argument('job_id',nargs='?')
    p=subs.add_parser('logs');p.add_argument('job_id');p.add_argument('--lines',type=int,default=50)
    p=subs.add_parser('stop');p.add_argument('job_id')
    p=subs.add_parser('worker');p.add_argument('job_id')
    args=ap.parse_args()
    if args.cmd=='doctor': out=doctor()
    elif args.cmd=='start':out=start(args.goal,args.project,args.steps,args.minutes)
    elif args.cmd=='status':out=status(args.job_id)
    elif args.cmd=='logs':out=logs(args.job_id,args.lines)
    elif args.cmd=='stop':out=stop(args.job_id)
    else:
        from cybernova_agent.worker import run
        run(args.job_id);return
    print(json.dumps(out,indent=2,ensure_ascii=False))
    if out.get('ok') is False:sys.exit(1)

if __name__=='__main__':main()
