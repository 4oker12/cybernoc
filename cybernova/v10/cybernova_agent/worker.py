from __future__ import annotations
import json, os, signal, time, traceback
from .common import jidpath, state_update, event, write_json
from .tools import project_root, execute_tool
from .model import chat
from .repo_ops import execute_repo_tool

ALLOWED={'plan','list_files','read_file','write_file','check_file','finish','ask_human','repo_status','repo_sync','install_python_tool'}

class StopRequested(Exception): pass

def _stop(*_): raise StopRequested('Interrupted')

def run(job_id):
    signal.signal(signal.SIGTERM,_stop)
    state=json.loads((jidpath(job_id)/'state.json').read_text(encoding='utf8'))
    goal=state['goal']; name=state['project']
    max_steps=int(state.get('max_steps',8)); max_seconds=int(state.get('max_seconds',1200))
    root=project_root(name)
    state_update(job_id,status='running',step='model_and_tools',pid=os.getpid())
    event(job_id,'start',project=name,goal=goal)
    history=[]; last_signature=None; repeated_consecutive=0; dirty=set(); verified=set(); steps=0
    started=time.monotonic(); parse_errors=0
    try:
        while steps<max_steps and time.monotonic()-started<max_seconds:
            if (jidpath(job_id)/'STOP').exists(): raise StopRequested('Stop file present')
            state_update(job_id,step=f'decision_{steps+1}',steps=steps)
            try:
                decision=chat(goal,history,timeout=240,pending_checks=dirty,verified_files=verified,remaining_steps=max_steps-steps,plan=json.loads((jidpath(job_id)/'state.json').read_text(encoding='utf8')).get('plan'))
                parse_errors=0
            except (ValueError,OSError,TimeoutError) as e:
                parse_errors+=1
                event(job_id,'model_error',error=repr(e)[:400],retry=parse_errors)
                if parse_errors>=2: raise RuntimeError('Model failed to return a valid decision twice')
                history.append({'result':'The decision protocol failed. You must select one valid action with object arguments. Check current project files and continue.'})
                continue
            action=decision['action']; args=decision['args']; reason=str(decision.get('reason',''))[:400]
            event(job_id,'decision',action=action,args=({k:(str(v)[:80] if k!='content' else '[file content omitted]') for k,v in args.items()}),reason=reason,confidence=decision.get('confidence'))
            if action not in ALLOWED:
                result={'ok':False,'error':'Action not in local policy'}
            elif action=='finish':
                if dirty or not verified:
                    result={'ok':False,'error':'Cannot finish: all changed files must be checked and at least one check must pass', 'unchecked_files':sorted(dirty)}
                else:
                    summary=str(args.get('summary',''))[:1400]
                    event(job_id,'completed',summary=summary)
                    state_update(job_id,status='succeeded',step='done',summary=summary,steps=steps)
                    write_json(jidpath(job_id)/'report.json',{'job_id':job_id,'status':'succeeded','summary':summary,'steps':steps,'checked':not dirty and bool(verified)})
                    return
            elif action=='plan':
                steps_raw=args.get('steps',[])
                accepted=args.get('acceptance',[])
                if isinstance(steps_raw,list) and 1<=len(steps_raw)<=8 and isinstance(accepted,list) and len(accepted)<=8:
                    plan={'steps':[str(x)[:180] for x in steps_raw],'acceptance':[str(x)[:180] for x in accepted]}
                    state_update(job_id,plan=plan)
                    result={'ok':True,'plan':plan}
                else:
                    result={'ok':False,'error':'Plan expects 1..8 steps and up to 8 acceptance criteria'}
            elif action=='ask_human':
                question=str(args.get('question',''))[:1200]
                event(job_id,'needs_human',question=question)
                state_update(job_id,status='needs_human',step='awaiting_review',question=question,steps=steps)
                return
            else:
                signature=json.dumps([action,args],ensure_ascii=False,sort_keys=True)
                # Repeats separated by useful actions are legitimate. Only block
                # an unchanged sequence with no progress in between.
                repeated_consecutive = repeated_consecutive + 1 if signature == last_signature else 1
                last_signature = signature
                if repeated_consecutive >= 3:
                    raise RuntimeError('Repeated identical action three times consecutively; stopped to avoid loop')
                if repeated_consecutive == 2 and action in ('list_files','read_file','check_file','repo_status'):
                    result={'ok':False,'error':'Duplicate read-only action with no changes. Choose a different action.',
                            'pending_file_checks':sorted(dirty),'verified_files':sorted(verified),
                            'next_action_hint':('check_file for an unchecked file' if dirty else 'finish or modify a file')}
                else:
                    try:
                        result=(execute_repo_tool(root,action,args) if action in ('repo_status','repo_sync','install_python_tool') else execute_tool(root,action,args,job_id))
                    except (ValueError, OSError, UnicodeError) as tool_error:
                        result={'ok':False,'error':f'{type(tool_error).__name__}: {str(tool_error)[:250]}'}
                if action in ('repo_sync','install_python_tool') and result.get('ok'):
                    verified.add('operation:'+action)
                if action=='write_file' and result.get('ok'):
                    dirty.add(args['path']); verified.discard(args['path'])
                if action=='check_file' and result.get('ok'):
                    dirty.discard(args['path']); verified.add(args['path'])
            event(job_id,'tool_result',action=action,result={k:(v[:1800] if isinstance(v,str) else v) for k,v in result.items()})
            history.append({'step':steps+1,'reason':reason,'action':action,'arguments':({k:(str(v)[:80] if k!='content' else '[omitted]') for k,v in args.items()}),'result':{k:(v[:3000] if isinstance(v,str) else v) for k,v in result.items()}})
            steps+=1
        raise RuntimeError('Step or time budget exhausted before model finished')
    except StopRequested as e:
        event(job_id,'stopped',reason=str(e))
        state_update(job_id,status='cancelled',step='stopped',error=str(e),steps=steps)
    except Exception as e:
        event(job_id,'failed',error=repr(e)[:700])
        state_update(job_id,status='failed',step='stopped',error=repr(e)[:700],steps=steps)
