"""File-scoped tools. No shell, remote URLs, or system configuration changes."""
from __future__ import annotations
import json, os, pathlib, re, hashlib, tomllib
from .common import PROJECTS, BASE

ALLOWED_EXT={'.py','.md','.txt','.json','.toml','.yaml','.yml'}
MAX_FILE=90000
MAX_FILES=50

def project_root(name: str) -> pathlib.Path:
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,39}', name):
        raise ValueError('Invalid project name')
    root=PROJECTS/name
    if root.is_symlink(): raise ValueError('Symlink project forbidden')
    root.mkdir(parents=True, exist_ok=True)
    if root.resolve().parent != PROJECTS.resolve():
        raise ValueError('Project escapes projects directory')
    return root

def safe_path(root: pathlib.Path, relative: str) -> pathlib.Path:
    if not isinstance(relative, str) or not relative or len(relative)>160 or '\\' in relative:
        raise ValueError('Invalid path')
    frag=pathlib.PurePosixPath(relative)
    if frag.is_absolute() or '..' in frag.parts or '.' in frag.parts or any(x.startswith('.') for x in frag.parts):
        raise ValueError('Non-project path forbidden')
    if frag.suffix not in ALLOWED_EXT:
        raise ValueError('File extension not allowed')
    p=root.joinpath(*frag.parts)
    current=root
    for part in frag.parts:
        current=current/part
        if current.is_symlink(): raise ValueError('Symlinks forbidden')
    if not p.resolve().is_relative_to(root.resolve()): raise ValueError('Path escapes root')
    return p

def execute_tool(root: pathlib.Path, name: str, args: dict, job_id: str):
    if not isinstance(args,dict): return {'ok':False,'error':'Invalid tool arguments'}
    if name=='list_files':
        files=[]
        for p in root.rglob('*'):
            if len(files)>=MAX_FILES: break
            if p.is_file() and not p.is_symlink() and p.suffix in ALLOWED_EXT:
                files.append({'path':p.relative_to(root).as_posix(),'bytes':p.stat().st_size})
        return {'ok':True,'files':files}
    if name=='read_file':
        p=safe_path(root,args.get('path',''))
        if not p.is_file() or p.stat().st_size>MAX_FILE: return {'ok':False,'error':'File missing or too large'}
        return {'ok':True,'path':args['path'],'content':p.read_text(encoding='utf8',errors='replace')[:MAX_FILE]}
    if name=='write_file':
        p=safe_path(root,args.get('path',''))
        body=args.get('content')
        if not isinstance(body,str) or len(body.encode('utf8'))>MAX_FILE: return {'ok':False,'error':'Content is missing or too large'}
        if not p.exists() and len([x for x in root.rglob('*') if x.is_file()])>=MAX_FILES:
            return {'ok':False,'error':'File count quota exceeded'}
        if p.exists() and (not p.is_file() or p.stat().st_size>MAX_FILE):
            return {'ok':False,'error':'Existing file exceeds limit'}
        if p.exists():
            original=p.read_bytes()
            digest=hashlib.sha256(original).hexdigest()
            history=BASE/'history'/job_id
            history.mkdir(parents=True,exist_ok=True)
            snapshot=history/(digest+'.bak')
            if not snapshot.exists():
                snapshot.write_bytes(original)
                os.chmod(snapshot,0o600)
        p.parent.mkdir(parents=True,exist_ok=True)
        tmp=p.with_name('.__cybernova_'+job_id+'.tmp')
        tmp.write_text(body, encoding='utf8')
        os.chmod(tmp,0o644)
        os.replace(tmp,p)
        return {'ok':True,'path':args['path'],'bytes':len(body.encode('utf8')),'sha256':hashlib.sha256(body.encode('utf8')).hexdigest()}
    if name=='check_file':
        p=safe_path(root,args.get('path',''))
        if not p.is_file(): return {'ok':False,'error':'File missing'}
        text=p.read_text(encoding='utf8')
        try:
            if p.suffix=='.py': compile(text,str(p),'exec')
            elif p.suffix=='.json': json.loads(text)
            elif p.suffix=='.toml': tomllib.loads(text)
            elif not text.strip(): return {'ok':False,'error':'Text file is empty'}
            check_type={'.py':'python_syntax','.json':'json_parse','.toml':'toml_parse'}.get(p.suffix,'nonempty_utf8_only')
            return {'ok':True,'path':args['path'],'check':check_type}
        except (SyntaxError,ValueError) as ex:
            return {'ok':False,'path':args['path'],'error':str(ex)[:600]}
    return {'ok':False,'error':'Unknown tool'}
