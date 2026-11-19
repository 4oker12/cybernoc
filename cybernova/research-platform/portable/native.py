#!/usr/bin/env python3
"""Native (no nested Docker) Cybernova installer for Vast/Linux/Windows.

Uses the same Controller/MCP/DB/runtime as portable Docker. No shell piped
from the internet; installs only this repository's versioned requirements.
All runtime state and secrets live OUTSIDE Git, in a user-selected data dir.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler
import venv

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = Path(os.environ.get("CYBERNOVA_NATIVE_DATA_DIR", (
    "/workspace/cybernova-portable-data" if Path("/workspace").is_dir()
    else str(Path.home() / ".local/share/cybernova")
)))
VALID_MODEL = re.compile(r"^[A-Za-z0-9_.:/+-]{1,160}$")
VALID_URL = re.compile(r"^https://[A-Za-z0-9.:-]+(?:/[A-Za-z0-9_./-]*)?$")


class NativeError(RuntimeError):
    pass


def _private(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise NativeError("invalid_private_directory")
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    if os.name!="nt":
        path.chmod(0o700)


def _new_file(path: Path, contents: str):
    if path.exists() or path.is_symlink():
        raise NativeError("config_already_exists")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        f.write(contents)
        f.flush()
        os.fsync(f.fileno())


def init(data: Path, provider: str, model: str, base_url: str="") -> dict:
    data=data.expanduser().resolve()
    if provider not in {"ollama","openai_compatible"}:
        raise NativeError("invalid_provider")
    if not VALID_MODEL.fullmatch(model):
        raise NativeError("invalid_model")
    if provider=="openai_compatible" and not VALID_URL.fullmatch(base_url):
        raise NativeError("remote_model_requires_https_base_url")
    if provider=="ollama" and base_url:
        raise NativeError("base_url_only_for_remote_models")
    _private(data)
    scope=data/"scope.json"
    if not scope.exists():
        _new_file(scope,'{\n  "allowed_hosts": []\n}\n')
    values={
        "CYBERNOVA_LLM_PROVIDER":provider,
        "CYBERNOVA_MODEL":model,
        "CYBERNOVA_LLM_BASE_URL":base_url,
        "CYBERNOVA_LLM_API_KEY_FILE":str(data/"model_api_key") if provider=="openai_compatible" else "",
        "CYBERNOVA_OLLAMA_URL":"http://127.0.0.1:11434/api/chat",
        "CYBERNOVA_COMM_DB":str(data/"communications.sqlite3"),
        "CYBERNOVA_BACKUP_KEY_FILE":str(data/"backup.key"),
        "CYBERNOVA_ACCESS_SECRET_FILE":str(data/"web_access.txt"),
        "CYBERNOVA_HTTP_SCOPE_FILE":str(scope),
        "CYBERNOVA_ACCESS_HOST":"127.0.0.1",
        "CYBERNOVA_MCP_URL":"http://127.0.0.1:18792/mcp",
        "CYBERNOVA_COMM_WORKER":"1",
    }
    if any("\n" in v or "\r" in v or "\x00" in v for v in values.values()):
        raise NativeError("unsafe_configuration_value")
    _new_file(data/"runtime.env","".join(k+"="+v+"\n" for k,v in values.items()))
    return {"configured":True,"data_dir":str(data),"provider":provider,
            "model":model,"scope":"empty_default_deny"}


def _load(data: Path) -> dict:
    env_file=data/"runtime.env"
    if not env_file.is_file() or env_file.is_symlink():
        raise NativeError("run_init_first")
    values={}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise NativeError("invalid_environment_file")
        name,value=line.split("=",1)
        if name not in {
            "CYBERNOVA_LLM_PROVIDER","CYBERNOVA_MODEL","CYBERNOVA_LLM_BASE_URL",
            "CYBERNOVA_LLM_API_KEY_FILE","CYBERNOVA_OLLAMA_URL","CYBERNOVA_COMM_DB",
            "CYBERNOVA_BACKUP_KEY_FILE","CYBERNOVA_ACCESS_SECRET_FILE",
            "CYBERNOVA_HTTP_SCOPE_FILE","CYBERNOVA_ACCESS_HOST",
            "CYBERNOVA_MCP_URL","CYBERNOVA_COMM_WORKER",
        } or any(ord(c)<32 for c in value):
            raise NativeError("unsafe_environment_file")
        values[name]=value
    if values.get("CYBERNOVA_LLM_PROVIDER") not in {"ollama","openai_compatible"}:
        raise NativeError("invalid_provider")
    return values


def _python(data: Path) -> Path:
    return data/"venv"/("Scripts/python.exe" if os.name=="nt" else "bin/python")


def install(data: Path) -> dict:
    _load(data)
    python=_python(data)
    if not python.exists():
        venv.EnvBuilder(with_pip=True,clear=False).create(data/"venv")
    proc=subprocess.run(
        [str(python),"-m","pip","install","--disable-pip-version-check",
         "-r",str(ROOT/"console"/"requirements.txt")],
        check=False,
    )
    if proc.returncode:
        raise NativeError("python_dependencies_install_failed")
    return {"dependencies_installed":True,"python":str(python)}


def set_key(data: Path):
    values=_load(data)
    if values["CYBERNOVA_LLM_PROVIDER"]!="openai_compatible":
        raise NativeError("remote_provider_not_selected")
    path=data/"model_api_key"
    key=getpass.getpass("Remote provider key (hidden): ").strip()
    if not 8 <= len(key) <= 10000 or any(ord(c)<32 for c in key):
        raise NativeError("invalid_api_key")
    _new_file(path,key+"\n")
    return {"key_saved":True,"key_printed":False}


def doctor(data: Path) -> dict:
    import urllib.error
    import urllib.request
    opener=build_opener(ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:18794/api/status",timeout=7) as r:
            value=json.load(r)
        return {
            "web_ui_up":True,
            "mcp_ready":bool(value.get("mcp_ready")),
            "selected_model":value.get("model"),
            "provider":value.get("model_provider"),
            "note":"Remote model API authentication is not tested here",
        }
    except (OSError,ValueError,TimeoutError):
        return {"web_ui_up":False,"mcp_ready":False}


def run(data: Path):
    values=_load(data)
    python=_python(data)
    if not python.exists():
        raise NativeError("run_install_first")
    env=os.environ.copy()
    env.update(values)
    env["PYTHONPATH"]=str(ROOT)+(os.pathsep+env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return subprocess.call([str(python),"-u","-m","console.portable_runtime"],
                           cwd=ROOT,env=env)


def start(data: Path) -> dict:
    _load(data)
    python=_python(data)
    if not python.exists():
        raise NativeError("run_install_first")
    if shutil.which("tmux") is None:
        return {"started":False,
                "command":"python native.py run --data-dir "+str(data),
                "reason":"tmux_unavailable; run in a dedicated terminal or use Docker"}
    if subprocess.run(["tmux","has-session","-t","cybernova-native"],
                      capture_output=True).returncode==0:
        raise NativeError("native_session_already_running")
    env=os.environ.copy()
    env.update(_load(data))
    env["PYTHONPATH"]=str(ROOT)+(os.pathsep+env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    logfile=data/"runtime.log"
    command="cd "+shlex.quote(str(ROOT))+" && exec "+shlex.quote(str(python))+(
        " -u -m console.portable_runtime >>"+shlex.quote(str(logfile))+" 2>&1"
    )
    check=subprocess.run(["tmux","new-session","-d","-s","cybernova-native",command],
                         env=env,capture_output=True,text=True)
    if check.returncode:
        raise NativeError("tmux_start_failed")
    time.sleep(2)
    return {"started":True,"session":"cybernova-native",
            "local_ui":"http://127.0.0.1:18795/",
            "login":"cybernova",
            "password_file":str(data/"web_access.txt")}


def wizard(data: Path):
    print("Cybernova Native — без Docker; Vast/Linux/Windows")
    print("1 — локальная Ollama; 2 — внешний OpenAI-совместимый API")
    choice=input("Режим [1/2]: ").strip()
    if choice not in {"1","2"}:
        raise NativeError("invalid_selection")
    provider="ollama" if choice=="1" else "openai_compatible"
    model=input("Модель [cybernova-security:30b]: ").strip() or "cybernova-security:30b"
    url=""
    if provider=="openai_compatible":
        url=input("HTTPS base URL: ").strip()
        print("Внешняя модель получит контекст и ответы инструментов.")
        if input("Разрешаю передачу данных внешнему провайдеру? [yes/NO]: ").strip()!="yes":
            raise NativeError("external_model_not_approved")
    init(data,provider,model,url)
    install(data)
    if provider=="openai_compatible":
        set_key(data)
    return start(data)


def main():
    p=argparse.ArgumentParser(description="Native Cybernova installer (no Docker)")
    p.add_argument("--data-dir",type=Path,default=DEFAULT_DATA)
    sub=p.add_subparsers(dest="cmd",required=True)
    sub.add_parser("wizard")
    x=sub.add_parser("init")
    x.add_argument("--provider",required=True,choices=["ollama","openai_compatible"])
    x.add_argument("--model",required=True)
    x.add_argument("--base-url",default="")
    for command in ("install","set-key","run","start","doctor","stop"):
        sub.add_parser(command)
    args=p.parse_args()
    data=args.data_dir.expanduser().resolve()
    try:
        if args.cmd=="wizard":
            value=wizard(data)
        elif args.cmd=="init":
            value=init(data,args.provider,args.model,args.base_url)
        elif args.cmd=="install":
            value=install(data)
        elif args.cmd=="set-key":
            value=set_key(data)
        elif args.cmd=="run":
            raise SystemExit(run(data))
        elif args.cmd=="start":
            value=start(data)
        elif args.cmd=="doctor":
            value=doctor(data)
        elif args.cmd=="stop":
            if shutil.which("tmux") is None:
                raise NativeError("tmux_unavailable")
            proc=subprocess.run(["tmux","kill-session","-t","cybernova-native"],
                                capture_output=True)
            if proc.returncode:
                raise NativeError("tmux_session_missing")
            value={"stopped":True,"data_preserved":True}
        print(json.dumps(value,ensure_ascii=False,indent=2))
    except (NativeError,OSError,ValueError) as exc:
        p.exit(2,"CYBERNOVA_NATIVE_ERROR: "+str(exc)+"\n")


if __name__=="__main__":
    main()
