#!/usr/bin/env python3
"""Cybernova portable deployment manager (Python stdlib, no external SDK).

Typical:
  python manage.py init --provider ollama --model qwen2.5-coder:7b
  python manage.py up
  python manage.py pull-model
  python manage.py doctor
Or:
  python manage.py init --provider openai_compatible --model model-id \
      --base-url https://provider.example/v1
  python manage.py set-key
  python manage.py up
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
ENV_FILE = ROOT / ".env"
CONFIG = ROOT / "config"
SCOPE = CONFIG / "scope.json"
APP = "cybernova"
MODEL_RE = re.compile(r"^[a-zA-Z0-9_.:/+-]{1,160}$")
URL_RE = re.compile(r"^https://[a-zA-Z0-9.:-]+(?:/[a-zA-Z0-9_./-]*)?$")


class InstallError(RuntimeError):
    pass


def _check_private(path: Path):
    if path.exists() and path.is_symlink():
        raise InstallError("symlink_not_allowed")
    if path.exists() and not path.is_dir():
        raise InstallError("path_not_directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)


def _write_new(path: Path, data: str):
    if path.exists() or path.is_symlink():
        raise InstallError(str(path.name) + "_already_exists")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def init(provider: str, model: str, base_url: str = "") -> dict:
    if provider not in {"ollama", "openai_compatible"}:
        raise InstallError("invalid_provider")
    if not MODEL_RE.fullmatch(model):
        raise InstallError("invalid_model_name")
    if provider == "openai_compatible" and not URL_RE.fullmatch(base_url):
        raise InstallError("remote_base_url_must_be_https")
    if provider == "ollama" and base_url:
        raise InstallError("ollama_base_url_not_needed")
    CONFIG.mkdir(parents=True,exist_ok=True)
    if not SCOPE.exists():
        _write_new(SCOPE,'{\n  "allowed_hosts": []\n}\n')
    env = (
        "# Cybernova portable config. NEVER commit this file.\n"
        "CYBERNOVA_LLM_PROVIDER=" + provider + "\n"
        "CYBERNOVA_MODEL=" + model + "\n"
        "CYBERNOVA_OLLAMA_URL=http://ollama:11434/api/chat\n"
        "CYBERNOVA_LLM_BASE_URL=" + base_url + "\n"
        "CYBERNOVA_LLM_API_KEY_FILE=" +
        ("/data/model_api_key" if provider=="openai_compatible" else "") +
        "\n"
    )
    _write_new(ENV_FILE, env)
    return {
        "initialized":True, "provider":provider, "model":model,
        "next": "python manage.py set-key" if provider == "openai_compatible"
                else "python manage.py up; python manage.py pull-model",
    }


def set_key(rotate: bool = False) -> dict:
    if not ENV_FILE.is_file():
        raise InstallError("run_init_first")
    if "CYBERNOVA_LLM_PROVIDER=openai_compatible" not in ENV_FILE.read_text():
        raise InstallError("remote_provider_not_selected")
    key = getpass.getpass("API key (input hidden): ").strip()
    if not 8 <= len(key) <= 10000 or any(ord(c)<32 for c in key):
        raise InstallError("invalid_api_key")
    _compose("build", APP)
    command = ["docker","compose","-f",str(ROOT/"compose.yaml"),
               "run","--rm","--no-deps","-T",APP,
               "python","-m","console.portable_credentials","import-model-key"]
    if rotate:
        command.append("--rotate")
    process = subprocess.run(command,cwd=ROOT,input=key+"\\n",
                             text=True,capture_output=True)
    if process.returncode:
        raise InstallError("api_key_import_failed")
    return {"key_stored_in_private_volume": True,"key_printed": False}


def _compose(*args, capture: bool = False, extra_files: bool = False):
    if shutil.which("docker") is None:
        raise InstallError("docker_not_installed")
    command=["docker","compose","-f",str(ROOT/"compose.yaml")]
    if extra_files:
        command+=["-f",str(ROOT/"compose.gpu.yaml")]
    command+=list(args)
    process=subprocess.run(command,cwd=ROOT,
                           text=True,capture_output=capture)
    if process.returncode:
        raise InstallError("docker_compose_exit_"+str(process.returncode))
    return (process.stdout or "") if capture else ""


def _profile() -> list[str]:
    if not ENV_FILE.exists():
        raise InstallError("run_init_first")
    text=ENV_FILE.read_text()
    if "CYBERNOVA_LLM_PROVIDER=ollama" in text:
        return ["--profile","local-ollama"]
    return []


def up(tunnel: bool = False, gpu: bool = False) -> dict:
    if gpu and not _profile():
        raise InstallError("gpu_only_for_local_ollama")
    profile=_profile()+(["--profile","tunnel"] if tunnel else [])
    _compose(*profile,"up","-d","--build",extra_files=gpu)
    return {"started":True,"local_ui":"http://127.0.0.1:18795/",
            "login":"cybernova",
            "password":"docker compose exec -T cybernova cat /data/web_access.txt (second line)",
            "tunnel":tunnel, "note":"remote tunnel URL from: python manage.py logs"}


def exec_in_container(*args: str, capture=True):
    return _compose("exec","-T",APP,*args,capture=capture)


def backup_to_host(directory: Path) -> dict:
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name!="nt":
        directory.chmod(0o700)
    tag=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name="cybernova-"+tag+".cnbk"
    internal="/data/backups/"+name
    exec_in_container("python","-m","console.backup","backup",
                      "--output",internal,capture=False)
    exec_in_container("python","-m","console.backup","verify",internal,capture=False)
    cid=_compose("ps","-q",APP,capture=True).strip()
    if not cid:
        raise InstallError("container_not_running")
    for filename in (name,name+".manifest.json"):
        destination=directory/filename
        if destination.exists():
            raise InstallError("backup_name_collision")
        process=subprocess.run(
            ["docker","cp",cid+":"+("/data/backups/"+filename),str(destination)],
            capture_output=True,text=True,
        )
        if process.returncode:
            raise InstallError("backup_copy_failed")
        if os.name!="nt":
            destination.chmod(0o600)
    return {"encrypted_backup":str(directory/name),
            "manifest":str(directory/(name+".manifest.json")),
            "warning":"Copy both files AND backup.key to another machine/storage securely"}


def main():
    p=argparse.ArgumentParser(description="Portable Cybernova deployment")
    commands=p.add_subparsers(dest="cmd",required=True)
    x=commands.add_parser("init",help="Create local config and empty allowlist")
    x.add_argument("--provider",choices=["ollama","openai_compatible"],required=True)
    x.add_argument("--model",default="qwen2.5-coder:7b")
    x.add_argument("--base-url",default="")
    x=commands.add_parser("set-key",help="Import API key into private named volume")
    x.add_argument("--rotate",action="store_true")
    x=commands.add_parser("up",help="Build/start services")
    x.add_argument("--tunnel",action="store_true")
    x.add_argument("--gpu",action="store_true")
    commands.add_parser("doctor",help="Check running application and MCP")
    commands.add_parser("pull-model",help="Download selected local Ollama model")
    commands.add_parser("logs",help="Show last service logs (may contain task content)")
    commands.add_parser("stop",help="Stop containers, preserve volumes")
    commands.add_parser("init-backup-key",help="Generate an encryption key")
    commands.add_parser("export-backup-key",help="Copy key to a private local path")
    x=commands.add_parser("backup",help="Online encrypted DB snapshot to a host directory")
    x.add_argument("--to",type=Path,required=True)
    args=p.parse_args()
    try:
        if args.cmd=="init":
            result=init(args.provider,args.model,args.base_url)
        elif args.cmd=="set-key":
            result=set_key(args.rotate)
        elif args.cmd=="up":
            result=up(args.tunnel,args.gpu)
        elif args.cmd=="doctor":
            exec_in_container("python","-m","console.portable_runtime","doctor",capture=False)
            result={"healthy":True}
        elif args.cmd=="pull-model":
            if not _profile():
                raise InstallError("pull_model_only_for_ollama")
            model=next(line.split("=",1)[1] for line in ENV_FILE.read_text().splitlines()
                       if line.startswith("CYBERNOVA_MODEL="))
            _compose("--profile","local-ollama","exec","-T","ollama","ollama","pull",model)
            result={"model_pulled":model}
        elif args.cmd=="logs":
            _compose(*_profile(),"logs","--tail","80")
            result={"logs_shown":True}
        elif args.cmd=="stop":
            _compose(*_profile(),"down")
            result={"stopped":True,"volumes_preserved":True}
        elif args.cmd=="init-backup-key":
            exec_in_container("python","-m","console.backup","init-key",capture=False)
            result={"key_initialized":True,"reminder":"Export key to another machine"}
        elif args.cmd=="export-backup-key":
            raise InstallError("specify_exact_destination_in_next_version_use_docker_cp_manually")
        else:
            result=backup_to_host(args.to.expanduser().resolve())
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (InstallError, OSError, ValueError, StopIteration) as exc:
        p.exit(2,"CYBERNOVA_SETUP_ERROR: "+str(exc)+"\n")


if __name__=="__main__":
    main()
