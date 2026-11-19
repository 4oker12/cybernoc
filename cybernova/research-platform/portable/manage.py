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
from io import BytesIO
import zipfile
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
    if os.name != "nt":
        SCOPE.chmod(0o644)  # Host allowlist is not secret; container is UID 10001.
    commit = "unknown"
    try:
        commit = subprocess.run(["git","rev-parse","HEAD"],cwd=REPO,
                                capture_output=True,text=True,check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    env = (
        "CYBERNOVA_SOURCE_COMMIT=" + commit + "\n"
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
    process = subprocess.run(command,cwd=ROOT,input=key+"\n",
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


def import_backup_key(source: Path) -> dict:
    """Import a 32-byte key to a NEW container volume without printing it."""
    if not ENV_FILE.is_file():
        raise InstallError("run_init_first")
    source = source.expanduser()
    if source.is_symlink() or not source.is_file():
        raise InstallError("backup_key_source_invalid")
    key = source.read_bytes()
    if len(key) != 32:
        raise InstallError("backup_key_must_be_32_bytes")
    _compose("build", APP)
    command = [
        "docker", "compose", "-f", str(ROOT / "compose.yaml"),
        "run", "--rm", "--no-deps", "-T", APP,
        "python", "-m", "console.portable_credentials", "import-backup-key",
    ]
    result = subprocess.run(command, cwd=ROOT, input=key, capture_output=True)
    if result.returncode:
        raise InstallError("backup_key_import_failed_or_key_already_exists")
    return {"backup_key_imported": True, "key_printed": False,
            "next": "python manage.py restore --from PATH_TO_BACKUP.cnbk"}


def restore_from_host(archive: Path) -> dict:
    """Restore onto a NEW /data database; never replace a running investigation."""
    if not ENV_FILE.is_file():
        raise InstallError("run_init_first")
    archive = archive.expanduser().absolute()
    manifest = Path(str(archive) + ".manifest.json")
    if (archive.is_symlink() or not archive.is_file()
            or manifest.is_symlink() or not manifest.is_file()
            or archive.suffix != ".cnbk"):
        raise InstallError("archive_or_manifest_invalid")
    # Never mutate an active database or stop active services implicitly.
    if _compose("ps", "--status", "running", "-q", APP, capture=True).strip():
        raise InstallError("stop_cybernova_before_restore")
    _compose("build", APP)
    command = [
        "docker", "compose", "-f", str(ROOT / "compose.yaml"),
        "run", "--rm", "--no-deps", "-T",
        "--volume", str(archive.parent) + ":/restore:ro", APP,
        "python", "-m", "console.backup", "restore",
        "/restore/" + archive.name, "--to", "/data/communications.sqlite3",
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise InstallError("restore_failed_check_key_manifest_and_empty_database")
    return {
        "database_restored": True,
        "archive": str(archive),
        "overwrite": False,
        "next": "python manage.py up",
        "note": "Only the communications SQLite DB was restored; original raw artifacts, models, API keys and scope must be provisioned separately.",
    }


def wizard() -> dict:
    print("Cybernova Portable — мастер первого запуска")
    print("1 — своя модель через Ollama (локально / Vast)")
    print("2 — внешняя модель через OpenAI-совместимый API")
    selection=input("Режим [1/2]: ").strip()
    if selection not in {"1","2"}:
        raise InstallError("invalid_wizard_selection")
    if selection=="1":
        model=input("Модель Ollama [qwen2.5-coder:7b]: ").strip() or "qwen2.5-coder:7b"
        result=init("ollama",model)
    else:
        model=input("Идентификатор модели у провайдера: ").strip()
        url=input("HTTPS API base URL (пример https://api.example/v1): ").strip()
        print("ВНИМАНИЕ: запросы, история и результаты инструмента могут")
        print("передаваться выбранному удалённому провайдеру модели.")
        if input("Понимаю и разрешаю внешний инференс? [yes/NO]: ").strip()!="yes":
            raise InstallError("cloud_inference_not_approved")
        result=init("openai_compatible",model,url)
        set_key()
    if input("Собрать и запустить контейнеры? [yes/NO]: ").strip()=="yes":
        tunnel=input("Cloudflare Quick Tunnel? [yes/NO]: ").strip()=="yes"
        gpu=False
        if selection=="1":
            gpu=input("Есть NVIDIA Container Toolkit? GPU режим? [yes/NO]: ").strip()=="yes"
        up(tunnel=tunnel,gpu=gpu)
        result["containers_started"]=True
        if selection=="1" and input("Скачать модель Ollama сейчас? Это может быть много ГБ. [yes/NO]: ").strip()=="yes":
            _compose("--profile","local-ollama","exec","-T","ollama","ollama","pull",model)
            result["model_downloaded"]=model
    return result


def stage_restore(archive: Path, key_file: Path) -> dict:
    """Transfer encrypted DB and 32-byte key via stdin; do not replace active DB."""
    archive=archive.expanduser().resolve()
    key_file=key_file.expanduser().resolve()
    manifest=Path(str(archive)+".manifest.json")
    if not archive.is_file() or not manifest.is_file() or not key_file.is_file():
        raise InstallError("archive_manifest_or_key_missing")
    if archive.is_symlink() or manifest.is_symlink() or key_file.is_symlink():
        raise InstallError("restore_symlink_not_allowed")
    if archive.stat().st_size > 138*1024*1024:
        raise InstallError("encrypted_archive_too_large")
    key=key_file.read_bytes()
    if len(key)!=32:
        raise InstallError("backup_key_length_invalid")
    _compose("build", APP)
    cmd=["docker","compose","-f",str(ROOT/"compose.yaml"),
         "run","--rm","--no-deps","-T",APP,"python","-m"]
    first=subprocess.run(cmd+["console.portable_credentials",
                             "import-backup-key"],
                         cwd=ROOT,input=key,capture_output=True)
    if first.returncode:
        raise InstallError("backup_key_import_failed_or_already_present")
    package=BytesIO()
    with zipfile.ZipFile(package,"w",compression=zipfile.ZIP_STORED) as out:
        out.writestr("snapshot.cnbk",archive.read_bytes())
        out.writestr("snapshot.cnbk.manifest.json",manifest.read_bytes())
    second=subprocess.run(cmd+["console.portable_restore"],
                          cwd=ROOT,input=package.getvalue(),
                          capture_output=True)
    if second.returncode:
        raise InstallError("encrypted_restore_verification_failed")
    try:
        result=json.loads(second.stdout.decode().strip().splitlines()[-1])
    except (ValueError,IndexError):
        raise InstallError("restore_stage_response_invalid") from None
    return {"staged":True,"result":result,
            "next":"Inspect staged DB; stop services before explicit activation"}


def verify_source() -> dict:
    """Verify locally checked-out Git objects; do not mistake Git for offsite backup."""
    if shutil.which("git") is None:
        raise InstallError("git_missing")
    check=subprocess.run(["git","fsck","--full","--no-reflogs"],
                         cwd=REPO,capture_output=True,text=True)
    if check.returncode:
        raise InstallError("git_integrity_check_failed")
    status=subprocess.run(["git","status","--porcelain","--untracked-files=no"],
                          cwd=REPO,capture_output=True,text=True)
    if status.returncode:
        raise InstallError("git_status_failed")
    commit=subprocess.run(["git","rev-parse","HEAD"],cwd=REPO,
                          capture_output=True,text=True,check=True).stdout.strip()
    return {"repository_integrity":"git_fsck_ok",
            "source_commit":commit,
            "tracked_changes":bool(status.stdout.strip()),
            "note":"Git validates tracked objects; verify remote ownership and protected releases separately"}


def export_source_bundle(directory: Path) -> dict:
    from hashlib import sha256
    info=verify_source()
    if info["tracked_changes"]:
        raise InstallError("tracked_changes_not_committed")
    directory=directory.expanduser().resolve()
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    name="cybernoc-"+info["source_commit"][:12]+".bundle"
    dest=directory/name
    checksum=directory/(name+".sha256")
    if dest.exists() or checksum.exists():
        raise InstallError("source_bundle_already_exists")
    job=subprocess.run(["git","bundle","create",str(dest),"--all"],
                       cwd=REPO,capture_output=True,text=True)
    if job.returncode:
        raise InstallError("git_bundle_creation_failed")
    verify=subprocess.run(["git","bundle","verify",str(dest)],
                          cwd=REPO,capture_output=True,text=True)
    if verify.returncode:
        dest.unlink(missing_ok=True)
        raise InstallError("git_bundle_verification_failed")
    digest=sha256(dest.read_bytes()).hexdigest()
    _write_new(checksum,digest+"  "+name+"\n")
    return {"bundle":str(dest),"sha256_file":str(checksum),
            "source_commit":info["source_commit"],
            "note":"Store offsite; SHA256 detects accidental transfer corruption, not a forged replacement"}


def main():
    p=argparse.ArgumentParser(description="Portable Cybernova deployment")
    commands=p.add_subparsers(dest="cmd",required=True)
    commands.add_parser("wizard",help="Interactive first-run setup with clear privacy/cost prompts")
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
    commands.add_parser("verify-source",help="Validate Git object integrity and show commit")
    x=commands.add_parser("export-source",help="Create verified Git bundle for offline disaster recovery")
    x.add_argument("--to",type=Path,required=True)
    commands.add_parser("pull-model",help="Download selected local Ollama model")
    commands.add_parser("logs",help="Show last service logs (may contain task content)")
    commands.add_parser("stop",help="Stop containers, preserve volumes")
    commands.add_parser("init-backup-key",help="Generate an encryption key")
    x=commands.add_parser("export-backup-key",help="Copy backup key to offline file")
    x.add_argument("--to",required=True,type=Path)
    x=commands.add_parser("backup",help="Online encrypted DB snapshot to a host directory")
    x.add_argument("--to",type=Path,required=True)
    x=commands.add_parser("import-backup-key",help="Import existing binary backup key into a fresh Docker volume")
    x.add_argument("--from",dest="source",required=True,type=Path)
    x=commands.add_parser("restore",help="Restore archive to a NEW database while service is stopped")
    x.add_argument("--from",dest="source",required=True,type=Path)
    x=commands.add_parser("stage-restore",help="Verify encrypted backup on new machine without replacing database")
    x.add_argument("--from",dest="archive",type=Path,required=True)
    x.add_argument("--key-file",type=Path,required=True)
    args=p.parse_args()
    try:
        if args.cmd=="wizard":
            result=wizard()
        elif args.cmd=="init":
            result=init(args.provider,args.model,args.base_url)
        elif args.cmd=="set-key":
            result=set_key(args.rotate)
        elif args.cmd=="up":
            result=up(args.tunnel,args.gpu)
        elif args.cmd=="verify-source":
            result=verify_source()
        elif args.cmd=="export-source":
            result=export_source_bundle(args.to)
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
        elif args.cmd=="import-backup-key":
            result=import_backup_key(args.source)
        elif args.cmd=="restore":
            result=restore_from_host(args.source)
        elif args.cmd=="export-backup-key":
            dst=args.to.expanduser().resolve()
            if dst.exists() or dst.is_symlink():
                raise InstallError("backup_key_destination_exists")
            dst.parent.mkdir(parents=True,exist_ok=True)
            cid=_compose("ps","-q",APP,capture=True).strip()
            if not cid:
                raise InstallError("container_not_running")
            process=subprocess.run(
                ["docker","cp",cid+":/data/backup.key",str(dst)],
                text=True,capture_output=True,
            )
            if process.returncode:
                raise InstallError("backup_key_export_failed")
            if os.name!="nt":
                dst.chmod(0o600)
            result={"key_exported":str(dst),
                    "warning":"Keep it OFF this machine and never commit to Git"}
        elif args.cmd=="stage-restore":
            result=stage_restore(args.archive,args.key_file)
        else:
            result=backup_to_host(args.to.expanduser().resolve())
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (InstallError, OSError, ValueError, StopIteration) as exc:
        p.exit(2,"CYBERNOVA_SETUP_ERROR: "+str(exc)+"\n")


if __name__=="__main__":
    main()
