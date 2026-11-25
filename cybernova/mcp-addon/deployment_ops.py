"""Restricted deployment operations for Cybernova's managed Auto Updater.

Only the pinned GitHub repository is accepted. Operations that can change releases
refuse to run while the 30-second updater owns its lock. Run as cybernova, never root.
"""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import time
from contextlib import contextmanager

WORK = Path("/workspace/cybernova-updater")
CONFIG = WORK / "config.json"
SHA = re.compile(r"^[0-9a-f]{40}$")

def _core():
    sys.path.insert(0, str(WORK / "app"))
    from cybernova_updater.core import Settings, GitBackend, Deployer, Watcher, atomic_json
    return Settings, GitBackend, Deployer, Watcher, atomic_json

def _settings():
    Settings, _, _, _, _ = _core()
    cfg = Settings.from_json(CONFIG)
    if cfg.work != WORK or cfg.active != Path("/workspace/cybernova-agent"):
        raise RuntimeError("Unexpected deployment paths; refusing operation")
    return cfg

def _state():
    p = WORK / "state.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}

def _require_sha(sha):
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("Expected full 40-character lowercase commit SHA")
    return sha

def _require_operator():
    if os.geteuid() == 0:
        raise PermissionError("Deployment operations must run as cybernova, not root")
    if not CONFIG.is_file():
        raise RuntimeError("Updater config absent")

@contextmanager
def _exclusive():
    """Use the *same* process lock as cybernova_updater.cli; refuse conflicts."""
    _require_operator()
    lock_path = WORK / ".runner.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Auto Updater is running; use GitHub auto-deploy or stop it before manual changes") from None
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

def _validate_active(cfg):
    _, _, Deployer, _, _ = _core()
    return Deployer(cfg)._verify_managed_link()

def status():
    _require_operator()
    cfg = _settings()
    state = _state()
    current = WORK / "current"
    releases = WORK / "releases"
    reports = WORK / "reports"
    active = cfg.active
    return {
        "ok": True,
        "status": state.get("status", "uninitialized"),
        "baseline_commit": state.get("baseline_commit"),
        "last_seen_commit": state.get("last_seen_commit"),
        "deployed_commit": state.get("deployed_commit"),
        "error": state.get("error"),
        "window_started_at": state.get("started_at"),
        "window_expires_at": state.get("expires_at"),
        "active_managed": active.is_symlink() and os.readlink(active) == str(current),
        "current_target": str(current.resolve()) if current.is_symlink() else None,
        "release_count": sum(1 for p in releases.iterdir() if p.is_dir() and not p.is_symlink()) if releases.is_dir() else 0,
        "last_reports": [p.name for p in sorted(reports.glob("*.json"),reverse=True)[:5]] if reports.is_dir() else [],
    }

def preview():
    _require_operator()
    cfg = _settings()
    _, GitBackend, _, _, _ = _core()
    state = _state()
    head = GitBackend(cfg).head()
    return {
        "ok": True,
        "remote_head": head,
        "last_seen_commit": state.get("last_seen_commit"),
        "deployed_commit": state.get("deployed_commit"),
        "new_commit": head != state.get("last_seen_commit"),
        "source": cfg.source,
        "branch": cfg.branch,
        "note": "Only changes inside cybernova/v10 trigger agent deployment. Poller applies them automatically.",
    }

def stage(commit_sha):
    sha = _require_sha(commit_sha)
    with _exclusive():
        cfg = _settings()
        _, GitBackend, Deployer, _, atomic_json = _core()
        repo = GitBackend(cfg)
        if repo.head() != sha:
            raise RuntimeError("Commit is not current approved branch HEAD")
        repo.fetch(sha)
        stage_dir = WORK / "manual_stage" / sha
        if stage_dir.exists() or stage_dir.is_symlink():
            raise RuntimeError("Stage exists; refuse overwrite")
        tree = repo.tree(sha)
        repo.materialize(sha,stage_dir)
        result = Deployer(cfg)._test(stage_dir)
        atomic_json(stage_dir / ".stage-result.json",
                    {"commit":sha,"tree":tree,"staged_at":time.time(),"tests_passed":True})
        return {"ok":True,"commit":sha,"tree":tree,"tests_passed":True,"test_tail":result[-1500:]}

def apply(commit_sha):
    sha = _require_sha(commit_sha)
    with _exclusive():
        cfg = _settings()
        _, GitBackend, _, Watcher, _ = _core()
        stage_dir = WORK / "manual_stage" / sha
        marker = stage_dir / ".stage-result.json"
        if not marker.is_file() or stage_dir.is_symlink():
            raise RuntimeError("Must stage and pass tests first")
        data=json.loads(marker.read_text(encoding="utf-8"))
        if data.get("commit") != sha or not data.get("tests_passed"):
            raise RuntimeError("Invalid stage record")
        repo=GitBackend(cfg)
        if repo.head() != sha:
            raise RuntimeError("Remote HEAD changed after staging")
        repo.fetch(sha)
        if repo.tree(sha) != data["tree"]:
            raise RuntimeError("Staged source tree changed")
        _validate_active(cfg)
        watcher=Watcher(cfg)
        if watcher.state.get("status") in ("stopped_error","stopped_window"):
            raise RuntimeError("Updater is stopped; manual state review needed")
        if watcher.state.get("last_seen_commit") == sha:
            raise RuntimeError("Commit already processed by updater; no deployment needed")
        outcome=watcher.tick()
        if outcome.get("status") == "stopped_error":
            raise RuntimeError("Updater stopped on error: " + str(outcome.get("error",""))[:400])
        if outcome.get("deployed_commit") != sha:
            raise RuntimeError("Commit did not change the approved agent source tree")
        return {"ok":True,"deployed_commit":sha,"status":outcome.get("status"),
                "report":outcome.get("last_report")}

def rollback(target="legacy"):
    if target != "legacy":
        _require_sha(target)
    with _exclusive():
        cfg = _settings()
        _, _, Deployer, _, atomic_json = _core()
        pointer = _validate_active(cfg)
        releases = WORK / "releases"
        if target == "legacy":
            destination = WORK / "legacy-agent"
        else:
            destination = releases / target
        if destination.is_symlink() or not destination.is_dir():
            raise RuntimeError("Target must be an existing managed release directory")
        if not destination.resolve().is_relative_to(WORK.resolve()):
            raise RuntimeError("Rollback target escaped managed directory")
        if not (destination / "agent.py").is_file() or not (destination / "tests").is_dir():
            raise RuntimeError("Rollback candidate incomplete")
        tested=Deployer(cfg)._test(destination)
        next_link=WORK / ".current.rollback"
        if next_link.exists() or next_link.is_symlink():
            raise RuntimeError("Pending rollback link exists; inspect state")
        previous=str(pointer.resolve()) if pointer.is_symlink() else None
        os.symlink(destination,next_link)
        try:
            os.replace(next_link,pointer)
        except BaseException:
            next_link.unlink(missing_ok=True)
            raise
        state=_state()
        state["status"]="stopped_error"
        state["error"]="Manual rollback to "+str(target)+"; operator must explicitly resume updater"
        state["rollback_previous"]=previous
        state["rollback_target"]=str(destination)
        state["last_poll_at"]=time.time()
        state["deployed_commit"]=target if target!="legacy" else None
        state["deployed_tree"]=None
        atomic_json(WORK / "state.json",state)
        return {"ok":True,"rolled_back_to":target,"previous":previous,
                "updater_stopped":True,"test_tail":tested[-800:]}

def recent_events(limit=10):
    _require_operator()
    if not isinstance(limit,int) or not 1<=limit<=20:
        raise ValueError("limit 1..20")
    reports=WORK/"reports"
    records=[]
    if reports.is_dir():
        for p in sorted(reports.glob("*.json"), reverse=True)[:limit]:
            if p.is_symlink() or p.stat().st_size>20000:continue
            try: x=json.loads(p.read_text(encoding="utf-8"))
            except (OSError,ValueError):continue
            records.append({"report":p.name,"commit":x.get("commit"),
                            "status":x.get("status"),"timestamp":x.get("timestamp")})
    return {"ok":True,"events":records}

COMMANDS={"status":status,"preview":preview,"stage":stage,"apply":apply,
          "rollback":rollback,"events":recent_events}
if __name__=="__main__":
    try:
        name=sys.argv[1]
        if name not in COMMANDS:raise ValueError("Unknown operation")
        value=sys.argv[2] if len(sys.argv)>2 else None
        if name in ("stage","apply"):
            if value is None:raise ValueError("Commit SHA required")
            result=COMMANDS[name](value)
        elif name=="rollback":
            result=rollback(value or "legacy")
        elif name=="events":
            result=recent_events(int(value) if value is not None else 10)
        else:
            if value is not None:raise ValueError("Unexpected argument")
            result=COMMANDS[name]()
        print(json.dumps(result,ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__,"message":str(exc)[:500]},
                         ensure_ascii=False))
        sys.exit(1)
