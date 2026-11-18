#!/usr/bin/env python3
"""Bounded Cybernova session runner. Fixed local-only preset; never a shell API."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path("/workspace/cybernova-updater/sessions")
LAB = Path("/workspace/cybernova-pentest-kit-src/cybernova/v10/pentest_pack")
LAB_PY = Path("/workspace/cybernova-lab-review-venv/bin/python")
PRESET = "local_qwen_baseline"
DURATION_LIMIT = 1080
ID = re.compile(r"^[0-9a-f]{32}$")
EXPECTED = frozenset({"curl.http", "httpx.http", "openssl.x509", "jq.json",
                      "python.ip", "python.syntax", "dnspython.zone"})
QWEN_EXPECTED = frozenset({"python.ip", "python.syntax"})


def _root():
    if ROOT.is_symlink():
        raise ValueError("Session root must not be a symlink")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not ROOT.is_dir():
        raise ValueError("Invalid session directory")
    os.chmod(ROOT, 0o700)
    return ROOT


def _read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or unsafe session record")
    if path.stat().st_size > 128_000:
        raise ValueError("Session record exceeds limit")
    data = json.loads(path.read_text(encoding="utf-8"))
    if type(data) is not dict:
        raise ValueError("Session record must be an object")
    return data


def _write(path, data):
    raw = (json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n").encode()
    if len(raw) > 128_000:
        raise ValueError("Session record exceeds limit")
    temp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _folder(session_id):
    if type(session_id) is not str or not ID.fullmatch(session_id):
        raise ValueError("Invalid session identifier")
    path = _root() / session_id
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Unknown session")
    return path


def _public_status(folder):
    record = _read(folder / "session.json")
    if (folder / "result.json").exists():
        result = _read(folder / "result.json")
        return {"ok": True, "session_id": record["session_id"], "preset": PRESET,
                "state": result["state"], "passed": result.get("passed", False),
                "finished_at": result.get("finished_at"),
                "reason": result.get("reason", "")}
    age = time.time() - record["started_at"]
    return {"ok": True, "session_id": record["session_id"], "preset": PRESET,
            "state": "running" if 0 <= age <= DURATION_LIMIT + 120 else "stalled",
            "passed": False, "age_seconds": max(0, int(age))}


def start(preset=PRESET):
    if preset != PRESET:
        raise ValueError("Unknown session preset")
    _root()
    if not LAB_PY.is_file() or not (LAB / "cybernova_lab" / "__main__.py").is_file():
        raise RuntimeError("Local lab checkout or isolated Python environment missing")
    lock_fd = os.open(ROOT / ".start.lock", os.O_CREAT | os.O_RDWR |
                      getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(lock_fd, "r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        for folder in ROOT.iterdir():
            if (folder.is_dir() and not folder.is_symlink() and ID.fullmatch(folder.name)
                    and (folder / "session.json").is_file()):
                if _public_status(folder)["state"] == "running":
                    return {"ok": False, "reason": "session_already_running",
                            "session_id": folder.name}
        session_id = uuid.uuid4().hex
        folder = ROOT / session_id
        folder.mkdir(mode=0o700)
        _write(folder / "session.json",
               {"session_id": session_id, "preset": PRESET,
                "started_at": time.time(), "scope": "LOCAL_LAB_ONLY"})
        with (folder / "worker.stdout").open("xb") as stdout, \
             (folder / "worker.stderr").open("xb") as stderr:
            os.chmod(stdout.name, 0o600)
            os.chmod(stderr.name, 0o600)
            subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                              "worker", session_id],
                             stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                             start_new_session=True, close_fds=True,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                  "PYTHONUNBUFFERED": "1", "HOME": "/nonexistent"})
        return {"ok": True, "session_id": session_id, "preset": PRESET,
                "state": "running", "scope": "LOCAL_LAB_ONLY"}


def _check_evidence(root):
    count = 0
    evidence = root / "evidence"
    if root.is_symlink() or evidence.is_symlink() or not evidence.is_dir():
        raise ValueError("Missing or unsafe evidence directory")
    for path in (root / "evidence").glob("*/*.json"):
        if path.parent.is_symlink() or not ID.fullmatch(path.parent.name):
            raise ValueError("Unsafe evidence run directory")
        obj = _read(path)
        if "stdout_sha256" not in obj:
            continue
        if obj.get("capture_complete", True) is not True:
            raise ValueError("Incomplete evidence capture")
        for stream in ("stdout", "stderr"):
            name = obj.get(stream + "_file")
            if (type(name) is not str or not re.fullmatch(r"[0-9a-f]{32}\." + stream, name)):
                raise ValueError("Invalid artifact name")
            artifact = path.parent / name
            if artifact.is_symlink() or not artifact.is_file():
                raise ValueError("Missing artifact")
            if artifact.stat().st_size > 4_000_000:
                raise ValueError("Evidence artifact exceeds capture quota")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if digest != obj[stream + "_sha256"] or artifact.stat().st_size != obj[stream + "_bytes"]:
                raise ValueError("Evidence digest or size mismatch")
        count += 1
    return count


def worker(session_id):
    folder = _folder(session_id)
    result = {"state": "failed", "passed": False, "finished_at": None,
              "reason": "worker_not_completed"}
    try:
        work = folder / "work"
        with (folder / "lab.stdout").open("xb") as stdout, \
             (folder / "lab.stderr").open("xb") as stderr:
            os.chmod(stdout.name, 0o600)
            os.chmod(stderr.name, 0o600)
            proc = subprocess.run([str(LAB_PY), "-m", "cybernova_lab", "demo",
                                   "--root", str(work), "--with-qwen"],
                                  cwd=LAB, stdin=subprocess.DEVNULL,
                                  stdout=stdout, stderr=stderr, timeout=DURATION_LIMIT,
                                  check=False, env={"PATH": "/usr/bin:/bin",
                                                    "LANG": "C.UTF-8", "HOME": "/nonexistent"})
        adapter = _read(work / "adapter-report.json")
        qwen = _read(work / "qwen-report.json")
        scripted = {x.get("adapter_id") for x in adapter.get("actions", [])
                    if x.get("exit_code") == 0}
        autonomous = {x.get("adapter_id") for x in qwen.get("actions", [])
                      if x.get("exit_code") == 0}
        evidence_count = _check_evidence(work)
        good = (proc.returncode == 0 and adapter.get("status") == "completed_local_workflow"
                and qwen.get("status") == "completed_local_workflow"
                and EXPECTED <= scripted and QWEN_EXPECTED <= autonomous
                and qwen.get("external_target_requests") == 0
                and evidence_count >= 9)
        result = {"state": "completed", "passed": good,
                  "reason": "all_checks_passed" if good else "requirements_not_met",
                  "scripted_adapters": sorted(scripted), "qwen_adapters": sorted(autonomous),
                  "adapter_status": adapter.get("status"), "qwen_status": qwen.get("status"),
                  "qwen_successful_actions": qwen.get("successful_actions"),
                  "evidence_manifests_verified": evidence_count,
                  "external_target_requests": qwen.get("external_target_requests"),
                  "process_exit_code": proc.returncode}
    except subprocess.TimeoutExpired:
        result["reason"] = "session_timeout"
    except Exception as exc:
        result["reason"] = type(exc).__name__
    result["finished_at"] = time.time()
    _write(folder / "result.json", result)
    return 0 if result.get("passed") else 1


def status(session_id):
    return _public_status(_folder(session_id))


def report(session_id):
    folder = _folder(session_id)
    result = _public_status(folder)
    if (folder / "result.json").is_file():
        safe = _read(folder / "result.json")
        for key in ("scripted_adapters", "qwen_adapters", "adapter_status",
                    "qwen_status", "qwen_successful_actions", "evidence_manifests_verified",
                    "external_target_requests", "process_exit_code"):
            result[key] = safe.get(key)
    return result


def main(args):
    try:
        if args == ["start"]:
            response = start()
        elif len(args) == 2 and args[0] in ("status", "report", "worker"):
            if args[0] == "worker":
                return worker(args[1])
            response = globals()[args[0]](args[1])
        else:
            raise ValueError("Expected start | status ID | report ID")
        print(json.dumps(response, ensure_ascii=False))
        return 0 if response.get("ok") else 2
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__,
                          "reason": str(exc)[:240]}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
