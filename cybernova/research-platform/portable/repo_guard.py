"""Guard Cybernova Git commits against accidentally tracked sensitive artifacts.

A CI *path* guard, not a substitute for secret scanning, access control,
GPG/Sigstore signed releases, branch protection or offsite backups.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
DENIED = (
    "*.sqlite", "*.sqlite3", "*.sqlite3-wal", "*.sqlite3-shm", "*.db",
    "*.cnbk", "*.har", "*.pcap", "*.pcapng", "*.gguf", "*.safetensors",
    "*.ckpt", "*.onnx", "id_rsa", "id_ed25519", "*.pem", "*.p12", "*.pfx",
    "*.key", ".env", ".env.local", ".env.production", "credentials.json",
    "secrets.json", "*.private.json", "*-private.json",
)
DIRNAMES = frozenset({
    "secrets", "private", "backups", "models", "checkpoints",
})
PERMITTED = (".env.example", "requirements.lock", "poetry.lock")
MAX_TRACKED_FILE = 20 * 1024 * 1024


def prohibited(path: str) -> bool:
    normalized = path.replace("\\", "/")
    components = normalized.split("/")
    if normalized.startswith("/") or normalized in {"", ".", ".."} or ".." in components:
        return True
    if components[-1] in PERMITTED:
        return False
    if any(section.lower() in DIRNAMES for section in components[:-1]):
        return True
    filename = components[-1].lower()
    return any(fnmatch.fnmatch(filename, item) for item in DENIED)


def review_tracked(paths: list[str]) -> list[str]:
    return [item for item in paths if prohibited(item)]


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT,
        capture_output=True, check=False,
    )
    if result.returncode:
        print("GIT_FILE_INVENTORY_FAILED", file=sys.stderr)
        return 2
    paths = [p.decode("utf-8", errors="replace")
             for p in result.stdout.split(b"\x00") if p]
    errors = review_tracked(paths)
    for path in paths:
        if path in errors:
            continue
        file = ROOT / path
        if file.exists() and file.stat().st_size > MAX_TRACKED_FILE:
            errors.append(path + ": larger than 20 MiB")
    if errors:
        print("CYBERNOVA_GIT_ARTIFACT_GUARD_FAILED", file=sys.stderr)
        for filename in errors[:30]:
            print("  " + filename, file=sys.stderr)
        return 1
    print("CYBERNOVA_GIT_ARTIFACT_GUARD_OK tracked=" + str(len(paths)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
