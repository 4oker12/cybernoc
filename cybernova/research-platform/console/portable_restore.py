"""Safe cross-machine import of an encrypted Cybernova backup.

Input: one ZIP stream on stdin with *exactly* snapshot.cnbk and
snapshot.cnbk.manifest.json. No extraction of attacker-controlled paths.
Always restores to a NEW filename; never overwrites live communications DB.
"""
from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import sys
import zipfile

from .backup import BackupError, restore

MAX_INPUT_BYTES = 140 * 1024 * 1024
DATA_DIR = Path(os.environ.get("CYBERNOVA_COMM_DB", "/data/communications.sqlite3")).parent
DEST = DATA_DIR / "communications-restored.sqlite3"
TEMP = DATA_DIR / "incoming-cybernova-backup.cnbk"
EXPECTED = {"snapshot.cnbk", "snapshot.cnbk.manifest.json"}


def stage(data: bytes, *, destination: Path = DEST, incoming: Path = TEMP) -> dict:
    if not data or len(data) > MAX_INPUT_BYTES:
        raise BackupError("restore_package_too_large_or_empty")
    if incoming.exists() or incoming.is_symlink() or destination.exists():
        raise BackupError("staging_destination_already_exists")
    try:
        z = zipfile.ZipFile(BytesIO(data))
        entries = z.infolist()
        if {item.filename for item in entries} != EXPECTED or len(entries) != 2:
            raise BackupError("restore_package_unexpected_paths")
        for item in entries:
            if item.file_size > MAX_INPUT_BYTES:
                raise BackupError("restore_package_entry_too_large")
        payload = z.read("snapshot.cnbk")
        manifest = z.read("snapshot.cnbk.manifest.json")
    except (zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        raise BackupError("restore_package_invalid") from exc
    incoming.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(incoming, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        manifest_path = Path(str(incoming)+".manifest.json")
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(manifest)
            out.flush()
            os.fsync(out.fileno())
        result = restore(incoming, destination)
        result["activated"] = False
        result["instructions"] = (
            "STOP Cybernova; verify this database; archive the old database "
            "and WAL/SHM; activate via a separate explicit maintenance action"
        )
        return result
    finally:
        incoming.unlink(missing_ok=True)
        Path(str(incoming)+".manifest.json").unlink(missing_ok=True)


def main():
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES+1)
        result = stage(payload)
        print(json.dumps(result))
    except (OSError, BackupError, ValueError) as exc:
        print("RESTORE_STAGE_ERROR:"+str(exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
