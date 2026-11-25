"""Encrypted, verified, restorable SQLite backups for portable Cybernova.

Not a Git backup: source code stays in GitHub; investigation data is private.
Uses SQLite online backup API (WAL-safe snapshot), AES-256-GCM authenticated
encryption, SHA-256 transfer manifest, SQLite integrity_check on recovery.
Key must be copied OFF THE MACHINE: a local-only key is NOT disaster recovery.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
from contextlib import closing
import sqlite3
import tempfile

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

MAGIC = b"CNBK1\x00"
MAX_SNAPSHOT = 128 * 1024 * 1024


class BackupError(RuntimeError):
    pass


def _default_db() -> Path:
    return Path(os.environ.get("CYBERNOVA_COMM_DB",
                               str(Path.home()/".local/share/cybernova/communications.sqlite3")))


def _key_path() -> Path:
    return Path(os.environ.get("CYBERNOVA_BACKUP_KEY_FILE", "/data/backup.key"))


def _check_file(path: Path):
    if path.is_symlink():
        raise BackupError("symlinks_not_allowed")
    if not path.is_file():
        raise BackupError("file_not_found")


def create_key(path: Path | None = None) -> Path:
    target = path or _key_path()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.is_symlink():
        raise BackupError("key_symlink_forbidden")
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise BackupError("key_already_exists") from None
    try:
        with os.fdopen(fd,"wb") as output:
            output.write(secrets.token_bytes(32))
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return target


def load_key(path: Path | None = None) -> bytes:
    target = path or _key_path()
    _check_file(target)
    if os.name != "nt" and target.stat().st_mode & 0o077:
        raise BackupError("key_file_permissions_too_open")
    key = target.read_bytes()
    if len(key) != 32:
        raise BackupError("backup_key_must_be_32_bytes")
    if AESGCM is None:
        raise BackupError("cryptography_required")
    return key


def _integrity(path: Path) -> None:
    uri = path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as db, db:
        result = db.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise BackupError("sqlite_integrity_failed")


def _atomic_write(path: Path, content: bytes):
    if path.exists() or path.is_symlink():
        raise BackupError("destination_already_exists")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def backup(source: Path, destination: Path, *, key_path: Path | None = None) -> dict:
    _check_file(source)
    if source.resolve() == destination.resolve():
        raise BackupError("destination_same_as_database")
    key = load_key(key_path)
    with tempfile.TemporaryDirectory(prefix="cybernova-snapshot-") as temp:
        snapshot = Path(temp) / "snapshot.sqlite3"
        # SQLite backup incorporates the source WAL without copy races.
        with closing(sqlite3.connect(str(source), timeout=20)) as src, src:
            with closing(sqlite3.connect(str(snapshot))) as dst, dst:
                src.backup(dst)
        _integrity(snapshot)
        size = snapshot.stat().st_size
        if size > MAX_SNAPSHOT:
            raise BackupError("snapshot_too_large_use_offsite_volume_backup")
        plaintext = snapshot.read_bytes()
    nonce = secrets.token_bytes(12)
    ciphertext = MAGIC + nonce + AESGCM(key).encrypt(
        nonce, plaintext, MAGIC,
    )
    manifest = {
        "format": "CNBK1", "encrypted": "AES-256-GCM",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "ciphertext_bytes": len(ciphertext),
        "snapshot_bytes": len(plaintext),
        "integrity": "sqlite_integrity_check_ok",
    }
    _atomic_write(destination, ciphertext)
    manifest_path = Path(str(destination) + ".manifest.json")
    try:
        _atomic_write(manifest_path,
                      (json.dumps(manifest, indent=2,sort_keys=True)+"\n").encode())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return {"backup":str(destination),"manifest":str(manifest_path),
            "ciphertext_sha256":manifest["ciphertext_sha256"],
            "snapshot_bytes":len(plaintext)}


def verify(destination: Path, *, key_path: Path | None = None) -> bytes:
    key = load_key(key_path)
    _check_file(destination)
    manifest_path = Path(str(destination)+".manifest.json")
    _check_file(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = destination.read_bytes()
    if (manifest.get("format") != "CNBK1" or
            manifest.get("ciphertext_sha256") != hashlib.sha256(payload).hexdigest()):
        raise BackupError("backup_manifest_mismatch")
    if not payload.startswith(MAGIC) or len(payload) < len(MAGIC)+12+16:
        raise BackupError("backup_header_invalid")
    nonce = payload[len(MAGIC):len(MAGIC)+12]
    encrypted = payload[len(MAGIC)+12:]
    try:
        data = AESGCM(key).decrypt(nonce, encrypted, MAGIC)
    except Exception:
        raise BackupError("backup_authentication_failed_or_wrong_key") from None
    if len(data) > MAX_SNAPSHOT:
        raise BackupError("snapshot_too_large")
    with tempfile.TemporaryDirectory(prefix="cybernova-verify-") as temp:
        snap = Path(temp)/"verify.sqlite3"
        snap.write_bytes(data)
        _integrity(snap)
    return data


def restore(destination: Path, target: Path, *, key_path: Path | None = None) -> dict:
    """Only restore to a NEW DB file; stop the app before swapping DBs."""
    if target.exists() or target.is_symlink():
        raise BackupError("restore_target_already_exists")
    data = verify(destination,key_path=key_path)
    _atomic_write(target,data)
    return {"restored_to":str(target),"bytes":len(data),
            "note":"Stop services and manually replace database only after validating this copy"}


def main():
    parser=argparse.ArgumentParser(description="Cybernova encrypted database backups")
    sub=parser.add_subparsers(dest="cmd",required=True)
    k=sub.add_parser("init-key",help="Create local random backup encryption key once")
    k.add_argument("--key-file",type=Path)
    b=sub.add_parser("backup",help="Create online encrypted SQLite backup")
    b.add_argument("--output",required=True,type=Path)
    b.add_argument("--db",type=Path)
    b.add_argument("--key-file",type=Path)
    v=sub.add_parser("verify",help="Authenticate and integrity-check backup")
    v.add_argument("file",type=Path)
    v.add_argument("--key-file",type=Path)
    r=sub.add_parser("restore",help="Restore verified snapshot to new file only")
    r.add_argument("file",type=Path)
    r.add_argument("--to",required=True,type=Path)
    r.add_argument("--key-file",type=Path)
    args=parser.parse_args()
    try:
        if args.cmd=="init-key":
            print(json.dumps({"key_created":str(create_key(args.key_file)),
                              "action":"COPY THIS KEY OFF THE MACHINE SECURELY"}))
        elif args.cmd=="backup":
            print(json.dumps(backup(args.db or _default_db(),args.output,
                                    key_path=args.key_file)))
        elif args.cmd=="verify":
            data=verify(args.file,key_path=args.key_file)
            print(json.dumps({"verified":True,"snapshot_bytes":len(data)}))
        else:
            print(json.dumps(restore(args.file,args.to,key_path=args.key_file)))
    except (BackupError, OSError, ValueError, sqlite3.DatabaseError) as exc:
        parser.exit(2,"BACKUP_ERROR: "+str(exc)+"\n")


if __name__ == "__main__":
    main()
