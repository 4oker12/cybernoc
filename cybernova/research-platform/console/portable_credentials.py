"""Import hosted-provider credentials into the named, private Cybernova data volume.

The installer transfers the key through the child's standard input. It is
never printed, passed as argv, committed, or added to a Docker image layer.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

KEY_FILE = Path(os.environ.get("CYBERNOVA_LLM_API_KEY_FILE",
                               "/data/model_api_key"))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("command",choices=["import-model-key","import-backup-key"])
    parser.add_argument("--rotate",action="store_true")
    args=parser.parse_args()
    key=sys.stdin.buffer.read(10020)
    if args.command=="import-model-key":
        key=key.strip()
    else:
        if len(key)!=32:
            parser.exit(2,"backup_key_must_be_32_bytes\n")
        target=Path(os.environ.get("CYBERNOVA_BACKUP_KEY_FILE","/data/backup.key"))
        if target.exists() and not args.rotate:
            parser.exit(2,"backup_key_exists\n")
        key_path=target
    if args.command=="import-model-key":
        key_path=KEY_FILE
    if args.command=="import-model-key" and (not 8 <= len(key) <= 10000 or any(b<32 for b in key)):
        parser.exit(2,"invalid_api_key\n")
    key_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if key_path.is_symlink():
        parser.exit(2,"symlink_forbidden\n")
    if key_path.exists() and not args.rotate:
        parser.exit(2,"key_exists_use_rotate\n")
    tmp=key_path.with_name(key_path.name+".new-"+str(os.getpid()))
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(key + (b"\n" if args.command=="import-model-key" else b""))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp,key_path)
        print("KEY_IMPORTED_TO_PRIVATE_VOLUME")
    finally:
        tmp.unlink(missing_ok=True)


if __name__=="__main__":
    main()
