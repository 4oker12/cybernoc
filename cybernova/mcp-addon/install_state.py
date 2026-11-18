"""Private per-activation recovery snapshot; never modifies the agent or its releases."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import uuid


def _regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected regular profile/state file")


def _tree_digests(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError("Addon recovery source contains a symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif not path.is_dir():
            raise ValueError("Addon recovery source contains a special file")
    return result


def snapshot(destination, profile):
    destination, profile = Path(destination), Path(profile)
    _regular(profile)
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError("Unsafe addon destination")
    backup = destination.parent / (destination.name + '.activation.' + uuid.uuid4().hex)
    backup.mkdir(mode=0o700)
    before = profile.read_bytes()
    fd = os.open(backup/'profile.before', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(before)
        stream.flush()
        os.fsync(stream.fileno())
    existed = destination.exists()
    digests = _tree_digests(destination) if existed else {}
    if existed:
        shutil.copytree(destination, backup/'addon.before', symlinks=True)
    manifest = {'destination': str(destination.absolute()), 'profile': str(profile.absolute()),
                'addon_existed': existed, 'addon_sha256': digests,
                'profile_sha256': hashlib.sha256(before).hexdigest()}
    fd = os.open(backup/'state.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(manifest, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return backup


def restore(backup):
    backup = Path(backup)
    if backup.is_symlink() or not backup.is_dir():
        raise ValueError("Unsafe recovery snapshot")
    _regular(backup/'state.json')
    state = json.loads((backup/'state.json').read_text())
    destination, profile = Path(state['destination']), Path(state['profile'])
    if backup.parent != destination.parent or not backup.name.startswith(destination.name+'.activation.'):
        raise ValueError("Recovery snapshot does not match destination")
    _regular(backup/'profile.before')
    before = (backup/'profile.before').read_bytes()
    if hashlib.sha256(before).hexdigest() != state['profile_sha256']:
        raise ValueError("Recovery profile checksum mismatch")
    if destination.is_symlink():
        raise ValueError("Refusing symlink destination during rollback")
    if state['addon_existed']:
        source = backup/'addon.before'
        if source.is_symlink() or not source.is_dir():
            raise ValueError("Previous addon snapshot missing")
        if _tree_digests(source) != state['addon_sha256']:
            raise ValueError("Previous addon checksum mismatch")
        stage = backup/'restored-addon'
        shutil.copytree(source, stage, symlinks=True)
    if destination.exists():
        os.replace(destination, backup/'failed-addon')
    if state['addon_existed']:
        os.replace(backup/'restored-addon', destination)
    temporary = profile.with_name(profile.name+'.restore.'+uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(before)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, profile)
    return {'restored': True, 'previous_addon_restored': state['addon_existed']}


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'snapshot':
        print(snapshot(sys.argv[2], sys.argv[3]))
    elif len(sys.argv) == 3 and sys.argv[1] == 'restore':
        print(json.dumps(restore(sys.argv[2])))
    else:
        raise SystemExit('snapshot DEST PROFILE | restore SNAPSHOT')
