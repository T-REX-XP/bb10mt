"""Rebuild App World's native directory after a confirmed QNX6 lookup defect.

Run on the rooted handset with Python 3.2. The old directory is retained for
rollback. Only the pinned public storefront library replaces unreadable bytes.
"""
import argparse
import errno
import hashlib
import json
import os
import shutil
import stat
import uuid

BASE = '/apps/sys.appworld.gYABgNSvaLtte_snIx7wjRsOcyM/native'
LIBRARY = 'libAppWorldStoreFront.so.1.0.0'
SHA256 = '5bd0d353c27b2d2356ec53e462d7fb1f0c7990ff8124e5fdc03ac3d46ac2d552'


def digest(path):
    with open(path, 'rb') as source:
        return hashlib.sha256(source.read()).hexdigest()


def metadata(source, target):
    info = os.lstat(source)
    os.chown(target, info.st_uid, info.st_gid)
    os.chmod(target, stat.S_IMODE(info.st_mode))


def repair(base, replacement):
    if digest(replacement) != SHA256:
        raise RuntimeError('Replacement storefront is not the pinned payload')
    info = os.lstat(base)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, 89):
        raise RuntimeError('Unexpected native directory')
    target = base + '/' + LIBRARY
    try:
        existing = digest(target)
    except (OSError, IOError) as error:
        if error.errno != errno.ENOENT or os.listdir(base).count(LIBRARY) != 1:
            raise RuntimeError('Not the confirmed filename lookup defect')
    else:
        if existing != SHA256:
            raise RuntimeError('Unknown readable storefront; no replacement made')
        return {'changed': False, 'storefrontVerified': True}

    tag = uuid.uuid4().hex[:12]
    parent = os.path.dirname(base)
    stage = parent + '/.native-fixed-' + tag
    backup = parent + '/.native-backup-' + tag
    os.mkdir(stage, 0o700)
    try:
        def copy_tree(source, destination):
            for name in os.listdir(source):
                old, new = source + '/' + name, destination + '/' + name
                if old == target:
                    shutil.copyfile(replacement, new)
                    os.chown(new, 0, 0)
                    os.chmod(new, 0o755)
                    continue
                item = os.lstat(old)
                if stat.S_ISDIR(item.st_mode):
                    os.mkdir(new, 0o700)
                    copy_tree(old, new)
                elif stat.S_ISREG(item.st_mode):
                    shutil.copyfile(old, new)
                    if digest(old) != digest(new):
                        raise RuntimeError('Native file copy did not verify')
                else:
                    raise RuntimeError('Unexpected special native entry')
                metadata(old, new)
            metadata(source, destination)
        copy_tree(base, stage)
        if digest(stage + '/' + LIBRARY) != SHA256:
            raise RuntimeError('Staged storefront did not verify')
        os.rename(base, backup)
        try:
            os.rename(stage, base)
        except BaseException:
            os.rename(backup, base)
            raise
        return {'changed': True, 'storefrontVerified': True, 'backup': backup}
    finally:
        # Only the uniquely-created, unpublished staging directory is removed.
        if os.path.isdir(stage):
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replacement', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not args.apply or os.geteuid() != 0:
        raise RuntimeError('Explicit apply under the existing root SSH setup required')
    print(json.dumps(repair(BASE, args.replacement)))


if __name__ == '__main__':
    main()
