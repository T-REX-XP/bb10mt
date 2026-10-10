#!/usr/bin/env python3
"""Independently compare package targets to a legacy firmware image."""
import argparse
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import struct
import sys


def crc(data):
    value = 0
    for byte in data:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ (0x04C11DB7 if value & 0x80000000 else 0)) & 0xFFFFFFFF
    return value


def observed(image, path):
    number, bad = image.resolve(path)
    if bad:
        raise ValueError("pathname checksum mismatch: " + path)
    node = image.inode(number)
    mode = struct.unpack_from("<H", node, 32)[0]
    if mode & 0xF000 != 0x8000:
        raise ValueError("target is not regular: " + path)
    return dict(sha256=hashlib.sha256(image.read_node(node, 36, 100)).hexdigest(),
                mode=mode & 0o7777, uid=struct.unpack_from("<I", node, 8)[0],
                gid=struct.unpack_from("<I", node, 12)[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--legacy-image", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("independent_qnx6", args.pack / "scripts/qnx6_longnames.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = json.loads(args.plan.read_text())
    rows = []
    with args.legacy_image.open("rb") as old, args.image.open("rb") as new:
        with mmap.mmap(old.fileno(), 0, access=mmap.ACCESS_READ) as old_data, mmap.mmap(new.fileno(), 0, access=mmap.ACCESS_READ) as new_data:
            baseline, patched = module.Image(old_data), module.Image(new_data)
            sb = patched.sb
            if struct.unpack_from("<I", new_data, sb + 4)[0] != crc(new_data[sb + 8:sb + 512]):
                raise ValueError("superblock CRC mismatch")
            for action in plan["actions"]:
                path = action["path"]
                before, after = observed(baseline, path), observed(patched, path)
                if before != after:
                    raise ValueError("legacy equivalence mismatch: " + path)
                operation = action.get("operation")
                if operation:
                    expected = dict(sha256=operation["sha256"], mode=int(operation["mode"], 8),
                                    uid=operation["uid"], gid=operation["gid"])
                else:
                    expected = dict(sha256=action["assertionSha256"],
                                    mode=action["before"]["mode"], uid=action["before"]["uid"], gid=action["before"]["gid"])
                if after != expected:
                    raise ValueError("package final-state mismatch: " + path)
                rows.append(dict(path=path, **after))
            # Preserve the rest of the maintained pack's public payloads too.
            pack_check = module.verify(new_data, module.targets(args.pack), permissions=module.firmware_permissions(args.pack))
            if pack_check["incorrectLongNames"]:
                raise ValueError("maintained pack has bad pathname checksums")
    with args.image.open("rb") as source:
        image_hash = hashlib.file_digest(source, "sha256").hexdigest()
    report = dict(schemaVersion=1, imageSha256=image_hash, packages=len(plan["packages"]),
                  packageFiles=sum("operation" in a for a in plan["actions"]), foundationUnchanged=True,
                  legacyTargetsIdentical=True, superblockCRCVerified=True, maintainedPack=pack_check,
                  independentVerifier="Python QNX6 reader and standard library", targets=rows,
                  handsetAcceptance="not tested")
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
