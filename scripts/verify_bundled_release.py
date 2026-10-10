"""Independently verify checksums, archives and embedded runtime inventories."""
import argparse
import hashlib
import io
import json
import pathlib
import struct
import tarfile
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def embedded(data):
    at = 0
    while (at := data.find(b"PK\x05\x06", at)) >= 0:
        if at + 22 > len(data):
            break
        comment = struct.unpack_from("<H", data, at + 20)[0]
        size, offset = struct.unpack_from("<II", data, at + 12)
        start, end = at - size - offset, at + 22 + comment
        if start >= 0 and data[start:start + 4] == b"PK\x03\x04" and end <= len(data):
            payload = data[start:end]
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    manifest = json.loads(archive.read("manifest.json"))
                    if manifest.get("schema") == 1:
                        return payload, manifest
            except (ValueError, KeyError, zipfile.BadZipFile):
                pass
        at += 4
    raise ValueError("embedded runtime ZIP missing")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--compare", help="Second independently built distribution")
    parser.add_argument("--record", help="Write machine-readable verification report")
    args = parser.parse_args()
    root = pathlib.Path(args.directory)
    expected_version = json.loads((root / 'sbom.cdx.json').read_text())['metadata']['component']['version']
    checksums = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        sha, name = line.split("  ", 1)
        assert pathlib.PurePath(name).name == name and name not in checksums
        with (root / name).open("rb") as file:
            assert hashlib.file_digest(file, "sha256").hexdigest() == sha, name
        checksums[name] = sha
    assert len(checksums) in (16, 17), len(checksums)
    if 'build-version.json' in checksums:
        version = json.loads((root / 'build-version.json').read_text())['version']
        assert json.loads((root / 'sbom.cdx.json').read_text())['metadata']['component']['version'] == version
    assert set(p.name for p in root.iterdir()) == {*checksums, "SHA256SUMS"}
    report = {"verifiedChecksumEntries": len(checksums), "targets": {}, "sha256": checksums}
    lock = json.loads((root / "runtime.lock.json").read_text())
    with zipfile.ZipFile(root / "runtime-sources.zip") as sources:
        for row in lock["sources"]:
            assert digest(sources.read(row["filename"])) == row["sha256"], row["filename"]
    report["matchingNativeSourceArchives"] = len(lock["sources"])
    for target in lock["targets"]:
        suffix = "-" + target + (".exe" if target.startswith("windows-") else "")
        names = [n for n in checksums if n.startswith("bb10mt-") and n.endswith(suffix)]
        assert len(names) == 1, names
        name = names[0]
        data = (root / name).read_bytes()
        payload, manifest = embedded(data)
        assert manifest["target"] == target
        if 'build-version.json' in checksums:
            assert manifest['version'] == expected_version
        with zipfile.ZipFile(io.BytesIO(payload)) as runtime:
            expected = {"manifest.json", *(row["path"] for row in manifest["files"])}
            assert set(runtime.namelist()) == expected
            for row in manifest["files"]:
                member = runtime.getinfo(row["path"])
                content = runtime.read(member)
                assert len(content) == row["size"] and digest(content) == row["sha256"], row["path"]
                assert member.external_attr >> 16 & 0o777 == row["mode"], row["path"]
                assert member.date_time == (1980, 1, 1, 0, 0, 0)
            assert "licenses/libusb-COPYING" in expected
            if target.startswith("linux-"):
                assert manifest["loader"] in expected
                assert {"licenses/gcc-14-COPYING.RUNTIME", "bin/fusermount3", "lib/fusermount3.real"} <= expected
            if target.startswith("windows-"):
                assert {"lib/vcruntime140.dll", "licenses/Microsoft-VC-Runtime.rtf"} <= expected
        app = "bb10mt.exe" if target.startswith("windows-") else "bb10mt"
        archive_name = name.removesuffix(".exe") + (".zip" if target.startswith("windows-") else ".tar.gz")
        if archive_name.endswith(".zip"):
            with zipfile.ZipFile(root / archive_name) as archive:
                assert archive.read(app) == data
                assert "docs/BUNDLED_RUNTIME.md" in archive.namelist()
        else:
            with tarfile.open(root / archive_name) as archive:
                assert archive.extractfile(app).read() == data
                assert archive.getmember(app).mode == 0o755
                assert all(member.mtime == 0 for member in archive.getmembers())
                assert "docs/BUNDLED_RUNTIME.md" in archive.getnames()
        report["targets"][target] = {"executableBytes": len(data), "payloadSHA256": digest(payload), "verifiedRuntimeFiles": len(manifest["files"]), "archivedExecutableMatches": True}
    if args.compare:
        other = pathlib.Path(args.compare)
        assert {p.name for p in other.iterdir()} == {p.name for p in root.iterdir()}
        for name in [*checksums, "SHA256SUMS"]:
            assert (root / name).read_bytes() == (other / name).read_bytes(), name
        report["allReleaseFilesIdenticalAcrossTwoBuilds"] = True
    if args.record:
        pathlib.Path(args.record).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", newline="\n")
    print("PASS: six embedded runtimes, %d checksums, native sources, archive equality" % len(checksums) + (", reproducible rebuild" if args.compare else ""))


if __name__ == "__main__":
    main()
