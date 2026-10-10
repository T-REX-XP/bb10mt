"""Fetch SHA256-pinned redistributable runtime binaries and matching sources.

No packages are installed. Requires Python 3 and tar (Windows) or 7zz/7z for
the official Windows archive. Output contains per-target payload inputs.
"""
import argparse
import concurrent.futures
import hashlib
import io
import json
import pathlib
import re
import shutil
import subprocess
import struct
import tarfile
import tempfile
import urllib.request


def fetch(asset, cache):
    path = cache / (asset["sha256"][:16] + "-" + asset["filename"])
    if path.exists():
        with path.open("rb") as existing:
            if hashlib.file_digest(existing, "sha256").hexdigest() == asset["sha256"]:
                return path
    headers = {"User-Agent": "bb10mt-runtime-vendor"}
    if asset["url"].startswith("https://ghcr.io/"):
        token_url = "https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/libusb:pull"
        with urllib.request.urlopen(token_url, timeout=60) as response:
            headers["Authorization"] = "Bearer " + json.load(response)["token"]
    temporary = path.with_suffix(path.suffix + ".download")
    digest = hashlib.sha256()
    try:
        request = urllib.request.Request(asset["url"], headers=headers)
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
            while block := response.read(1 << 20):
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != asset["sha256"]:
            raise ValueError("SHA256 mismatch: " + asset["filename"])
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    print("Verified", asset["filename"], flush=True)
    return path


def deb_tar(path):
    data = path.read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError("invalid deb archive")
    at = 8
    while at + 60 <= len(data):
        header = data[at:at + 60]
        if header[58:] != b"`\n":
            raise ValueError("invalid ar header")
        size = int(header[48:58])
        name = header[:16].decode().strip().rstrip("/")
        at += 60
        if at + size > len(data):
            raise ValueError("truncated deb member")
        if name.startswith("data.tar"):
            return tarfile.open(fileobj=io.BytesIO(data[at:at + size]), mode="r:*")
        at += size + size % 2
    raise ValueError("deb data archive missing")


def normalized(name):
    return name.removeprefix("./").lstrip("/")


def member_bytes(archive, member, depth=0):
    if depth > 8:
        raise ValueError("archive symlink cycle")
    if member.isfile():
        return archive.extractfile(member).read()
    if member.issym() or member.islnk():
        target = pathlib.PurePosixPath(member.linkname)
        if not target.is_absolute() and member.issym():
            target = pathlib.PurePosixPath(normalized(member.name)).parent / target
        parts = []
        for part in target.parts:
            if part in ("/", "."):
                continue
            if part == "..":
                if not parts:
                    raise ValueError("archive link escapes root")
                parts.pop()
            else:
                parts.append(part)
        name = "/".join(parts)
        linked = next((m for m in archive.getmembers() if normalized(m.name) == name), None)
        if linked is None:
            raise ValueError("archive link target missing: " + name)
        return member_bytes(archive, linked, depth + 1)
    raise ValueError("archive member is not a file")


def write(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != data:
        raise ValueError("conflicting runtime file: " + str(path))
    path.write_bytes(data)


def seven_zip(path, member):
    seven = shutil.which("7zz") or shutil.which("7z")
    if not seven and pathlib.Path("C:/Program Files/7-Zip/7z.exe").is_file():
        seven = "C:/Program Files/7-Zip/7z.exe"
    command = [seven, "x", "-so", str(path), member] if seven else ["tar", "-xOf", str(path), member]
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout


def burn_runtime(source, row, root):
    """Read pinned MS redistributable cabinets without running its installer."""
    data, cabinets, start = source.read_bytes(), [], 0
    while (at := data.find(b"MSCF\0\0\0\0", start)) >= 0:
        size = struct.unpack_from("<I", data, at + 8)[0]
        if size < 36 or at + size > len(data):
            raise ValueError("invalid redistributable cabinet")
        cabinets.append(data[at:at + size])
        start = at + size
    if len(cabinets) != 2:
        raise ValueError("unexpected redistributable layout")
    with tempfile.TemporaryDirectory(prefix="bb10mt-vcrt-") as tmp:
        cabinet = pathlib.Path(tmp) / "bundle.cab"
        cabinet.write_bytes(cabinets[0])
        write(root, "licenses/Microsoft-VC-Runtime.rtf", seven_zip(cabinet, "u4"))
        cabinet.write_bytes(cabinets[1])
        inner = pathlib.Path(tmp) / "runtime.cab"
        inner.write_bytes(seven_zip(cabinet, row["cabinet"]))
        write(root, "lib/vcruntime140.dll", seven_zip(inner, row["member"]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default="third_party/runtime.lock.json")
    parser.add_argument("--cache", default="out/runtime-downloads")
    parser.add_argument("--output", default="out/runtimes")
    args = parser.parse_args()
    lock = json.loads(pathlib.Path(args.lock).read_text())
    if lock["schema"] != 1:
        raise ValueError("unsupported runtime lock")
    cache, output = pathlib.Path(args.cache), pathlib.Path(args.output)
    cache.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError("choose a new runtime output directory")
    assets = lock["assets"] + lock["sources"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        paths = dict(zip((a["id"] for a in assets), pool.map(lambda a: fetch(a, cache), assets)))
    output.mkdir(parents=True)
    by_id = {a["id"]: a for a in lock["assets"]}
    source_licenses = {}
    for asset in lock["sources"]:
        source = paths[asset["id"]]
        write(output / "sources", asset["filename"], source.read_bytes())
        if asset["filename"].endswith((".asc", ".dsc")):
            continue
        with tarfile.open(source) as archive:
            for member in archive.getmembers():
                name = pathlib.PurePosixPath(member.name)
                if member.isfile() and len(name.parts) <= 2 and name.name in {"COPYING", "COPYING.LIB", "COPYING3", "COPYING.RUNTIME", "GPL2.txt", "LGPL2.txt", "LICENSE", "LICENSE.LGPL2.1"}:
                    source_licenses[asset["package"] + "-" + name.name] = member_bytes(archive, member)
                if member.isfile() and str(name) == "debian/copyright":
                    source_licenses[asset["package"] + ".source-copyright"] = member_bytes(archive, member)
                if asset["package"] == "gcc-14" and member.isfile() and name.name.startswith("gcc-") and name.name.endswith(".tar.xz"):
                    with tarfile.open(fileobj=io.BytesIO(member_bytes(archive, member))) as nested:
                        for license in nested.getmembers():
                            leaf = pathlib.PurePosixPath(license.name)
                            if license.isfile() and len(leaf.parts) <= 2 and leaf.name in {"COPYING", "COPYING.LIB", "COPYING3", "COPYING.RUNTIME"}:
                                source_licenses["gcc-14-" + leaf.name] = member_bytes(nested, license)
    for target, rows in lock["targets"].items():
        root = output / target
        packages = []
        for row in rows:
            key = row if isinstance(row, str) else row["asset"]
            asset, source = by_id[key], paths[key]
            packages.append({k: asset[k] for k in ("package", "version", "source", "url", "sha256")})
            if asset["format"] == "burn":
                burn_runtime(source, row, root)
                continue
            if asset["format"] == "7z":
                write(root, row["name"], seven_zip(source, row["member"]))
                continue
            archive = deb_tar(source) if asset["format"] == "deb" else tarfile.open(source)
            with archive:
                for member in archive.getmembers():
                    name = normalized(member.name)
                    basename = pathlib.PurePosixPath(name).name
                    if name.endswith("/copyright") and name.startswith("usr/share/doc/") and member.isfile():
                        write(root, "licenses/" + asset["package"] + ".copyright", member_bytes(archive, member))
                    if target.startswith("linux-"):
                        if name.endswith("/fusermount3") and member.isfile():
                            write(root, "lib/fusermount3.real", member_bytes(archive, member))
                        elif "/gconv/" not in name and re.fullmatch(r"(?:lib[^/]+\.so(?:\.[\w.]+)*|ld-linux[^/]+\.so(?:\.\d+)*)", basename) and not member.isdir():
                            write(root, "lib/" + basename, member_bytes(archive, member))
                    elif basename == "libusb-1.0.0.dylib":
                        write(root, "lib/libusb-1.0.dylib", member_bytes(archive, member))
                    elif name.endswith("/.brew/libusb.rb") and member.isfile():
                        write(root, "build-info/homebrew-libusb.rb", member_bytes(archive, member))
        for name, data in source_licenses.items():
            write(root, "licenses/" + name, data)
        write(root, "native-packages.json", (json.dumps(packages, indent=2, sort_keys=True) + "\n").encode())
    write(output, "runtime.lock.json", pathlib.Path(args.lock).read_bytes())
    print("Runtime payloads prepared in", output)


if __name__ == "__main__":
    main()
