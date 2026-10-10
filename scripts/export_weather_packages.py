#!/usr/bin/env python3
"""Export the maintained Weather/trust payloads as local bb10mt packages.

This migration adapter is build-time tooling. The Go binary consumes exported
JSON/payloads without Python, shell hooks, a compiler or the original pack.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def read_source(root, relative):
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts) or relative.startswith("/") or "\\" in relative:
        raise ValueError("unsafe pack source: " + relative)
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("symlink pack source: " + relative)
    if not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError("nonregular pack source: " + relative)
    return path.read_bytes()


def publish_directory(source, target):
    if os.name == "nt":
        os.rename(source, target)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        rename = libc.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = rename(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    elif sys.platform == "darwin":
        rename = libc.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = rename(os.fsencode(source), os.fsencode(target), 4)
    else:
        raise ValueError("atomic catalog publication unsupported on this platform")
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(target))


def export(root, output):
    root = Path(root).resolve()
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists")
    # The existing pack preflight checks the allowed ELF instruction/URL changes,
    # typed PPS values, boot TLS pin, legacy script ordering and public PEM.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "scripts"))
    spec = importlib.util.spec_from_file_location("weather_pack_preflight", root / "scripts/verify_weather_pack.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    preflight = module.verify(root, check_backend=False)
    weather = json.loads(read_source(root, "patched_services/weather.manifest.json"))
    trust = json.loads(read_source(root, "certs/manifest.json"))
    boot_manifest = json.loads(read_source(root, "patched_services/bbid-autostart.json"))
    boot_path = module.BOOT
    boot_hash = digest(read_source(root, boot_path))
    if boot_manifest["files"][boot_path] != boot_hash:
        raise ValueError("boot foundation hash differs from maintained manifest")
    cert_source = "certs/isrgrootx1.pem"
    cert = read_source(root, cert_source)
    cert_hash = digest(cert)
    if trust.get("formatVersion") != 1 or trust["files"] != {cert_source: cert_hash} or cert_hash != weather["certificateSHA256"]:
        raise ValueError("shared certificate manifest differs")
    if len(trust["copies"]) != 3 or set(trust["copies"].values()) != {cert_source} or b"PRIVATE KEY" in cert:
        raise ValueError("expected three destinations and one public certificate source")

    foundation_id, trust_id, weather_id = "foundation.existing-boot", "trust.isrg-root-x1", "app.sys-weather"
    foundation_version = "1.0.0-" + boot_hash[:12]
    trust_version = "1.0.0-" + cert_hash[:12]
    weather_version = weather["contractVersion"] + "-" + digest(json.dumps(weather, sort_keys=True).encode())[:12]
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", weather_version):
        raise ValueError("unsupported Weather contract version")
    foundation = dict(schemaVersion=1, id=foundation_id, version=foundation_version, kind="foundation",
                      provides=["boot.geoweather-tls-pin/v1"],
                      assertions=[dict(path="/" + boot_path.removeprefix("patchdata/"), sha256=boot_hash)])
    ca = dict(schemaVersion=1, id=trust_id, version=trust_version, kind="shared", owns=[], operations=[])
    app = dict(schemaVersion=1, id=weather_id, version=weather_version, kind="app", app="sys.weather",
               requires=[dict(id=foundation_id, version=foundation_version), dict(id=trust_id, version=trust_version)],
               requiresCapabilities=["boot.geoweather-tls-pin/v1"], owns=[], operations=[])
    stage = Path(tempfile.mkdtemp(prefix=".bb10mt-weather-", dir=output.parent))
    try:
        for package in (foundation, ca, app):
            (stage / package["id"]).mkdir()
        (stage / trust_id / "isrgrootx1.pem").write_bytes(cert)
        for destination in sorted(trust["copies"]):
            if destination.startswith("/apps/sys.appworld."):
                destination = "app:/sys.appworld/" + destination.split("/", 3)[3]
            elif not destination.startswith("/var/"):
                raise ValueError("unsupported trust destination")
            ca["owns"].append(destination)
            ca["operations"].append(dict(type="put-file", path=destination, source="isrgrootx1.pem",
                                         sha256=cert_hash, mode="0644", uid=0, gid=0, allowAbsent=True))
        for source, expected in sorted(weather["files"].items()):
            data = read_source(root, source)
            if digest(data) != expected:
                raise ValueError("Weather source changed during export: " + source)
            name = Path(source).name
            (stage / weather_id / name).write_bytes(data)
            if source.startswith(module.APP_LIB):
                destination = "app:/sys.weather/native/lib/" + name
                originals = [module.patcher.STOCK_SHA256[name]]
            elif source.startswith(module.GEO_LIB):
                destination = "/var/weather-libs/" + name
                originals = []
            elif source == module.METARS:
                destination = "/" + source.removeprefix("patchdata/")
                originals = []
            else:
                raise ValueError("unexpected Weather source")
            app["owns"].append(destination)
            operation = dict(type="put-file", path=destination, source=name, sha256=expected,
                             mode="0640" if name == "metars" else "0755", uid=379 if name == "metars" else 0,
                             gid=379 if name == "metars" else 0, allowAbsent=True)
            if originals:
                operation["originalSha256"] = originals
            app["operations"].append(operation)
        for package in (foundation, ca, app):
            write_json(stage / package["id"] / "manifest.json", package)
        write_json(stage / "weather.json", dict(schemaVersion=1, packages=[
            dict(id=foundation_id, version=foundation_version), dict(id=weather_id, version=weather_version)]))
        write_json(stage / "export-report.json", dict(schemaVersion=1, preflight=preflight,
                   foundationSha256=boot_hash, publicCertificateSources=1, payloadFiles=6,
                   rootInstallation=False, privateKeysExported=False))
        publish_directory(stage, output)
        return dict(catalog=str(output), packages=3, operations=8, publicCertificateSources=1,
                    profile=str(output / "weather.json"))
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--output", "-o", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.pack, args.output), indent=2))
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
