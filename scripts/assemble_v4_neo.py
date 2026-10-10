#!/usr/bin/env python3
"""Assemble a PRIVATE v4-neo pack from maintained data and a verified Go release."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from export_weather_packages import export, publish_directory

TARGETS = ('windows-amd64', 'windows-arm64', 'linux-amd64', 'linux-arm64',
           'darwin-amd64', 'darwin-arm64')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for data in iter(lambda: source.read(4 << 20), b''):
            h.update(data)
    return h.hexdigest()


def copy_tree(source, output):
    if source.is_symlink():
        raise ValueError('symlink build input: ' + str(source))
    if source.is_dir():
        output.mkdir(parents=True, exist_ok=True)
        for child in sorted(source.iterdir()):
            if child.name != '__pycache__':
                copy_tree(child, output / child.name)
    elif source.is_file():
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output)
    else:
        raise ValueError('nonregular build input: ' + str(source))


def assemble(pack, release, output):
    pack, release, output = pack.resolve(), release.resolve(), output.absolute()
    version=json.loads((release/'sbom.cdx.json').read_text(encoding='utf-8'))['metadata']['component']['version']
    if not version.startswith('v0.7.') or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-+' for c in version):
        raise ValueError('unsupported Go release version: '+version)
    if os.path.lexists(output):
        raise ValueError('output already exists')
    if output.is_relative_to(pack) or output.is_relative_to(release):
        raise ValueError('output must be outside the input directories')
    subprocess.run([sys.executable, '-B', str(pack / 'scripts/validate_patch_pack.py'),
                    '--root', str(pack)], check=True)
    sums = {}
    for line in (release / 'SHA256SUMS').read_text(encoding='utf-8').splitlines():
        checksum, name = line.split('  ', 1)
        if name in sums or Path(name).name != name or '\\' in name:
            raise ValueError('invalid release checksum inventory')
        sums[name] = checksum

    def release_copy(name, target):
        source = release / name
        if source.is_symlink() or digest(source) != sums[name]:
            raise ValueError('release SHA256 mismatch: ' + name)
        copy_tree(source, target)

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.v4-neo-assemble-', dir=output.parent))
    try:
        # No general pack copy: docs/ssh.pub and handset access scripts are not
        # delivery inputs. The existing firmware SSH host key remains local.
        for name in ('patch.txt', 'patchdata', 'certs', 'patched_apps', 'patched_services'):
            copy_tree(pack / name, stage / 'foundation' / name)
        validators = ('validate_patch_pack.py', 'verify_weather_pack.py',
                      'patch_weatherlib_urls.py', 'qnx6_longnames.py',
                      'ukrainian_localization.py', 'patch_ukrainian_settings.py')
        for name in validators:
            copy_tree(pack / 'scripts' / name, stage / 'foundation/scripts' / name)
        for name in ('verify_firmware.py', 'stage_firmware.py', 'patch_ui.py', 'pin_patch.py',
                     'pin_provider.manifest.json', 'pim_account.manifest.json', 'pim_account.cpp'):
            copy_tree(pack / 'scripts/bbm' / name, stage / 'foundation/scripts/bbm' / name)
        for name in ('test_patch_pack.py', 'test_qnx6_longnames.py'):
            copy_tree(pack / 'tests' / name, stage / 'foundation/tests' / name)
        copy_tree(ROOT / 'patchers/v4-neo', stage)
        for name in ('export_weather_packages.py', 'verify_real_build.py', 'test_verify_real_build.py'):
            copy_tree(ROOT / 'scripts' / name, stage / 'scripts' / name)
        copy_tree(ROOT / 'docs/PACKAGES.md', stage / 'docs/PACKAGES.md')
        copy_tree(ROOT / 'docs/ERROR_CODES.md', stage / 'docs/ERROR_CODES.md')
        executables = {}
        for target in TARGETS:
            suffix = '.exe' if target.startswith('windows') else ''
            name = 'bb10mt-' + version + '-' + target + suffix
            relative = 'bin/' + target + '/bb10mt' + suffix
            release_copy(name, stage / relative)
            if not target.startswith('windows'):
                (stage / relative).chmod(0o755)
            executables[target] = relative
        for name in ('DEPENDENCIES.md', 'runtime.lock.json', 'sbom.cdx.json', 'runtime-sources.zip', 'build-version.json'):
            release_copy(name, stage / 'toolchain' / name)
        # Take notices/licenses from the verified release archive, not an
        # unrelated working checkout. Native-library sources include licenses.
        archive = 'bb10mt-' + version + '-windows-amd64.zip'
        if digest(release / archive) != sums[archive]:
            raise ValueError('release archive SHA256 mismatch')
        with zipfile.ZipFile(release / archive) as files:
            for info in files.infolist():
                if info.filename in ('LICENSE', 'THIRD_PARTY_NOTICES.md') or info.filename.startswith('third_party/licenses/'):
                    relative = Path(info.filename)
                    if relative.is_absolute() or '..' in relative.parts or '\\' in info.filename or info.is_dir():
                        raise ValueError('unsafe release license path')
                    target = stage / 'toolchain' / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(files.read(info))
        export(stage / 'foundation', stage / 'packages')
        source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        files = {p.relative_to(stage).as_posix(): digest(p) for p in sorted(stage.rglob('*'))
                 if p.is_file() and not p.is_relative_to(stage / 'packages')}
        boot = 'patchdata/apps/sys.android.gYABgKAOw1czN6neiAT72SGO.ns/native/system/xbin/btool'
        lock = dict(schemaVersion=1, patcher='v4-neo', toolVersion=version,
                    sourceCommit=source_commit, sourcePack=str(pack),
                    bootHookSha256=digest(stage / 'foundation' / boot),
                    canonicalCertificateSha256=digest(stage / 'foundation/certs/isrgrootx1.pem'),
                    executables=executables, files=files,
                    privateLocalPack=True, handsetLoginKeyIncluded=False,
                    firmwareSSHHostKeyIncluded=True)
        (stage / 'neo.lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')
        subprocess.run([sys.executable, '-B', str(stage / 'build.py'), 'validate'], check=True)
        publish_directory(stage, output)
        return dict(patcher=str(output), toolVersion=version, executables=len(executables),
                    foundationBootUnchanged=digest(pack / boot) == lock['bootHookSha256'],
                    canonicalCertificateUnchanged=digest(pack / 'certs/isrgrootx1.pem') == lock['canonicalCertificateSha256'],
                    privateLocalPack=True, handsetAcceptance='not tested')
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pack', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(assemble(args.pack, args.release, args.output), indent=2))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
