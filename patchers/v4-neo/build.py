#!/usr/bin/env python3
"""Build fresh v4-neo firmware with the bundled Go bb10mt and offline checks."""
from __future__ import annotations

import argparse
from collections import deque
import errno
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import platform
import queue
import shutil
import shlex
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True

ERROR_NAMES = {2:'USAGE', 3:'INPUT_INVALID', 4:'OUTPUT_EXISTS', 5:'VALIDATION_FAILED',
               6:'DISK_SPACE', 7:'TOOL_FAILED', 8:'VERIFICATION_FAILED', 9:'IO_FAILED', 130:'INTERRUPTED'}


class BuildError(ValueError):
    def __init__(self, code, message, hint=''):
        super().__init__(message)
        self.code, self.hint = code, hint


def error_details(error):
    if isinstance(error, BuildError):
        return error
    if isinstance(error, KeyboardInterrupt):
        return BuildError(130, 'Build interrupted.', 'Private staging is removed; choose a new output and retry.')
    if isinstance(error, FileExistsError):
        return BuildError(4, str(error), 'Choose a NEW output path; existing data is preserved.')
    if isinstance(error, FileNotFoundError):
        return BuildError(3, str(error), 'Check that the input and required tool files exist.')
    if isinstance(error, OSError):
        code = 6 if error.errno == errno.ENOSPC or getattr(error, 'winerror', None) in (39, 112) else 9
        return BuildError(code, str(error), 'Free space or check filesystem access and permissions.')
    return BuildError(5, str(error), 'Check the source manifest and reported details; reassemble if the pinned source changed.')


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise BuildError(2, message, 'Run build.py --help or build.py fresh --help.')


def status(message):
    print(time.strftime('[%H:%M:%S] ') + message, flush=True)


def sha256(path, progress=False):
    h = hashlib.sha256()
    size, done, reported = Path(path).stat().st_size, 0, -10
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(4 << 20), b''):
            h.update(chunk)
            done += len(chunk)
            percent = done * 100 // size if size else 100
            if progress and size >= 256 << 20 and (percent >= reported + 10 or done == size):
                status('SHA256 %s: %d%% (%d / %d MiB)' % (Path(path).name, percent, done >> 20, size >> 20))
                reported = percent
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bounded(root, name):
    if not name or '\\' in name or name.startswith('/') or ':' in name or any(
            p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('unsafe snapshot path: ' + name)
    path = root
    for part in name.split('/'):
        path = path / part
        if path.is_symlink():
            raise ValueError('symlink snapshot path: ' + name)
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('missing snapshot file: ' + name)
    return path


def validate_snapshot(root):
    lock = json.loads((root / 'neo.lock.json').read_text(encoding='utf-8'))
    if lock.get('schemaVersion') != 1 or not lock.get('toolVersion', '').startswith('v0.7.'):
        raise ValueError('unsupported v4-neo snapshot')
    for name, expected in lock['files'].items():
        if sha256(bounded(root, name)) != expected:
            raise ValueError('snapshot SHA256 mismatch: ' + name)
    actual = set()
    for path in (root / 'foundation').rglob('*'):
        if path.is_symlink():
            raise ValueError('symlink in foundation: ' + str(path))
        if path.is_file() and '__pycache__' not in path.parts:
            actual.add(path.relative_to(root).as_posix())
    expected = {n for n in lock['files'] if n.startswith('foundation/')}
    if actual != expected:
        raise ValueError('unmanifested or missing foundation file')
    return lock


def host_target(system=None, machine=None):
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    arch = {'amd64': 'amd64', 'x86_64': 'amd64', 'arm64': 'arm64',
            'aarch64': 'arm64'}.get(machine)
    if system not in ('windows', 'linux', 'darwin') or arch is None:
        raise ValueError('supported hosts: Linux, Windows or macOS on x64/ARM64')
    return system + '-' + arch


def executable(root, lock):
    target = host_target()
    name = lock['executables'][target]
    tool = bounded(root, name)
    if sha256(tool) != lock['files'][name]:
        raise ValueError('tool SHA256 mismatch')
    if os.name != 'nt':
        tool.chmod(tool.stat().st_mode | 0o100)
    return tool


def run(command, cwd, log):
    log.write('\n> ' + ' '.join(map(str, command)) + '\n')
    log.flush()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    quiet = any('validate_patch_pack.py' in str(x) for x in command)
    started, heartbeat = time.monotonic(), time.monotonic()
    process = subprocess.Popen(list(map(str, command)), cwd=cwd, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding='utf-8', errors='replace', bufsize=1)
    updates, tail = queue.Queue(), deque(maxlen=6)
    def read_output():
        try:
            for line in process.stdout:
                updates.put(line)
        finally:
            updates.put(None)
    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    try:
        while True:
            try:
                line = updates.get(timeout=0.25)
            except queue.Empty:
                if time.monotonic() - heartbeat >= 5:
                    status('Working: %.0fs elapsed; %s' % (time.monotonic() - started, Path(str(command[0])).name))
                    heartbeat = time.monotonic()
                continue
            if line is None:
                break
            log.write(line)
            log.flush()
            tail.append(line.rstrip())
            if not quiet:
                status(line.rstrip())
            heartbeat = time.monotonic()
        code = process.wait()
    except BaseException:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    finally:
        reader.join(timeout=5)
        process.stdout.close()
    if code:
        category = 5 if quiet else 8 if any(str(x) in ('fsck',) or 'verify_real_build.py' in str(x) for x in command) else 7
        if code == 6:
            category = 6
        raise BuildError(category, 'Command failed (child exit %d): %s\n%s' % (code, command[0], '\n'.join(tail)),
                         'See the failure log for the command and full diagnostic output.')
    status('Completed in %.1fs: %s' % (time.monotonic() - started, Path(str(command[0])).name))


def validate_input(root, input_path):
    if not input_path.is_file():
        raise BuildError(3, 'Input is not a firmware file: ' + str(input_path), 'Choose the original .exe CAP autoloader.')
    try:
        verifier = load_module('neo_input_cap', root / 'scripts/verify_real_build.py')
        with input_path.open('rb') as source:
            if source.read(2) != b'MZ':
                raise ValueError('missing MZ executable header')
            _, spans = verifier.cap(source)
            if not spans:
                raise ValueError('missing CAP bundles')
    except (ValueError, OSError, AssertionError, struct.error) as error:
        raise BuildError(3, 'Invalid firmware CAP: %s (%s)' % (input_path, error),
                         'Use the original supported BB10 autoloader; raw UFS images use the package commands.') from error


def source_preflight(root, log):
    run([sys.executable, '-B', root / 'foundation/scripts/validate_patch_pack.py',
         '--root', root / 'foundation'], root, log)


def verify_metadata(image, script):
    expected = {}
    for line in script.splitlines():
        row = shlex.split(line, comments=True)
        if len(row) != 3 or row[0] not in ('chmod', 'chown'):
            continue
        command, value, path = row
        entry = expected.setdefault(path, {})
        if command == 'chmod':
            entry['mode'] = int(value, 8)
        else:
            entry['uid'], entry['gid'] = map(int, value.split(':'))
    for path, fields in expected.items():
        number, bad_names = image.resolve(path)
        if bad_names:
            raise ValueError('incorrect metadata pathname checksum: ' + path)
        node = image.inode(number)
        observed = dict(mode=struct.unpack_from('<H', node, 32)[0] & 0o7777,
                        uid=struct.unpack_from('<I', node, 8)[0],
                        gid=struct.unpack_from('<I', node, 12)[0])
        if any(observed[key] != value for key, value in fields.items()):
            raise ValueError('final script metadata mismatch: ' + path)
    return len(expected)


def verify_image(root, image):
    module = load_module('neo_qnx6', root / 'foundation/scripts/qnx6_longnames.py')
    with image.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        report = module.verify(data, module.targets(root / 'foundation'),
                               permissions=module.firmware_permissions(root / 'foundation'))
        if report['incorrectLongNames']:
            raise ValueError('final image has incorrect pathname checksums')
        filesystem = module.Image(data)
        metadata_paths = verify_metadata(filesystem, (root / 'foundation/patch.txt').read_text(encoding='utf-8'))
        sb = filesystem.sb
        value = 0
        for byte in data[sb + 8:sb + 512]:
            value ^= byte << 24
            for _ in range(8):
                value = ((value << 1) ^ (0x04c11db7 if value & 0x80000000 else 0)) & 0xffffffff
        if struct.unpack_from('<I', data, sb + 4)[0] != value:
            raise ValueError('superblock CRC mismatch')
    return dict(report, superblockCRCVerified=True, verifiedMetadataPaths=metadata_paths)


def verify_build(root, tool, input_path, result, log):
    images = list(result.glob('*.ufs'))
    if len(images) != 1:
        raise ValueError('expected exactly one output filesystem')
    image_report = verify_image(root, images[0])
    run([tool, 'qnx6', 'fsck', '-i', images[0]], root, log)
    report_path = result / 'container-verification.json'
    run([sys.executable, '-B', root / 'scripts/verify_real_build.py',
         '--input', input_path, '--build', result, '--report', report_path], root, log)
    container_report = json.loads(report_path.read_text(encoding='utf-8'))
    if not container_report['containerTrailerCRCVerified'] or not container_report['CAPStubAndOverlayPreserved']:
        raise ValueError('independent container checks failed')
    if container_report.get('embeddedUFSMatchesImage') is not True:
        raise ValueError('packed OS filesystem equality was not verified')
    return dict(image=image_report, container=container_report)


def preserve_failure(log_path, output):
    """Keep diagnostics without overwriting a previous failure record."""
    candidate = output.with_name(output.name + '.failed.log')
    try:
        with candidate.open('xb') as target, log_path.open('rb') as source:
            shutil.copyfileobj(source, target)
        return candidate
    except OSError:
        return None


def publish(root, source, output):
    adapter = load_module('neo_publication', root / 'scripts/export_weather_packages.py')
    adapter.publish_directory(source, output)


def fresh(root, input_path, output):
    started = time.monotonic()
    root = root.resolve()
    output = output.absolute()
    if os.path.lexists(output):
        raise BuildError(4, 'output already exists: ' + str(output),
                         'Choose a NEW subfolder, for example: ' + str(output / 'v4-neo-z30'))
    input_path = input_path.resolve(strict=True)
    validate_input(root, input_path)
    status('Phase 1/6: validating snapshot and host compatibility')
    lock = validate_snapshot(root)
    tool = executable(root, lock)
    status('v4-neo | Go bb10mt %s | %s' % (lock['toolVersion'], host_target()))
    output.parent.mkdir(parents=True, exist_ok=True)
    # Conservative minimum for ordinary full CAP inputs. Highly sparse firmware
    # can need more; the Go transaction safely fails and cleans up on ENOSPC.
    needed = input_path.stat().st_size * 3 + (256 << 20)
    if shutil.disk_usage(output.parent).free < needed:
        raise BuildError(6, 'Insufficient output-volume space: need at least %.1f GiB, available %.1f GiB' %
                         (needed / (1 << 30), shutil.disk_usage(output.parent).free / (1 << 30)),
                         'Free space or choose a new output folder on another drive.')
    with tempfile.TemporaryDirectory(prefix='.v4-neo-', dir=output.parent) as temporary:
        stage = Path(temporary)
        result, log_path = stage / 'result', stage / 'build.log'
        try:
            with log_path.open('w', encoding='utf-8') as log:
                status('Phase 2/6: checking foundation contracts and package catalog')
                source_preflight(root, log)
                run([tool, 'packages', 'validate', '--catalog', root / 'packages'], root, log)
                input_hash = sha256(input_path, progress=True)
                status('Phase 3/6: patching and packing with native Go bb10mt')
                run([tool, 'batch', '-i', input_path, '-s', 'patch.txt', '-o', result],
                    root / 'foundation', log)
                status('Phase 4/6: independent filesystem, payload, CAP and radio verification')
                try:
                    checks = verify_build(root, tool, input_path, result, log)
                except (ValueError, AssertionError, KeyError, struct.error) as error:
                    if isinstance(error, BuildError):
                        raise
                    raise BuildError(8, str(error), 'Do not use the output; inspect the failure log and source compatibility.') from error
                status('Phase 5/6: rechecking input integrity and recording output SHA256')
                if sha256(input_path, progress=True) != input_hash:
                    raise BuildError(5, 'input changed during build', 'Restore the original firmware and retry.')
                # Detect source changes during the transaction as well.
                validate_snapshot(root)
                write_json(result / 'neo-acceptance.json', dict(
                    schemaVersion=1, patcher='v4-neo', toolVersion=lock['toolVersion'],
                    sourceCommit=lock['sourceCommit'], inputSha256=input_hash,
                    snapshotSha256=sha256(root / 'neo.lock.json'), checks=checks,
                    handsetAcceptance='not tested'))
                shutil.copyfile(root / 'neo.lock.json', result / 'snapshot-used.json')
            shutil.copyfile(log_path, result / 'neo-build.log')
            sums = ''.join(sha256(p, progress=True) + '  ' + p.name + '\n'
                           for p in sorted(result.iterdir()) if p.is_file())
            (result / 'SHA256SUMS').write_text(sums, encoding='utf-8')
            status('Phase 6/6: publishing the verified output directory')
            publish(root, result, output)
        except BaseException as error:
            detail = error_details(error)
            if log_path.exists():
                with log_path.open('a', encoding='utf-8') as log:
                    log.write('\nERROR [%s:%d] %s\nHint: %s\n' % (ERROR_NAMES[detail.code], detail.code, detail, detail.hint))
            failed_log = preserve_failure(log_path, output) if log_path.exists() else None
            if failed_log:
                print('Failure log: ' + str(failed_log), file=sys.stderr)
            raise
    status('SUCCESS: verified firmware published in %.1fs: %s' % (time.monotonic() - started, output))


def main(argv=None):
    parser = Arguments(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('validate', help='check the pinned snapshot and source/catalog contracts')
    build = commands.add_parser('fresh', help='build from original stock firmware into a NEW directory')
    build.add_argument('-i', '--input', type=Path, required=True)
    build.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'fresh':
        fresh(ROOT, args.input, args.output)
    else:
        lock = validate_snapshot(ROOT)
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as log:
            try:
                source_preflight(ROOT, log)
                run([executable(ROOT, lock), 'packages', 'validate', '--catalog', ROOT / 'packages'], ROOT, log)
            finally:
                log.seek(0)
                print(log.read())
        print('v4-neo snapshot, source pack and catalog verified.')


def entry(argv=None):
    try:
        main(argv)
        return 0
    except (ValueError, OSError, KeyError, AssertionError, KeyboardInterrupt) as error:
        detail = error_details(error)
        print('ERROR [%s:%d] %s' % (ERROR_NAMES[detail.code], detail.code, detail), file=sys.stderr)
        if detail.hint:
            print('Hint: ' + detail.hint, file=sys.stderr)
        return detail.code


if __name__ == '__main__':
    sys.exit(entry())
