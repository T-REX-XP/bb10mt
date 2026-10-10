import hashlib
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('neo_build', ROOT / 'build.py')
neo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(neo)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='neo tests with spaces ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / 'original firmware.exe'
        self.input.write_bytes(b'original firmware bytes')
        self.output = self.root / 'new output'
        self.lock = dict(toolVersion='v0.7.0-go.3', sourceCommit='test')
        (self.root / 'neo.lock.json').write_text('{}')
        self.calls = []

    def runner(self, command, cwd, log):
        self.calls.append([str(x) for x in command])
        if 'batch' in command:
            target = Path(command[-1])
            # Real child process, deliberately quiet, including paths with spaces.
            subprocess.run([sys.executable, '-c',
                'from pathlib import Path; import sys; '
                'p=Path(sys.argv[1]); p.mkdir(); (p/"firmware_os.exe").write_bytes(b"checked CAP")',
                str(target)], check=True, stdout=log, stderr=log)

    def build_with(self, runner=None, verify=None, seal=None, publisher=None):
        def publish(root, source, output):
            # The production publisher's no-replace semantics are tested below.
            if os.path.lexists(output):
                raise FileExistsError(str(output))
            os.rename(source, output)
        with patch.object(neo, 'validate_snapshot', side_effect=seal or [self.lock, self.lock]), \
                patch.object(neo, 'executable', return_value=Path('bb10mt')), \
                patch.object(neo, 'source_preflight'), \
                patch.object(neo, 'validate_input'), \
                patch.object(neo, 'run', side_effect=runner or self.runner), \
                patch.object(neo, 'verify_build', side_effect=verify or (lambda *args: {'verified': True})), \
                patch.object(neo, 'publish', side_effect=publisher or publish):
            neo.fresh(self.root, self.input, self.output)

    def assert_clean_failure(self):
        self.assertFalse(self.output.exists())
        self.assertEqual(self.input.read_bytes(), b'original firmware bytes')
        self.assertEqual(list(self.root.glob('.v4-neo-*')), [])
        self.assertTrue(self.output.with_name(self.output.name + '.failed.log').exists())

    def test_quiet_success_publishes_reports_and_correct_output_hashes(self):
        self.build_with()
        self.assertEqual(self.input.read_bytes(), b'original firmware bytes')
        report = json.loads((self.output / 'neo-acceptance.json').read_text())
        self.assertEqual(report['handsetAcceptance'], 'not tested')
        self.assertEqual(report['inputSha256'], neo.sha256(self.input))
        self.assertTrue((self.output / 'neo-build.log').exists())
        for row in (self.output / 'SHA256SUMS').read_text().splitlines():
            checksum, name = row.split('  ', 1)
            self.assertEqual(checksum, neo.sha256(self.output / name))
        self.assertEqual(sum('batch' in c for c in self.calls), 1)
        self.assertFalse(any('pack' in c or 'repair-names' in c for c in self.calls))
        self.assertEqual(list(self.root.glob('.v4-neo-*')), [])

    def test_tool_failure_removes_partial_results_without_publication(self):
        def runner(command, cwd, log):
            self.runner(command, cwd, log)
            if 'batch' in command:
                log.write('deliberate tool error\n')
                log.flush()
                raise ValueError('tool failed')
        with self.assertRaisesRegex(ValueError, 'tool failed'):
            self.build_with(runner=runner)
        self.assert_clean_failure()
        self.assertIn('deliberate tool error', self.output.with_name(self.output.name + '.failed.log').read_text())

    def test_independent_verification_failure_blocks_publication(self):
        def reject(*args):
            raise ValueError('container CRC mismatch')
        with self.assertRaisesRegex(neo.BuildError, 'CRC mismatch') as failure:
            self.build_with(verify=reject)
        self.assertEqual(failure.exception.code, 8)
        self.assert_clean_failure()

    def test_input_change_during_build_blocks_publication(self):
        def runner(command, cwd, log):
            self.runner(command, cwd, log)
            if 'batch' in command:
                self.input.write_bytes(b'externally changed')
        with self.assertRaisesRegex(ValueError, 'input changed'):
            self.build_with(runner=runner)
        self.assertFalse(self.output.exists())

    def test_foundation_change_during_build_blocks_publication(self):
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.build_with(seal=[self.lock, ValueError('source changed')])
        self.assert_clean_failure()

    def test_existing_output_and_previous_log_are_preserved(self):
        self.output.mkdir()
        (self.output / 'keep').write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'output already exists'):
            neo.fresh(self.root, self.input, self.output)
        self.assertEqual((self.output / 'keep').read_bytes(), b'keep')
        log = self.output.with_name(self.output.name + '.failed.log')
        log.write_bytes(b'previous log')
        source = self.root / 'new.log'
        source.write_bytes(b'new log')
        self.assertIsNone(neo.preserve_failure(source, self.output))
        self.assertEqual(log.read_bytes(), b'previous log')

    def test_publication_race_does_not_replace_existing_directory(self):
        adapter_path = ROOT / 'scripts/export_weather_packages.py'
        if not adapter_path.exists():
            adapter_path = ROOT.parents[1] / 'scripts/export_weather_packages.py'
        adapter = neo.load_module('neo_adapter_test', adapter_path)
        def raced(root, source, output):
            output.mkdir()
            (output / 'other builder').write_bytes(b'keep')
            adapter.publish_directory(source, output)
        with self.assertRaises(OSError):
            self.build_with(publisher=raced)
        self.assertEqual((self.output / 'other builder').read_bytes(), b'keep')
        self.assertFalse((self.output / 'firmware_os.exe').exists())

    def test_real_process_nonzero_exit_fails(self):
        with io.StringIO() as log:
            # subprocess needs a real descriptor for redirected output.
            with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as stream:
                with self.assertRaisesRegex(ValueError, 'exit 7'):
                    neo.run([sys.executable, '-c', 'raise SystemExit(7)'], self.root, stream)

    def test_snapshot_hash_and_extra_foundation_files_are_rejected(self):
        source = self.root / 'foundation/payload'
        source.parent.mkdir()
        source.write_bytes(b'pinned')
        lock = dict(schemaVersion=1, toolVersion='v0.7.0-go.3',
                    files={'foundation/payload': neo.sha256(source)})
        neo.write_json(self.root / 'neo.lock.json', lock)
        neo.validate_snapshot(self.root)
        source.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            neo.validate_snapshot(self.root)
        source.write_bytes(b'pinned')
        (source.parent / 'unexpected').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'unmanifested'):
            neo.validate_snapshot(self.root)

    def test_snapshot_escape_and_platform_mapping(self):
        for name in ('../escape', '/escape', 'C:/escape', 'folder\\escape', 'a/./b'):
            with self.assertRaises(ValueError):
                neo.bounded(self.root, name)
        for system, machine, target in (
                ('Windows', 'AMD64', 'windows-amd64'), ('Linux', 'aarch64', 'linux-arm64'),
                ('Darwin', 'arm64', 'darwin-arm64'), ('Darwin', 'x86_64', 'darwin-amd64')):
            self.assertEqual(neo.host_target(system, machine), target)
        with self.assertRaises(ValueError):
            neo.host_target('Linux', 'i686')

    def test_final_permissions_use_last_assignment_and_check_all_exact_paths(self):
        node = bytearray(128)
        struct.pack_into('<H', node, 32, 0o100640)
        struct.pack_into('<II', node, 8, 379, 379)
        class Image:
            def resolve(self, path):
                return 1, []
            def inode(self, number):
                return node
        script = 'chmod 777 /weather\nchmod 640 /weather\nchown 379:379 /weather\n'
        self.assertEqual(neo.verify_metadata(Image(), script), 1)
        with self.assertRaisesRegex(ValueError, 'metadata mismatch'):
            neo.verify_metadata(Image(), script + 'chown 0:0 /weather\n')
        struct.pack_into('<H', node, 32, 0o100777)
        with self.assertRaisesRegex(ValueError, 'metadata mismatch'):
            neo.verify_metadata(Image(), script)

    def test_actionable_output_error_and_exit_code(self):
        self.output.mkdir()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = neo.entry(['fresh', '-i', str(self.input), '-o', str(self.output)])
        self.assertEqual(code, 4)
        self.assertIn('OUTPUT_EXISTS:4', stderr.getvalue())
        self.assertIn(str(self.output / 'v4-neo-z30'), stderr.getvalue())
        self.assertNotIn('Traceback', stderr.getvalue())

    def test_usage_and_missing_input_have_different_codes(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(neo.entry(['fresh']), 2)
            self.assertEqual(neo.entry(['fresh', '-i', str(self.root/'missing.exe'), '-o', str(self.output)]), 3)

    def test_disk_space_is_checked_before_starting_a_build(self):
        with patch.object(neo, 'validate_input'), patch.object(neo, 'validate_snapshot', return_value=self.lock), \
                patch.object(neo, 'executable', return_value=Path('bb10mt')), \
                patch.object(neo.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(100, 100, 0)):
            with self.assertRaises(neo.BuildError) as failure:
                neo.fresh(self.root, self.input, self.output)
        self.assertEqual(failure.exception.code, 6)
        self.assertFalse(self.output.exists())

    def test_child_progress_arrives_before_process_completion(self):
        observed = []
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as log, \
                patch.object(neo, 'status', side_effect=lambda message: observed.append((time.monotonic(), message))):
            neo.run([sys.executable, '-u', '-c', 'import time; print("first stage",flush=True); time.sleep(0.2); print("last stage",flush=True)'], self.root, log)
        first = next(at for at, text in observed if text == 'first stage')
        last = next(at for at, text in observed if text == 'last stage')
        self.assertGreaterEqual(last-first, 0.15)

    def test_powershell_preserves_exit_code_without_exception_stack(self):
        pwsh = shutil.which('pwsh')
        if not pwsh:
            self.skipTest('PowerShell unavailable')
        self.output.mkdir()
        result = subprocess.run([pwsh, '-NoProfile', '-File', str(ROOT/'build.ps1'),
            '-InputFirmware', str(self.input), '-OutputDirectory', str(self.output), '-Python', sys.executable],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 4, result.stdout)
        self.assertIn('OUTPUT_EXISTS:4', result.stdout)
        self.assertNotIn('Exception:', result.stdout)


if __name__ == '__main__':
    unittest.main()
