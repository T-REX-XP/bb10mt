"""Small independent CAP fixtures exercise the final publication gate."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

spec = importlib.util.spec_from_file_location('verify', Path(__file__).with_name('verify_real_build.py'))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def u32(data, offset, value):
    struct.pack_into('<I', data, offset, value)


def container(parts):
    control = bytearray()
    for kind, payload in parts:
        row = bytearray(60)
        row[:4] = b'pfcq'
        for offset, value in ((8, 60), (12, kind), (16, 44), (20, 1), (40, 1)):
            u32(row, offset, value)
        row[44:48] = b'rrcq'
        u32(row, 56, len(payload))
        control.extend(row)
    main, header = bytearray(32), bytearray(28)
    main[:4] = header[:4] = b'mfcq'
    u32(main, 16, 60 + len(control))
    u32(main, 24, 32)
    u32(header, 8, 0x20000)
    u32(header, 16, len(parts))
    result = main + header + control + b''.join(p for _, p in parts) + bytes(556)
    return result + struct.pack('<I', zlib.crc32(result))


def cap(bundles):
    stub = bytearray(512)
    u32(stub, 0x3c, 64)
    stub[64:68] = b'PE\0\0'
    struct.pack_into('<H', stub, 70, 1)
    u32(stub, 88 + 16, 256)
    u32(stub, 88 + 20, 256)
    table = struct.pack('<IIIQ', *([0x97c5d59c] * 3), len(bundles))
    cursor, offsets = 512 + len(table) + len(bundles) * 8, []
    for bundle in bundles:
        offsets.append(cursor)
        cursor += len(bundle)
    return stub + table + struct.pack('<' + 'Q' * len(offsets), *offsets) + b''.join(bundles)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source.exe'
        self.build = self.root / 'output'
        self.build.mkdir()
        self.report = self.root / 'report.json'
        self.original = [(2, b'unchanged boot'), (5, b'original UFS')]
        self.changed = [(2, b'unchanged boot'), (5, b'new UFS')]
        self.radio = container([(12, b'unchanged radio')])

    def prepare(self, radio=True, radio_first=False):
        bundles = [container(self.original)]
        if radio:
            bundles.insert(0 if radio_first else 1, self.radio)
            (self.build / 'firmware_radio.exe').write_bytes(cap([self.radio]))
        self.source.write_bytes(cap(bundles))
        (self.build / 'firmware_os.exe').write_bytes(cap([container(self.changed)]))
        (self.build / 'firmware.ufs').write_bytes(b'new UFS')

    def run_verifier(self):
        with patch.object(sys, 'argv', ['verify', '--input', str(self.source),
                '--build', str(self.build), '--report', str(self.report)]), \
                contextlib.redirect_stdout(io.StringIO()):
            verify.main()

    def test_os_radio_and_radio_first_sources(self):
        for first in (False, True):
            self.prepare(radio_first=first)
            self.run_verifier()
            report = json.loads(self.report.read_text())
            self.assertEqual(report['nonUFSPartitionsPreserved'], [2])
            self.assertIsNotNone(report['radioUnchangedSHA256'])

    def test_os_only_source_does_not_require_radio(self):
        self.prepare(radio=False)
        self.run_verifier()
        self.assertIsNone(json.loads(self.report.read_text())['radioUnchangedSHA256'])

    def test_corrupt_container_crc_rejected(self):
        self.prepare()
        target = self.build / 'firmware_os.exe'
        data = bytearray(target.read_bytes())
        data[-1] ^= 1
        target.write_bytes(data)
        with self.assertRaisesRegex(AssertionError, 'CRC'):
            self.run_verifier()

    def test_repacked_but_changed_nonufs_partition_rejected(self):
        self.prepare()
        self.changed[0] = (2, b'wrong boot')
        (self.build / 'firmware_os.exe').write_bytes(cap([container(self.changed)]))
        with self.assertRaisesRegex(AssertionError, 'non-UFS partition changed'):
            self.run_verifier()

    def test_repacked_but_different_embedded_ufs_rejected(self):
        self.prepare()
        (self.build / 'firmware.ufs').write_bytes(b'not the embedded UFS')
        with self.assertRaises(AssertionError):
            self.run_verifier()

    def test_repacked_but_changed_radio_rejected(self):
        self.prepare()
        (self.build / 'firmware_radio.exe').write_bytes(cap([container([(12, b'changed radio')])]))
        with self.assertRaises(AssertionError):
            self.run_verifier()


if __name__ == '__main__':
    unittest.main()
