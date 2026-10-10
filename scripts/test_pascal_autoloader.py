"""Exercise the actual Pascal CLI's raw CAP scan and block-boundary overlap."""

import argparse
import pathlib
import struct
import subprocess
import tempfile
import unittest


MARKER = struct.pack("<III", *([0x97C5D59C] * 3))
PE_END = 1024


def stub(overlay):
    image = bytearray(PE_END)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 60, 128)
    image[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 132, 0x14C, 1, 0, 0, 0, 0, 0)
    image[152:160] = b".text\0\0\0"
    struct.pack_into("<II", image, 168, 512, 512)
    return bytes(image) + overlay


class PascalAutoloaderRegression(unittest.TestCase):
    binary = None
    work_root = None

    def create(self, cap_bytes, expected_stub):
        with tempfile.TemporaryDirectory(prefix="pascal-cap-test-", dir=self.work_root) as work:
            folder = pathlib.Path(work)
            cap = folder / "cap.exe"
            payload = folder / "payload.bin"
            output = folder / "autoloader.exe"
            cap.write_bytes(cap_bytes)
            payload_bytes = b"fixture-payload\0\x01\x02\x03"
            payload.write_bytes(payload_bytes)
            result = subprocess.run(
                [str(self.binary), "autoloader", "create", "-c", str(cap),
                 "-i", str(payload), "-o", str(output), "--versions", "2"],
                cwd=folder, capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            built = output.read_bytes()
            boundary = len(expected_stub)
            self.assertEqual(built[:boundary], expected_stub)
            self.assertEqual(built[boundary:boundary + 12], MARKER)
            self.assertEqual(struct.unpack_from("<Q", built, boundary + 92)[0], 1)
            self.assertEqual(struct.unpack_from("<Q", built, boundary + 100)[0], boundary + 132)
            self.assertEqual(built[boundary + 132:], payload_bytes)
            self.assertEqual(cap.read_bytes(), cap_bytes)

    def test_raw_stub_without_marker_finishes_and_preserves_overlay(self):
        # A 112-byte legitimate overlay ends with the 12-byte scanner remainder.
        cap = stub(bytes(range(112)))
        self.create(cap, cap)

    def test_marker_crossing_64k_scan_boundary_is_recognized(self):
        # Eight signature bytes are in the first scan block, four in the next.
        cap = stub(b"\xA5" * (65536 - 8))
        wrapped = cap + MARKER + b"\0" * 80 + struct.pack("<QQ", 1, len(cap) + 132)
        wrapped += b"\0" * (len(cap) + 132 - len(wrapped)) + b"old-payload"
        self.create(wrapped, cap)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--work-root", type=pathlib.Path, default=pathlib.Path("D:/tmp"))
    args = parser.parse_args()
    PascalAutoloaderRegression.binary = args.binary.resolve(strict=True)
    args.work_root.mkdir(parents=True, exist_ok=True)
    PascalAutoloaderRegression.work_root = args.work_root.resolve(strict=True)
    unittest.main(argv=[__file__], verbosity=2)
