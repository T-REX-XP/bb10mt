"""Independent streaming check of a native batch build; no Go code is reused."""
import argparse
import contextlib
import hashlib
import json
import pathlib
import struct
import zlib

if not __debug__:
    raise RuntimeError("verification requires Python without -O/-OO")


def read(f, offset, size):
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError("truncated input")
    return data


def u32(b, off=0):
    return struct.unpack_from("<I", b, off)[0]


def cap(f):
    pe = u32(read(f, 0x3C, 4))
    header = read(f, pe, 24)
    assert header[:4] == b"PE\0\0"
    count = struct.unpack_from("<H", header, 6)[0]
    optional = struct.unpack_from("<H", header, 20)[0]
    end = 0
    for i in range(count):
        section = read(f, pe + 24 + optional + 40 * i, 40)
        end = max(end, u32(section, 20) + u32(section, 16))
    tail = read(f, end, min(64 << 20, f.seek(0, 2) - end))
    sig = struct.pack("<III", *([0x97C5D59C] * 3))
    index = tail.index(sig)
    base = end + index
    size = f.seek(0, 2)
    for version, count_at in [(1, base + 12), (2, base + 92)]:
        n = struct.unpack("<Q", read(f, count_at, 8))[0]
        if not 1 <= n <= 10:
            continue
        offsets = struct.unpack("<" + "Q" * n, read(f, count_at + 8, n * 8))
        assert count_at + 8 + n * 8 <= offsets[0]
        assert list(offsets) == sorted(set(offsets)) and offsets[-1] < size
        return base, list(zip(offsets, list(offsets[1:]) + [size]))
    raise ValueError("no CAP table")


def digest_range(f, start, size):
    h = hashlib.sha256()
    while size:
        b = read(f, start, min(size, 4 << 20))
        h.update(b)
        start += len(b)
        size -= len(b)
    return h.hexdigest()


def qcfm(f, base, end):
    main = read(f, base, 32)
    assert main[:4] == b"mfcq" and u32(main, 12) == 0
    v2 = base + u32(main, 24)
    hdr = read(f, v2, 28)
    assert hdr[:4] == b"mfcq" and u32(hdr, 8) == 0x20000
    control = v2 + 28
    payload = base + u32(main, 16)
    chunks = []
    for _ in range(u32(hdr, 16)):
        c = read(f, control, 44)
        assert c[:4] == b"pfcq"
        runs = []
        for j in range(u32(c, 20)):
            r = read(f, control + u32(c, 16) + 16 * j, 16)
            assert r[:4] == b"rrcq"
            runs.append((u32(r, 8), u32(r, 12)))
        chunks.append((u32(c, 12), u32(c, 40), payload, runs))
        payload += sum(n for _, n in runs) * u32(c, 40)
        control += u32(c, 8)
    assert payload + 560 == end
    crc, offset = 0, base
    while offset < end - 4:
        data = read(f, offset, min(4 << 20, end - 4 - offset))
        crc = zlib.crc32(data, crc)
        offset += len(data)
    assert crc == u32(read(f, end - 4, 4)), "container trailer CRC mismatch"
    return chunks


def logical_digest(f, chunk):
    _, block, pos, runs = chunk
    h, logical = hashlib.sha256(), 0
    fill = b'\xff' * (4 << 20)
    for first, count in runs:
        missing = first * block - logical
        assert missing >= 0
        while missing:
            n = min(missing, len(fill))
            h.update(fill[:n])
            missing -= n
        size = count * block
        while size:
            data = read(f, pos, min(size, 4 << 20))
            h.update(data)
            pos += len(data)
            size -= len(data)
        logical = (first + count) * block
    return logical, h.hexdigest()


def classify_sources(f, sources):
    os_chunks, radio_source = None, None
    for span in sources:
        chunks = qcfm(f, *span)
        types = [c[0] for c in chunks]
        if 5 in types:
            if os_chunks is not None or types.count(5) != 1 or 12 in types:
                raise ValueError('ambiguous source OS bundle')
            os_chunks = chunks
        elif 12 in types:
            if radio_source is not None:
                raise ValueError('ambiguous source radio bundle')
            radio_source = span
        else:
            raise ValueError('unclassified source bundle')
    if os_chunks is None:
        raise ValueError('missing source OS bundle')
    return os_chunks, radio_source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=pathlib.Path, required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    os_path, = args.build.glob("*_os.exe")
    radio_paths = list(args.build.glob("*_radio.exe"))
    if len(radio_paths) > 1:
        raise ValueError("ambiguous radio output")
    radio_path = radio_paths[0] if radio_paths else None
    ufs, = args.build.glob("*.ufs")
    with contextlib.ExitStack() as stack:
        original = stack.enter_context(args.input.open("rb"))
        output = stack.enter_context(os_path.open("rb"))
        stub, sources = cap(original)
        output_stub, files = cap(output)
        assert stub == output_stub
        stub_hash = digest_range(original, 0, stub)
        assert stub_hash == digest_range(output, 0, stub)
        assert len(files) == 1 and len(sources) in (1, 2)
        source_chunks, source_radio = classify_sources(original, sources)
        radio_hash = None
        if source_radio is not None:
            if radio_path is None:
                raise ValueError("missing radio output")
            radio = stack.enter_context(radio_path.open("rb"))
            radio_stub, radios = cap(radio)
            assert radio_stub == stub and len(radios) == 1
            assert stub_hash == digest_range(radio, 0, stub)
            a, b = source_radio
            c, d = radios[0]
            radio_hash = digest_range(original, a, b - a)
            assert b - a == d - c and radio_hash == digest_range(radio, c, d - c)
            qcfm(radio, c, d)
        elif radio_path is not None:
            raise ValueError("unexpected radio output")
        chunks = qcfm(output, *files[0])
        assert [c[0] for c in chunks] == [c[0] for c in source_chunks], 'partition order/types changed'
        preserved = []
        for before, after in zip(source_chunks, chunks):
            if before[0] != 5:
                assert logical_digest(original, before) == logical_digest(output, after), 'non-UFS partition changed'
                preserved.append(before[0])
        logical, embedded_hash = logical_digest(output, next(c for c in chunks if c[0] == 5))
        with ufs.open("rb") as image:
            image_hash = digest_range(image, 0, ufs.stat().st_size)
        assert logical == ufs.stat().st_size and embedded_hash == image_hash, (
            'packed OS filesystem differs from the verified loose UFS; '
            'rebuild the autoloader after any filename-checksum repair')
    report = {"osAutoloader": os_path.name, "embeddedUFSSHA256": image_hash,
              "embeddedUFSBytes": logical, "embeddedUFSMatchesImage": True,
              "partitions": len(chunks),
              "containerTrailerCRCVerified": True, "CAPStubAndOverlayPreserved": True,
              "nonUFSPartitionsPreserved": preserved,
              "radioUnchangedSHA256": radio_hash, "independentVerifier": "Python standard library",
              "deviceAcceptance": "not tested"}
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
