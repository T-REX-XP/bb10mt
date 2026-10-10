# Go migration: review, design and implementation plan

Baseline: upstream `31e5e372d064942ffea92665947a1b3cda488413`, reviewed 2026-10-10.
Implementation is performed directly by the primary agent. The Pascal sources
remain a format reference and rollback path until the compatibility gates pass.

## Review findings

1. `umisc.pas:qnx6_lfile_checksum`: the unbracketed loop repeatedly reads the
   first byte; `Inc(p)` runs only once after the loop. Its rotate/add expression
   also differs from the BB10 kernel's shift/add/XOR recurrence. The retained Z30
   firmware audit and independent known-name vectors demonstrate bad checksums
   on otherwise correct payloads. The old fsck does not detect them.
2. `qcfm.pas:BuildHeadersAndMap`: the V2 header budget assumes one run record per
   partition. Fragmented inputs can grow metadata past the declared data offset.
   V1/hybrid headers use fixed 64 KiB budgets with the same overflow risk.
3. QCFM sparse reconstruction subtracts the first run from all offsets, losing
   leading erased blocks. Pure-V2 list output does not preserve that offset.
   The format stores runs, not original byte lengths; omitted trailing erased
   blocks cannot be recovered without an external length. Partial blocks need
   documented padding. Compound `.radio.*` extensions are misclassified by
   `ExtractFileExt`.
4. QCFM parsers do not validate available CRCs, run ordering/overlap, arithmetic
   limits, or all offsets before allocation. Header CRC fields are left zero by
   the packer. Signature CRC depends on read/seek history in its virtual stream.
5. `uautoloader.pas:MakeAutoloader` reserves 52/132 bytes regardless of input
   count (room for four offsets). Larger lists overwrite the advertised payload
   start. Readers accept non-monotonic offsets. PE bounds are clamped on errors.
6. `ubatch.pas` identifies OS/radio by a size threshold, silently deletes missing
   list entries, and continues after script-level errors. It publishes outputs
   before independent payload/checksum checks. Missing radio is not handled.
7. No Actions CI or release pipeline is present. The Pascal build depends on
   local CLI/mORMot/Lazarus paths; the resource build script hardcodes a home
   directory. Existing tests focus on QNX internals, with no portable packaging
   regression suite.
8. BAR hashing encodes SHA512 hexadecimal text instead of the raw digest.
   The real Weather manifest uses the correct 86-character unpadded base64url
   value. Hash updates also drop native assets and existing asset attributes.
9. RCFS mutation ignores script failures and writes the source image directly.
   The VMDK path finds an RCFS partition at index `k`, then extracts `parts[1]`.
   Sparse holes, EBR cycles, GPT CRCs and compression variants need explicit
   validation. Native mutations now stage copies and verify packed/read-back hashes.

Public issue review: closed issue #4 concerns external fake signing, response
handling and version compatibility; the migration explicitly distinguishes CRC
verification from OEM authentication and rejects unknown variants. Closed issue
#5 reports a Passport reboot failure after rooting. No proven offline root cause
was established, so it remains a hardware acceptance case and is not claimed fixed.

10. The flash path stores signature bytes in a process-wide buffer, allowing one
    file's trailer to leak into another. Signature/complete failures are logged
    without failing the overall flash. Native flash uses per-file trailers,
    verifies staged content before USB access and stops on the first failure.
11. The USB reader assumes one complete frame per bulk transfer; channel readers
    omit response bounds/CRC/sequence checks. Native buffering handles fragmented
    and coalesced frames, with bounded parsing and simulated protocol tests.
12. An ordinary rename can replace an existing empty output directory on Unix
    between preflight and publication. Native directory publication now uses
    Linux RENAME_NOREPLACE / Darwin RENAME_EXCL; unsupported filesystems fail.
13. The BAR installer recursively changes ownership across every application's
    private-data directory and installs executable assets without reliable modes.
    Native installation confines ownership to the selected package, preserves
    its private data/GID, sets executable modes, removes obsolete service entries
    and publishes only a verified new image. Ambiguous package metadata fails.

## Language decision

Use Go. Both Go and Rust offer checked slices, explicit errors and portable
executables. This project is mainly binary parsing, streaming file operations,
checksums, command routing and device I/O. Go's standard library covers the
offline formats without C dependencies and its cross compiler produces the
existing Windows/Linux/macOS target set. Rust would also work, but does not add
enough value here to offset the larger dependency/build surface. Keep transport
and mount backends separate; USB/FUSE require OS-specific integration whichever
language is chosen.

## Architecture and invariants

- `cmd/bb10mt`: compatible CLI names/options, explicit errors and nonzero exits.
- `internal/binio`: bounded ReaderAt access and checked numeric/range helpers.
- `internal/atomicfile`: temporary sibling, sync, validate, then publish without
  clobbering an existing artifact. Failed operations leave no final artifact.
- `internal/qcfm`: V1, V2 and hybrid headers/runs; streaming pack/unpack/verify;
  actual metadata size determines data start. Preserve partition offsets and
  flags, validate CRCs when present, label the legacy fake signature honestly.
- `internal/autoloader`: bounded PE sections and 64-bit CAP tail offsets;
  split/extract/create with dynamic offset-table capacity and roundtrip checks.
- `internal/qnx6`: explicit little-endian layouts, both superblocks, correct QNX
  CRC and long-name checksum, inode/data/bitmap managers, offline fsck, scripts
  and compaction. Mutations use a working image and verify before publication.
- `internal/bar`, `internal/rcfs`, `internal/raw`: independent codecs and command
  services; BAR updates must preserve manifest semantics and reject unsafe paths.
- `internal/batch`: extraction -> script -> filesystem/path checks -> pack ->
  container verification -> autoloader verification -> publish. Missing inputs
  and command errors are fatal. Select OS/radio by partition types.
- Transport services: protocol framing and injected I/O for testability, with
  separately gated USB/network/FUSE adapters. Never silently fall back to Pascal.

Do not interpret a CRC, hash, fake signature or passing offline check as proof
of OEM signing or handset acceptance. Unknown/encrypted/checksummed variants
must fail with a specific unsupported-layout error until implemented and tested.
Binary lengths and counts are untrusted; bound them before allocation. Stream
multi-gigabyte payloads, and keep metadata memory proportional to runs/inodes.

## Implementation sequence and acceptance gates

1. Build/test foundations and packaging regression fixtures. Implement native
   Go QCFM and CAP/PE services plus compatible pack/unpack/split/autoloader CLI.
   Prove V1/V2/hybrid, multiple sparse runs, leading holes, partial blocks,
   compound extensions, more than four inputs, signature CRC, corrupt/truncated
   inputs, and no output on error. Differential-check against legacy artifacts.
2. Implement native QNX6 read/check/repair, correct checksums and independent
   fixtures. Compare the retained real Z30 image with the Python audit; repair
   copies only. Implement allocation/writes/scripts/mkfs/compact and batch with
   payload/permission verification before packaging. Run both firmware pack
   source preflights and relevant tests when integrating any wrapper changes.
3. Port BAR, RCFS/VMDK, raw/NVRAM, loader extraction, CLI completion and config.
   Each command gets format fixtures and negative tests before replacing its
   legacy implementation. Maintain a command compatibility matrix.
4. Port network/USB framing, flash/info/connect/loader/nuke and FUSE adapters.
   Use recorded synthetic protocol transcripts in CI. Hardware operations need
   explicit real-device acceptance; do not claim it from mocks or offline tests.
5. Release gates: format/vet/unit/integration/race tests on Windows/Linux/macOS;
   fuzz parsers; build six OS/architecture artifacts with pinned Go, checksums,
   deterministic archives, provenance and an SBOM/dependency inventory. Release
   only from passing tagged commits. Run real firmware roundtrips and document
   remaining hardware gates. Remove Pascal only after full command parity.

## Delivery policy

Development delivery requires implemented command coverage, local regression and
real-image checks, build artifacts and configured CI/release gates. Qualification
as a default replacement additionally requires hosted CI and explicit handset
acceptance; synthetic device tests cannot satisfy those gates.
No firmware binary or wrapper is switched to the new executable until native
batch and independent image verification pass. Existing dirty firmware pack
files, vanilla boot handling and canonical public certificate layout are kept.

## Implemented offline milestone

QCFM/CAP, QNX6 read/check/repair/edit/mkfs/compact and native batch are implemented.
The real Z30 v4_new build passes all 58 independent expected payload/permission
checks and Pascal fsck. An independent Python streaming parser verifies the final
CAP's embedded UFS SHA256, signature trailer CRC, preserved CAP overlay and exact
radio bytes. A separate checksum-only repair changed 23 bytes in six directory
checksum fields and preserved the original free-block count. The count correctly
excludes both reserved metadata regions; it was not a firmware defect.

RCFS raw/LZO read/check/edit/extract, bounded VMDK disk access, BAR manifests,
MCT/NVRE parsing, CAP loader extraction and completion generation are implemented.
RCFS uses `github.com/woozymasta/lzo` v0.3.2 (MIT); legacy loader archives use
`github.com/ulikunitz/xz` v0.5.17 (BSD-3-Clause), pinned with Go module checksums.
Release inventories omit host
paths and include every dependency and license. See the compatibility matrix for
remaining command and variant gates. No hardware acceptance or hosted CI result
is inferred from these local checks.

## Native adapters and application installation

The retained USB/network protocol now has native services with injected
transports. Tests cover fragmented frames, CRC/sequence errors, RSA/AES/password
handshakes, loader initialization/probing and staged flashing. USB dynamically
loads a separately installed libusb-1.0; it never detaches a kernel driver.
Unknown variants fail, and passwords are never guessed or retried.

Linux FUSE exposes read-only images or a disposable writable transaction. Kernel
integration tests cover read/write, rename, links, sparse extension, truncation,
live free-space reporting, EBUSY on the last open link, clean unmount and rollback.
The writable image is checked before publication. BAR installation uses the same
offline transaction model rather than changing an arbitrary mounted host tree.
PPS/GID/ownership and retained private-data behavior have synthetic image tests.

Go 1.27.2 is pinned in CI and the module toolchain. CI adds a pinned govulncheck
scan for Linux, Windows and macOS alongside race/fuzz/FUSE tests. Six release
targets carry deterministic archives, SHA256SUMS, dependency/license inventories,
CycloneDX metadata and tagged prerelease provenance. See VALIDATION.md for the
actual local evidence and acceptance limits.
