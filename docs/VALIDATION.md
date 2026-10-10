# Local validation and remaining acceptance gates

Date: 2026-10-10. Baseline: upstream
`31e5e372d064942ffea92665947a1b3cda488413`. Implementation: branch `migrate-go`.
The implementation was performed directly, without delegated agents.

## Development checks

- Go 1.27.2, native Windows amd64: `go test ./...`, `go vet ./...`,
  `go mod verify`, and gofmt checks.
- Linux amd64: all package tests executed through the existing WSL distro.
  `scripts/wsl_test_exec.py` adapts Windows Go test paths to Linux paths; it
  does not install anything or access a handset.
- Linux kernel FUSE: read-only enforcement; writable create/read/write/rename,
  hard links/symlinks, sparse offset writes, truncation and fsync; live free-space
  counters; EBUSY when unlinking the last open link; clean unmount and final
  fsck; failed-mutation rollback with no published output. Source bytes retained.
- Parser fuzzing covered QCFM, CAP/PE, QNX6, BAR, MCT/NVRE, RCFS, VMDK,
  network/USB frames and loader archives. Regression seeds are retained in tests.
  The most recent USB and loader-archive runs each exercised over two million
  cases; no handset was involved.
- govulncheck v1.8.0 scans Windows, Linux and macOS targets. Go 1.27.2 and
  x/sys v0.49.0 replace the older toolchain/system dependency. Scans must pass
  before packages are built in CI; vulnerability database results are time-bound.
- Actions workflow syntax checked with actionlint v1.7.7. CI specifies native
  Windows/Linux/macOS race tests, parser fuzzing, Linux kernel FUSE integration,
  vulnerability scans and all six cross-builds. Tagged prereleases add provenance.
  Releases include a direct executable per target as well as archives with docs
  and licenses; SHA256SUMS covers both forms. `RELEASE_VALIDATION.json` records
  the independent archive/hash/repeat-build check of the delivered artifacts.

## Real firmware evidence

No firmware binary, private key or credential is committed. Retained local Z30
10.3.03.3216 artifacts were used as independent format and payload evidence.

- `REAL_IMAGE_VALIDATION.json`: a checksum-only repair changed 23 bytes across
  six long-name checksum fields in a 2,596,012,032-byte QNX6 image. The original
  free-block count was correct and retained.
- `REAL_BUILD_VALIDATION.json`: native batch completed the v4_new patch script.
  All 58 expected payload hashes/permissions passed the independent Python image
  checker. Pascal fsck also passed. An independent streaming Python parser checked
  final CAP offsets/PE overlay, QCFM runs/trailer CRC, embedded UFS SHA256 and exact
  unchanged radio bytes.
- `WRAPPER_BUILD_VALIDATION.json`: the existing v4_new PowerShell wrapper also
  completed with the Go executable and passed those final-container checks.
  Firmware timestamps make separate image builds differ; no byte-reproducibility
  claim is made for these firmware outputs.
- Real RCFS verification covered 15,676 inodes and 13,200 packed SHA256 hashes;
  real CAP extraction recovered 96 RAM loaders with gzip CRC verification.
- QNX6 compaction moved 76,664 blocks and shortened the retained physical image
  from 2,596,012,032 to 2,281,668,608 bytes while retaining logical geometry and
  the expected payload hashes/permissions.
- Wrapper/documentation fixes were synchronized to v4_orig and v4_new. Both
  source preflights and relevant packaging/long-name tests passed. The vanilla
  v4_new boot hook and canonical public certificate layout were preserved.

## Qualification limits

Hosted GitHub Actions have been configured and syntax-checked, but were not run
from this local checkout. Native macOS execution and local race instrumentation
were not performed; this Windows host has no configured GCC-compatible compiler for Go race tests. Cross-builds
and target vulnerability scans do not substitute for those runtime checks.

USB/network services and BAR PPS registration have simulated tests; no handset
flash, wipe, reboot, password attempt, BBID or BBM acceptance test was performed.
The Passport reboot report has no proven offline root cause and is not claimed
fixed. USB response/sequence assumptions still need real handset transcripts.
The legacy loaders.dat format has an independently generated LZMA fixture, but
no retained production loaders.dat was available to test.

The compatibility matrix records unsupported format variants and intentional
CLI changes. A checksum, fake signature or passing filesystem test cannot prove
OEM authentication or handset boot acceptance. Retain the Pascal rollback path
until hosted and handset qualification is complete.

## Bundled runtime follow-up (v0.7.0-go.2)

All six targets embed pinned native libraries and license notices. Local
Windows/Linux amd64 smoke tests passed extraction, alternate-runtime launch,
file hashes, rejected cache tampering, USB initialization/enumeration and QNX6
creation/fsck. Linux passed a writable bundled FUSE transaction and an empty-
root chroot test with procfs but no installed host libraries (version, USB
initialization, mkfs/fsck and helper launch). Native import closure checks cover
every target; macOS dylibs declare minimum macOS 14. Native arm64/macOS runs
remain hosted CI gates. Go test/vet cover the cache/runtime seams; native C
versions are inventoried but not scanned by govulncheck. See BUNDLED_RUNTIME.md
and BUNDLED_RELEASE_VALIDATION.json for distribution details/evidence.

## Declarative package follow-up (v0.7.0-go.3)

Local packages now expose exact dependencies, capabilities, ownership,
compatibility hashes, a locked plan and atomic new-directory builds. Weather
uses separate trust and read-only existing-boot foundation packages. Legacy
scripts remain supported. No executable package hooks or implicit rooting were
introduced. The exporter emits one public PEM source and no login keys.

Windows and WSL Linux tests passed, including synthetic OS/radio CAP builds,
idempotence, conflicting/ancestor ownership, changed payloads and locks,
unrecognized originals, ambiguous app directories, unsafe paths, allocation
failure, relative output paths and transaction rollback. Windows manifest
fuzzing ran 20 seconds (355,553 executions) without a failure. Go vet, workflow
lint and Windows/Linux exporter publication/confinement tests passed. Both pack
source preflights and ten Weather tests per pack passed after the documentation
was synchronized.

The real Z30 installation pilot restored eight removed Weather/trust files;
independent checks matched their bytes/modes/uid/gid to the legacy output and
verified all 58 maintained payloads. The original boot hook stayed unchanged.
The real full-size OS CAP was also rebuilt with all packages already present:
both OS CAP and embedded UFS remained byte-identical to their input. Independent
CAP trailer CRC, five-partition reconstruction, superblock CRC, pathname and
payload checks passed, as did native QNX6 fsck. Evidence is in
PACKAGE_BUILD_VALIDATION.json, PACKAGE_CAP_VALIDATION.json and
PACKAGE_CAP_IMAGE_VALIDATION.json.

Real temporary-disk failures published no output. Pinned source copies now use
the system temporary area, with output staging on the destination volume.
Hosted Actions, native macOS/arm64 execution, race instrumentation and handset
acceptance remain qualification gates; the local results do not substitute for
them. This package slice requires a compatible provisioned image and does not
install the root foundation on stock firmware.
