# BB10 MultiTool: Go migration

The native Go implementation retains the GPL-3.0 Pascal sources as a format
reference and rollback path. Read [the review and design](docs/MIGRATION.md) and
[command compatibility](docs/COMPATIBILITY.md) before replacing an existing tool.

Build requirements: Go 1.27.2. Downloaded executables need no Go installation.
Release executables bundle native user-space libraries; Linux includes its own
glibc loader and can run on musl hosts. Source-only builds use host libraries.
See [bundled runtime details](docs/BUNDLED_RUNTIME.md). RCFS uses the pinned
MIT-licensed pure-Go LZO codec recorded in [third-party notices](THIRD_PARTY_NOTICES.md).

Declarative local app packages are available alongside the script workflow.
See [package design and migration](docs/PACKAGES.md) for Weather, shared trust,
explicit boot prerequisites and locked builds. Adding package data does not
require recompiling the single binary.

```
go test ./...
go vet ./...
go build -trimpath -o bin/bb10mt-go.exe ./cmd/bb10mt
```

Examples (use a new output path for every operation):

```
bb10mt pack -c patched.signed -l partitions.lst --versions 2 --sign
bb10mt verify -c patched.signed
bb10mt unpack -c patched.signed -o unpacked
bb10mt autoloader create -c cap.exe -i patched.signed -o patched_os.exe
bb10mt autoloader verify -i patched_os.exe
bb10mt qnx6 audit -i filesystem.ufs
bb10mt qnx6 repair-names -i filesystem.ufs -o repaired.ufs
bb10mt qnx6 script -i repaired.ufs -s patch.txt -o patched.ufs
bb10mt qnx6 fsck -i patched.ufs
bb10mt qnx6 compact -i patched.ufs -o compact.ufs
bb10mt batch -i original.exe -s patch.txt -o new-build
bb10mt packages validate --catalog packages
bb10mt plan -i provisioned.ufs --catalog packages --profile packages/weather.json -o plan.json
bb10mt build --plan plan.json -o package-build
bb10mt rcfs verify -i filesystem.rcfs
bb10mt bar verify -p unpacked-bar
bb10mt bar install -p unpacked-bar -i filesystem.ufs -o installed.ufs
bb10mt qnx6 mount -i filesystem.ufs -m empty-mount-directory
```

Input list paths resolve relative to the list file, including subdirectories.
V1 flash offset/flags use `file=offset,flags`. Use `--versions 1,2` to preserve
that metadata; pure V2 cannot represent V1 flash flags. Longest suffix matching
preserves `.radio.*` and `.dmi.*` types. Sparse V2 extraction preserves leading
erased blocks; V1 extracts relative to its first flash offset and saves that
offset in the list. The writer retains the last block, even if erased.
QCFM has no original byte-length field: a partial final block is padded with
zeros to 64 KiB. Older files may have omitted trailing erased blocks; their
original extent cannot be inferred.

`--sign` appends the upstream legacy fake signature and a deterministic IEEE
CRC32. It is not an OEM signature. `verify` checks layout, V1 control/run CRCs
when present, and a recognized trailer's CRC. It does not authenticate firmware.
Unknown main-header CRC variants or signature trailers fail explicitly until
implemented. Files without a trailer have no whole-payload CRC to verify.

`qnx6 audit` verifies the superblock CRC and inspects all allocated directories,
including those not reachable from the root. Bad long-name checksums produce a
JSON report and a nonzero exit. `repair-names` repairs a **new copy** only after
the complete scan succeeds, then verifies it again. It changes only directory
checksum fields; inode-checksum/encrypted layouts are currently rejected.
`qnx6 verify -m expected.json` checks an array of `{ "path": "/path", "sha256":
"...", "mode": 493, "uid": 0, "gid": 0 }`; mode is the decimal permission
value (493 = octal 0755). SHA256 and permissions are independently optional.
Checksum and offline image checks do not establish handset boot acceptance.

Direct executables and release archives are produced with
`python scripts/vendor_runtime.py`, then
`go run ./cmd/release --version v0.7.0-go.2 --output dist`. Builds cover Windows/Linux/macOS on amd64 and arm64. The release
tool emits deterministic archives, SHA256SUMS, a dependency inventory, a
CycloneDX SBOM and required licenses. CI includes Windows/Linux/macOS race tests,
parser fuzzing, kernel FUSE transactions, vulnerability scans, six cross-builds,
archive checksum verification and tagged
prerelease provenance. Hosted CI has not been run from this local checkout.
All module-graph checksums are committed. If dependency maintenance has removed
auxiliary hashes, run `go mod download all` before packaging; missing or invalid
module hashes make the release command fail.

Choose the executable for your OS and CPU: `bb10mt-VERSION-windows-amd64.exe`
or `windows-arm64.exe`, `bb10mt-VERSION-linux-amd64` or `linux-arm64`, and
`bb10mt-VERSION-darwin-amd64` or `darwin-arm64`. Each is one executable with an embedded runtime;
Linux/macOS downloads may need `chmod +x`. Check it against SHA256SUMS before use.
The executable bundles libusb, licenses and native runtime dependencies; Linux
also bundles its loader and fusermount3 helper. Windows drivers, Linux kernel
FUSE/mount permissions and macOS system frameworks remain OS requirements.
Firmware and RAM-loader inputs remain external. Libraries extract to a verified
user cache automatically; `--extract-runtime` exports them and `--runtime-dir`
permits replacement libraries. Matching native source archives ship separately
as `runtime-sources.zip`. macOS bundles require macOS 14+.

The native batch path has passed independent payload, permission, filesystem and
final-autoloader checks on the real Z30 v4_new pack. The firmware wrappers accept
`-Multitool D:\Downloads\bb10mt\bin\bb10mt-go.exe` as an opt-in; their defaults
are preserved. USB and network services have native implementations and simulated
protocol tests; handset acceptance remains pending. Release executables bundle libusb-1.0. Firmware is staged and validated before USB is opened;
passwords are never guessed or retried. Linux FUSE mounts are read-only by default;
writable mounts and BAR installation publish a checked new image. Loader probing
is explicit with `loader --probe-all` and emits JSON lines. Read the compatibility
matrix before replacing the legacy executable; [validation records](docs/VALIDATION.md)
distinguish local results from hardware and hosted-CI gates.
