# Command compatibility and acceptance

The table describes implemented commands and their qualification limits.
Unsupported commands exit nonzero and never invoke the Pascal executable.

| Commands | Native Go status | Evidence / remaining gate |
|---|---|---|
| pack, unpack | Implemented V1/V2/hybrid | Sparse, padding, run bounds, CRC, deterministic roundtrip tests |
| verify (new) | Implemented | Real retained Z30 OS container, 3,010,003,896 bytes, trailer CRC passed |
| split | Implemented | CAP extraction uses bounded 64-bit offsets |
| autoloader create/extract/verify | Implemented | V1/V2 with 1, 4, 5 and 10 inputs; malformed offset and PE tests |
| qnx6 audit/repair-names/read/verify (new) | Implemented for BB10 LE v4 without inode checksums | Known kernel vectors and synthetic fixtures; real image scan detects six invalid names |
| qnx6 mkfs/script/fsck/compact | Implemented for BB10 LE v4 without inode checksums | Allocation, double-indirect blocks, links, rollback, free counters; real native image passes Python payload checks and Pascal fsck |
| qnx6 mount | Implemented on Linux, read-only or new writable output | Local WSL kernel FUSE read/write/rename/link/symlink/truncate/unmount plus final fsck passed on synthetic images |
| batch | Implemented for V2/hybrid OS/radio containers | Real Z30 build; 58 independent payload/permission checks; final embedded UFS hash, CAP overlay and unchanged radio verified |
| autoloader loaders | Implemented | Descriptor/gzip bounds tests; 96 real Z30 loaders extracted with gzip CRC checks |
| bar template/update/ids/verify | Implemented | Raw SHA512 base64url, folded manifests, native assets, metadata preservation and fuzz regression cases |
| bar install | Implemented as a new QNX6 image transaction | SHA512/SHA256, executable modes, isolated ownership, GID reuse, registration/service replacement and rollback tests; device acceptance pending |
| rcfs read/verify/extract/modify/vmdk | Implemented for raw/LZO1X and flat/monolithic-sparse disks | Real RCFS: 15,676 inodes, 13,200 packed SHA256 hashes and decompressed payloads verified; mutation rollback and correct partition selection tests |
| vmdk list (new) | Implemented | MBR/EBR/GPT bounds, cycle checks, header/table CRCs and sparse-hole tests |
| raw dump/nvram | Implemented | MCT/NVRE CRCs, malformed extents, duplicate records and fuzz tests |
| connect | Implemented with explicit IP and public RSA key | Fragmented simulated network handshake, RSA/AES/password/key/service tests; real device acceptance pending |
| usb list, flash/info/loader/nuke | Implemented with runtime libusb-1.0 | Simulated boot/RAM-loader/flash transcripts; CRC/sequence/framing, bounds, cancellation, no password retries, short writes and cleanup tests; real device acceptance pending |
| configuration and loader probing | External files, existing [Loaders] INI mappings, loaders.dat and explicit --probe-all implemented | Model address, signature markers, archive bounds/CRC/LZMA dictionary/size checks; bounded multi-loader simulated transcripts; device acceptance pending |
| completions, full help | Implemented | Bash syntax and PowerShell AST checks; native CLI definitions supply flags |

All mutating image commands require a new output (`-o`); this deliberately
replaces legacy in-place writes. QNX6 compaction keeps logical geometry while
omitting the unallocated physical tail. RCFS replacement must fit the original
packed extent and updates VSIG SHA256; its external signature is not authenticated.
The explicit RCFS `corrupt` operation intentionally invalidates the selected
stored payload and VSIG hash. RCFS extraction records symlinks and original
uid/gid/modes in `.bb10mt-rcfs.json` instead of creating host symlinks. VMDK edits
reject nonzero writes into unmapped grains; compressed/stream-optimized variants
are unsupported. BAR update/ids intentionally update their small manifest in place.

`qnx6 script` supports mkdir, touch, push, rm, chmod, chown, replace,
addstring and removeapp. `--debloat` generates the deferred-uninstall package list
and protects sys.android/sys.android.shell; `batch --compact` checks all inode
payload hashes after compaction. Inode-checksummed/encrypted QNX6 variants, nonzero QCFM main-header
CRC variants, and V1-only batch identification remain unsupported explicitly.

See `REAL_IMAGE_VALIDATION.json` and `REAL_BUILD_VALIDATION.json` for recorded
real-image evidence. `WRAPPER_BUILD_VALIDATION.json` records the independent
CAP/container/UFS/radio verification of the existing v4_new PowerShell wrapper
using the Go executable. No firmware binaries or private credentials are committed.

USB commands wait for BootROM mode by default; normal-mode reboot requires
`--reboot-to-bootrom`. Firmware inputs are staged and fully validated before USB
is opened. USB and network framing follow the retained legacy protocol, including
legacy cryptography, with synthetic tests; sequence/status assumptions still
require handset transcripts. The release bundles libusb; no
kernel driver is detached automatically. `info --bootrom-only` does not load RAM
code. `loader --loader-file` initializes one selected, validated loader.
`loader --probe-all` tries up to 256 distinct loader candidates once and emits
JSON lines. It skips incompatible structures, stops on transport/authentication
failure, and reboots every success. The next candidate waits up to `--timeout`
for the same model on the same bus to return to BootROM; no automatic password
retry or repeated recovery loop occurs. It does not write the legacy loaders.ini
side-effect file. Default loader/config/archive paths are beside the executable.

`bar install -p unpacked-bar -i original.ufs -o installed.ufs [--replace]`
replaces the old `--mount` in-place installer. It verifies the package, edits a
private image, updates exact registration keys, removes obsolete service entries
from the previous manifest and checks the final filesystem before publication.
An existing package needs `--replace`; its GID and private data are retained.
Only that package's private directories receive ownership changes. ELF/shebang
and host-executable assets receive 0755, other files 0644 and directories 0755.
Unsupported navigator CSV fields fail explicitly. PPS registration behavior is
covered by synthetic fixtures and still needs handset acceptance.

`qnx6 mount` runs in the foreground. With no output it is read-only; `-o` mounts
a private working copy and publishes the output only after unmount and a full
filesystem check. Failed mutations discard that output. Deleting or replacing
the last link to an open file returns EBUSY; close it first. Extended attributes,
special-device creation and exchange renames return unsupported errors. The
adapter serializes requests and streams whole-file rewrites for random writes.
It requires kernel FUSE and mount permissions. The release bundles an
unprivileged fusermount3 helper; ordinary users may still need an administrator-
installed setuid helper. No FUSE C library is linked.

Each release target is available as a direct executable and an archive. No Go
installation is required. Releases from v0.7.0-go.2 embed their native user-space
libraries, including libusb, the Windows C runtime and Linux loader/libraries/
helper. Linux bundles support musl hosts; macOS bundles require macOS 14+.
OS kernels, drivers, frameworks and permissions remain external. See
[BUNDLED_RUNTIME.md](BUNDLED_RUNTIME.md) for extraction, replacement and licenses.

CI validation is configured in `.github/workflows`, but a local run cannot
establish that hosted jobs passed. Device operations have not been performed.
Local race tests require a C compiler, which this host does not currently expose;
the hosted test matrix explicitly enables CGO for race instrumentation.
See [VALIDATION.md](VALIDATION.md) for toolchain, local platform and release evidence.
