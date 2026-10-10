# Third-party code

The Go build uses `github.com/woozymasta/lzo` v0.3.2 for RCFS LZO1X
compression and decompression. It is pinned in `go.mod` and `go.sum`, uses
no C runtime, and is licensed under MIT. Its complete license is included
in `third_party/licenses/lzo-MIT.txt` and every release archive.

The USB adapter uses `github.com/ebitengine/purego` v0.11.1 to call a separately
installed libusb-1.0 without a C compiler. Purego is licensed under Apache-2.0;
its license is included in `third_party/licenses/purego-Apache-2.0.txt` and
release archives. Libusb itself is loaded at runtime and is not redistributed.

Legacy `loaders.dat` uses `github.com/ulikunitz/xz` v0.5.17 for bounded LZMA
decompression (BSD-3-Clause, `third_party/licenses/xz-BSD.txt`). Archive metadata,
compressed CRC32, dictionary limits and exact decompressed lengths are checked.

Linux mounting uses `github.com/hanwen/go-fuse/v2` v2.12.0 (BSD-3-Clause).
Platform calls use `golang.org/x/sys` v0.49.0 (BSD-3-Clause). The full module
graph also includes go-fuse's test/auxiliary dependencies: godebug v1.1.0 and
mountinfo v0.7.2 (Apache-2.0), go-xdr at 1a41d1a06c93 (ISC), go-nfs-client
at b44639837b00 (BSD-2-Clause), and x/sync v0.10.0 (BSD-3-Clause).
Their complete license/notice files are included under `third_party/licenses`.
The dependency inventory describes the module graph, including auxiliary
modules; it does not imply every module is linked into every platform binary.

The release dependency inventory and CycloneDX SBOM record the module version
and downloaded module hash. The remaining offline formats use the Go standard
library. Go is distributed under BSD-3-Clause; see https://go.dev/LICENSE.

The embedded QCFM legacy fake-signature bytes originate from this project's
GPL Pascal source. They are not a private signing key or an OEM signature.
