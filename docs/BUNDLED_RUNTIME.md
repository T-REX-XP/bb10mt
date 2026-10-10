# Single-file runtime distribution

Starting with v0.7.0-go.2, each of the six release executables embeds the Go
application, its native user-space dependencies, notices and licenses. Download
one executable for Windows, Linux or macOS and the matching amd64/arm64 CPU.
No Go, libusb, C runtime installer or archive utility is needed to run it.

| Target | Embedded native runtime | OS requirements |
|---|---|---|
| Windows amd64/arm64 | libusb 1.0.30; Microsoft VC runtime 14.51.36247.0 | Windows 10/11 or compatible supported Server; USB driver suitable for libusb |
| Linux amd64/arm64 | glibc 2.41 loader/libraries; libgcc; libusb 1.0.28; libudev; libcap; fusermount3 3.17.2 | Supported Linux kernel, procfs; USB permissions; kernel FUSE and mount permissions for mounting |
| macOS amd64/arm64 | libusb 1.0.30, Sonoma bottle | macOS 14+; Apple system frameworks; USB permissions |

Go libraries and codecs are compiled into the application. Linux uses its
embedded ELF loader and library search path, so host glibc is not required;
musl hosts can use this bundle. OS kernels, USB drivers, system frameworks,
device permissions and firmware/RAM-loader input files remain external.
The program never installs drivers or changes USB driver bindings automatically.

## Extraction and launch

The executable is a static Go bootstrap on Linux. On first launch it extracts a
deterministic ZIP into the current user's OS cache, under
`bb10mt/runtimes/<payload-SHA256>`. Every launch verifies the manifest, file
sizes, SHA256 hashes and POSIX modes before executing the application. Changed,
missing, extra or symlink files fail explicitly. Cache directories are private
on POSIX; Windows uses the current user's normal cache permissions. A writable
cache on a filesystem allowing executable files is required. Concurrent launches
publish one complete cache directory atomically. Delete a rejected cache
directory to recreate it from the executable. Old version caches can be removed
after their processes exit.

Unix replaces the bootstrap process with the application to preserve signals
and exit status. Windows forwards streams and exit status; console interrupts
reach the application. Configuration and loader defaults remain beside the
downloaded executable, with the embedded `bb10mt.ini` as a fallback. Relative
image and output paths continue to resolve from the caller's working directory.

```
bb10mt --runtime-info
bb10mt --extract-runtime NEW_DIRECTORY
bb10mt --runtime-dir NEW_DIRECTORY --version
bb10mt --runtime-dir NEW_DIRECTORY usb list --libusb /path/to/replacement-library
```

`--runtime-dir` intentionally runs an explicitly selected, user-modified runtime
without enforcing the embedded hashes. Extract, replace/rebuild a shared library
and use this option to exercise your modified library. Normal cached launches
always enforce the embedded inventory. Runtime options must precede application
arguments. Use normal application `--help` for image and device commands.

Linux mounting uses Go FUSE and the bundled helper; it does not link libfuse.
Root mounts and unmounts directly. An ordinary user still needs a suitable
administrator-installed, root-owned setuid fusermount3 helper, or appropriate
mount capabilities. The launcher prefers such a system helper; otherwise it
uses its bundled unprivileged helper with the embedded ELF loader. The tool
does not grant privileges or install a setuid executable. `/dev/fuse` must exist.
macOS and Windows do not expose the Linux QNX6 mount adapter; offline image
editing works on all three systems.

## Build and maintenance

```
python scripts/vendor_runtime.py --output out/runtimes
go run ./cmd/release --version v0.7.0-go.2 --runtime-root out/runtimes --output dist
```

Python 3.11+ and 7zz/7z are packaging prerequisites. Windows also searches the
standard `C:/Program Files/7-Zip/7z.exe` location. The vendor script downloads
immutable/versioned upstream archives, verifies every pinned SHA256, and reads
selected members without running installers or installing packages. The build
rejects a runtime lock that differs from `third_party/runtime.lock.json`, checks
matching source hashes and validates native architecture/import closure for all
targets. Linux bootstrap executables must have no ELF interpreter. macOS native
imports must resolve only to Apple system libraries/frameworks; Windows imports
must resolve to bundled DLLs or normal Windows APIs.

`runtime.lock.json`, `DEPENDENCIES.md`, CycloneDX `sbom.cdx.json` and SHA256SUMS
accompany each release. Native archive versions/hashes are included in the SBOM;
this is an inventory, not an assertion that native libraries have no
vulnerabilities. Go vulnerability scans do not scan bundled C libraries.
Review upstream/Debian security updates when refreshing this lock, then rerun
native smoke tests, empty-root Linux tests and reproducibility checks. Packaging
requires network access only during the pinned download preparation step.

## Licenses and corresponding source

Use `--extract-runtime` to obtain `licenses/`, `native-packages.json`,
`runtime.lock.json` and the exact shared libraries. Native libraries remain
separate dynamically loaded files. Libusb and glibc retain LGPL notices;
libgcc includes GPLv3 and its GCC Runtime Library Exception; fusermount3 retains
GPLv2 notices. Other component notices are included as supplied upstream.
Microsoft's runtime DLL retains its separate proprietary redistributable license.

The release's `runtime-sources.zip` supplies exact upstream source archives,
Debian source descriptors and patches for the native open-source components,
plus the pinned lock and extraction script. Microsoft does not provide source
for its proprietary redistributable. Matching libusb sources include the Windows
Visual Studio project files; macOS runtime extraction includes Homebrew's bottle
formula under `build-info/`. For Debian builds, unpack the supplied matching
`.dsc` with `dpkg-source -x`, install the declared build dependencies in a
matching Debian build environment, and use `dpkg-buildpackage`; libc, libgcc,
libudev, libcap, libusb and FUSE sources/patches are all retained. Libusb's
upstream tarball also includes its configure/build instructions. The Go wrapper
and application sources remain in https://github.com/bb10root/bb10mt.
Distribute the source archive and notices alongside binary releases.

## Evidence and limits

Local Windows/Linux amd64 tests cover launch, extraction, modified-runtime
launch, manifest hashes, rejected cache tampering, USB library initialization
and read-only enumeration, and offline QNX6 creation/checks. Linux also passed a
writable kernel FUSE transaction and launch/USB initialization/offline checks
inside an empty chroot with procfs and no host libraries. All six targets are
cross-built and their native import dependencies checked. Native macOS and
arm64 execution remain hosted CI gates; no handset operation was performed.
Hosted Actions are configured but have not run from this local checkout.
