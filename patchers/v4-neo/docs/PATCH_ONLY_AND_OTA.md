# Experimental original-flasher patch packages

The `autoloader delta` command keeps the base executable's CAP stub and overlay
byte-for-byte and emits a V2 QCFM containing only changed 64 KiB UFS blocks.
It uses the existing original USB flasher, with no SSH, network agent or handset
connection during construction. It is opt-in and does not change normal full
OS/radio builds.

```powershell
.\bin\windows-amd64\bb10mt.exe autoloader delta `
  --base 'D:\Downloads\original.exe' `
  -i 'D:\Downloads\patched_os.exe' `
  -o 'D:\Downloads\patch-only-experimental' `
  --workdir 'D:\tmp' --experimental
```

Use exact base and target EXEs, not directory names. The output directory must
not exist; its parent and the packing workspace must exist. Publication requires
the workspace and destination to share a filesystem. Successful builds retain
only `patch-only-EXPERIMENTAL.exe` and `validation.json`; temporary containers and
the extracted CAP are removed. Neither command nor build executes the EXE.

The narrow implementation requires equally sized, complete UFS images with
64 KiB container blocks, V2 partition identities, identical CAP code, identical
OS partition order, and unchanged non-UFS partitions. It rejects no-op updates,
resizing, changed boot partitions and sparse input UFS images. Changed blocks
containing only `0xff` are included: they represent a change, not a removable hole.

Validation reads the serialized delta back, overlays it on the exact base and
compares every logical byte with the target, rehashing both inputs. The report
includes complete base/target EXE hashes, UFS hashes, changed-block preimage
hashes, output hash, sparse runs and the original CAP hash. Container CRCs and
the final CAP offset table are checked. The builder adds no credentials, but
replacement blocks inherit the target image's contents. Existing private keys
or provisioning data in that image are not scrubbed; this is not a public-release
credential audit.

## Experimental boundary

**Do not distribute this as a beta updater or flash a primary handset yet.**
The original CAP does not enforce the hashes in `validation.json`. These hashes
are build evidence, not an on-device compatibility check. A matching firmware
version does not establish identical UFS bytes: filesystem metadata and installed
files can change after use. The replacement blocks also contain metadata and
neighboring bytes outside the individual patched files.

QCFM can encode sparse runs, but that alone does not establish that the bundled
RAM loader preserves omitted blocks. Destination erasure, active/inactive region
selection, required companion partition records, activation and interruption
behavior still require loader analysis or a controlled disposable-device test.
The build proves an offline overlay; it does not prove a safe partial flash,
user-data preservation, hardware compatibility or boot success.

For the stock 10.3.3.3216 package and the existing `go12-beta-hub-fixed` target,
the measured change is 536 blocks (35,127,296 bytes) across 16 runs. The CAP stub
is 9,252,464 bytes. This is a block overlay for that exact source/target pair,
not a generic application installer.

The resulting EXE is 44,380,812 bytes: 9,252,464 bytes of original CAP flasher,
35,127,296 bytes of changed blocks and 1,052 bytes of container/table overhead.
File-level byte edits and compact deltas are also supported during offline
builds; see [BINARY_PATCHES.md](BINARY_PATCHES.md). The original flasher still
requires its block representation and cannot directly consume file deltas.

## OTA package investigation

The patch-only EXE above is **not an OTA package** and does not use `libfota`.
The BB10 10.3.3.3216 Deckard installer has separate application and system update
paths. Evidence comes from stock `deckard/installer/{application,coreos,package}`
and `deckard/bar/abstractbar` bytecode, plus `libfota.so.1`, `_fota.so` and
`libupi.so`. The library hashes and disassembly are recorded under
`D:\tmp\fota-investigation-20261011` on the investigation machine.

### Full BAR updates are a separate option

An application update need not contain a delta: `Application._stage` chooses
`_unzip` for non-patch packages and `_patch` for patch packages. A complete BAR
for an application can therefore avoid Red Bend generation entirely. It still
needs the correct package identity, digests, signatures, capabilities and
installation policy. Signing our own application does not establish authority
to replace BlackBerry's original BBM/World packages under their existing
identities, or to write arbitrary privileged runtime files. Package validity is
also separate from discovering and implementing the handset's OTA delivery flow.

### Application and system-data deltas

The outer package is a BAR archive with `Package-Type: patch` and
`Patch-Package-Type: application` or `system-data`. The application installer
selects `patch/*.dp` members, sorts them, extracts them, and calls
`deckard.fota.fsupdate(src_path, dst_path, delta_fd, temp_dir, progress, trace)`.
The source is the existing installed package directory; output is staged and
verified through `UnpackedBar(dst).verify()` before its fingerprint is recorded.

Common package identity fields include `Package-Id`, `Package-Name`,
`Package-Version`, `Package-Version-Id`, `Package-Type`, `Package-Author` and
`Package-Author-Id`. Patch metadata includes `Patch-Package-Type`,
`Patch-Source-Package-Version` and `Patch-Destination-Package-Version`.
These observed fields are not a complete ready-to-sign manifest template.
The precise package family, assets, capabilities and installation policy must
also be satisfied for the chosen destination.

### OS/radio deltas

The system path expects `Package-Type: patch`, `Patch-Package-Type: system` and
an `.mld` payload. It opens an active source and inactive destination and calls
`deckard.fota.update(src_fd, dst_fd, delta_fd, progress, trace)`. The code checks
destination package version metadata, references source/destination version IDs,
and performs additional digest/SCM verification and registration. Activation is
outside `libfota`; a CRC-correct `.mld` is insufficient.

### What makes a package valid

1. **Structure and identity:** correct BAR layout, manifest, assets and exact
   source/destination package identities. Every included asset must have its
   required digest; native verification uses SHA-512 and exact manifest/section
   bytes. Signing information includes `META-INF/{name}.SF` and corresponding
   certificate/signature records such as `{name}.EC`.
2. **Compatible delta:** the engine identifies itself as `RedBend_vRM 8.0.1.43`
   and recognizes `RedBendEFDPackage`. It checks delta, source and target
   CRC-related signatures. Generic binary diffs, ZIP files and sparse QCFM are
   not interchangeable with Red Bend deltas. No compatible generator or sample
   `.dp`/`.mld` was found in the local directories searched.
3. **Trusted signatures and policy:** `bar.checksigs()` runs before both staging
   paths. Stock application verification describes RDK and AUTHOR requirements,
   author-certificate binding and named trusted-key verification. System updates
   additionally require supported SCM signatures; the examined CoreOS code has
   an ECDSA521 verifier and rejects its legacy RSA paths as too weak. A self-signed
   author certificate or the patcher's legacy QCFM trailer does not demonstrate
   acceptance by these system-update gates. TLS/BBID certificates are unrelated
   to package-signing authority.
4. **Successful installation and activation:** staged files, permissions,
   fingerprints, source matching and registration must be correct; activation,
   recovery and reboot behavior must be demonstrated on the intended firmware.
   `libfota` has no-op file-attribute and backup callbacks and cannot be treated
   as a complete transactional installer.

QNX's related CAR documentation describes Red Bend delta generation tools and
delta-based updates; it is supporting context, not proof that CAR server APIs or
package settings apply unchanged to BB10 handsets:

- [QNX System Services Reference, delta generation section](https://support7.qnx.com/download/download/26213/System_Services_Reference.pdf)
- [QNX CAR software updates](https://www.qnx.com/developers/docs/6.6.0.update/com.qnx.doc.car.user/topic/software_update.html)

## OTA conclusion and next proof

No newly authored package has been demonstrated as valid for the stock BB10 OTA
installer. The remaining prerequisites are a legitimate signing/trust path for
the exact package family and, for delta updates, a compatible Red Bend generation
workflow. Full application BAR updates do not require Red Bend tools.
First obtain a known-good signed update, inspect its manifest/signature structure
and generate/apply a delta against copied fixture trees. Then verify the BAR and
system-signature gates without weakening them, followed by a controlled device
staging/activation/recovery test. Do not label a locally generated ZIP, hash
report, transport CRC or experimental partial-flash EXE as a valid OTA update.

This investigation has not altered installer trust, firmware payloads, the boot
hook, certificates or handset processes. No SSH is required by the implemented
builder and no device deployment was performed.
