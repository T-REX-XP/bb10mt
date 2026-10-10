# v4-neo patcher design

The Go core owns QNX6 writes, filename checksums, free-space accounting, QCFM
packing, CAP tables and atomic build transactions. This patcher supplies the
maintained firmware data and native verification of the final output contents.

## Boundaries

* `foundation/` is a pinned snapshot of the maintained pack's fresh-install
  script, payloads and manifests. Its original rooting
  sequence and boot hook are preserved byte for byte. Existing App World,
  BBID, BBM and experimental localization overlays remain in this migration
  baseline until dedicated package adapters can preserve their prerequisites.
* `packages/` contains independently versioned Weather, shared trust and an
  explicit assertion of the installed boot foundation. Packages contain public
  payloads only. They cannot install rooting, replace Android boot components
  or run host/device hooks. Additional compatible app overlays belong here.
* `bin/` supplies six pinned Go executables, each with its native runtime
  libraries embedded. Fresh builds, validation and assembly run directly in Go.
  No host Python interpreter, PowerShell script or shell wrapper is required.

## Fresh installation

Validate the snapshot and source contracts, select the host executable, hash
the original firmware and run Go `batch` into a private sibling directory.
Go repairs the source filesystem before applying the script and packs only
the checked final image. Check every maintained public payload,
its pathname checksums and service permissions, the superblock CRC, CAP stub
and offset table, packed trailer CRC, embedded UFS equality and unchanged
radio bundle. Recheck the source hash and emit an acceptance record and output
SHA256 sums. Publish the complete directory atomically without replacement.
There is no post-pack mutation or second OS repacking pass.

Failed builds remove their temporary output and leave the input and existing
output untouched. Preserve a failure log beside the requested output when
possible. Disk space is needed on the selected output volume, so firmware
outputs need not live beside the patcher.

## Package updates and rollback

For an already provisioned compatible UFS or CAP, run native `packages validate`,
`plan`, then `build`. The exact-version profile, source hashes, destination
ownership and original content hashes produce a locked plan. The native engine
rechecks the lock, writes privately and verifies before publication. Ordinary
package updates use the same Go executable.

Keep the original firmware, previous catalog, profile and output. Roll back by
rebuilding from that original with the earlier snapshot/profile. Do not infer
inverse patches or apply the fresh-install script repeatedly to a patched image.

## Delivery and qualification

The assembler copies only named build inputs, excludes login documentation and
host caches, verifies the release SHA256 inventory, exports the catalog and
publishes a new directory. The foundation contains the maintained firmware's
SSH host key; this local pack must remain private. The handset login private
key `docs/ssh.pub` is never read or copied. Public distribution requires a
separate per-install credential provisioning design.

Go tests check native publication/failure behavior; pack CI checks the assembled
source contracts on Linux, Windows and macOS. A local real Z30 build checks
offline artifacts. Native macOS/ARM execution, hosted CI and handset behavior
remain distinct evidence; an image build does not establish device acceptance.

Source-authoring checks for ELF changes, typed PPS, BBM and localization stay
in the maintained source repository. Run them before assembling a changed
foundation. The shipped Go preflight verifies declared hashes, certificate
layout, boot contract, script ordering, package manifests and sealed inventory.
Independent Python reference verifiers remain optional development evidence;
the native acceptance report identifies its verifier as Go.
