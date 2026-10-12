# Package build design and migration

The core owns image/container parsing, CRCs, QNX6 transactions and publication.
Local packages own their payloads, exact dependencies, file destinations and
accepted original hashes. Profiles select packages. The existing `batch` script
workflow stays available throughout migration.

The first release slice is Weather plus one shared certificate package and a
separate, read-only boot-foundation assertion. It does not provision rooting.
Weather requires the foundation capability; the foundation must be explicitly
listed in the profile and verifies the installed boot hook. An incompatible
stock image fails planning with the missing prerequisite, before any output is
published. Root installation, BAR registration, removals, executable hooks,
online repositories and automatic upgrades are outside this initial slice.

## Local contract

Each direct child of a catalog contains `manifest.json` and optional payloads.
JSON uses `schemaVersion: 1`, unknown fields are errors. Package IDs and exact
versions are simple portable identifiers. Kinds are `foundation`, `shared`,
and `app`. Foundation packages contain assertions only. An app can write its
own app namespace and explicitly declared `/var/` files; shared packages can
write explicitly declared app assets and `/var/` files. The Android boot hook,
`/etc` system configuration, `/accounts` rooting flags, SSH directories, device
nodes and privileged executable modes are excluded
from ordinary package writes.

Operations in v1 are `put-file` and `binary-patch`. Every operation declares an exact owned
path, payload SHA256, mode, uid, gid, whether absence is acceptable, and accepted
original SHA256 values. Existing desired content is idempotent; unknown content
fails. Parent directories are created as needed without changing existing
directory metadata. Duplicate or ancestor file ownership fails even when bytes
match. Image symlinks, nonregular targets and hard-linked targets are rejected.
Host payloads must be regular files beneath their package, with no symlinks.

`app:/sys.weather/native/lib/file` resolves to exactly one installed app directory
such as `/apps/sys.weather.<opaque-id>/native/lib/file`. The resolver checks the
directory and its BAR package identity when metadata is present. Legacy overlays
without metadata require a unique directory match. Compatibility is enforced by
the accepted whole-file hashes, rather than a claimed version string. Packages
that need registration changes must wait for a dedicated BAR adapter.

Profiles list `{id, version}` requirements. Dependencies are exact and ordered
topologically. Foundation dependencies are never selected implicitly. Conflicts,
cycles and missing capabilities fail. A lock records the input file hash, profile,
manifest hashes, payload hashes, resolved destinations and original file metadata.
No timestamps or network resolution enter a lock.

Build takes a verified private copy of the locked input and payloads, regenerates
the plan and compares it to the lock before executing. It checks preconditions
again at the image boundary, runs the existing transactional QNX6 writer and
verifies final hashes and metadata. CAP builds reuse the batch extraction,
checksum repair, packing and OS/radio verification path. The entire output
directory is published once with no replacement. A failed build leaves the input
and any existing output untouched. The lock is a reproducibility record, not a
signature or an authorization boundary.

The pinned input and output staging use a private transaction beneath the
destination's parent so publication remains atomic. Use `D:\tmp` for maintained
firmware build work. This area needs space for the private input/output copies.
Failed transactions remove their working files.

`binary-patch` accepts a BB10MT compressed copy/literal delta or a JSON byte-edit
recipe. It requires an existing binary, exactly one `originalSha256`, a separate
`patchSha256` for the patch payload, and `sha256` for the reconstructed binary.
The recipe must declare those same source/target hashes. The native script
command is `binarypatch IMAGE_PATH PATCH_FILE`; see [BINARY_PATCHES.md](BINARY_PATCHES.md)
in an assembled patcher for format details and examples. File patches apply
offline while building; they are not stock-loader or OTA package formats.

## Migration and rollback

1. Assemble a self-contained pack with native `bb10mt patcher assemble`.
   Its `packages/` catalog places the public PEM once in the shared package.
   Login keys are never exported. Run source-authoring tests before assembling
   a changed foundation; delivered firmware builds require only the executable.
2. Validate, plan against an already provisioned compatible image, and build.
3. Compare all eight Weather/trust destinations and the unchanged boot hook to
   the legacy build, including SHA256, mode, uid and gid; check QNX6 and CAP CRCs.
4. Keep `patch.txt` available. Roll back by rebuilding from the original image
   with the previous profile/catalog. Do not attempt inverse binary patches.
5. Move other apps only after their prerequisites and ownership are explicit.

```text
bb10mt patcher assemble --pack PATH_TO_V4_NEW --release RELEASE --source GO_REPOSITORY --source-commit REVISION -o NEW_PACK
# CATALOG is NEW_PACK/packages
bb10mt packages validate --catalog CATALOG
bb10mt plan -i provisioned.ufs --catalog CATALOG --profile PROFILE -o plan.json
bb10mt build --plan plan.json -o NEW_DIRECTORY
```

A compatible provisioned CAP autoloader can replace the `.ufs` input. Each platform keeps the
same Go command surface and bundled-runtime release mechanism. Package payloads
remain external data, so adding another app does not require recompiling the tool.

## Authoring another app package

Create `CATALOG/app.example/manifest.json` and place the payload beside it. Use
the actual SHA256 of `payload.dat` and the supported original file. For example:

```json
{
  "schemaVersion": 1,
  "id": "app.example",
  "version": "1.0.0",
  "kind": "app",
  "app": "com.example",
  "owns": ["app:/com.example/native/assets/payload.dat"],
  "operations": [{
    "type": "put-file",
    "path": "app:/com.example/native/assets/payload.dat",
    "source": "payload.dat",
    "sha256": "REPLACE_WITH_PAYLOAD_SHA256",
    "mode": "0644",
    "uid": 0,
    "gid": 0,
    "allowAbsent": false,
    "originalSha256": ["REPLACE_WITH_SUPPORTED_ORIGINAL_SHA256"]
  }]
}
```

Then select `{"id":"app.example","version":"1.0.0"}` in a profile. Shared
assets belong to a shared package with its own operations; app packages declare
that package in `requires`. Increment versions when payloads or preconditions
change. V1 allows one version of each package ID in a catalog. Keep all three
exported Weather packages together; their versions include source digest suffixes.

An exported catalog is self-contained. The exporter needs Python and the pack's
existing preflight scripts; normal `validate`, `plan` and `build` need only the
released binary and catalog data. Locks use absolute input/catalog paths: move
either source, create a new lock. They are local build records, not relocatable
distribution manifests. Retain the original image and catalog for rollback.

## Verification evidence

The real Z30 pilot removes the eight package files from a private copy of the
maintained image, installs them through a locked plan and compares them to the
legacy output with an independent Python QNX6 reader. It also checks all 58
maintained public payloads and the original boot-hook hash. See
`PACKAGE_BUILD_VALIDATION.json`. This verifies package installation into a
provisioned image; it does not claim fresh rooting or handset acceptance.

The real, full-size Z30 OS CAP was also rebuilt through the package path. The
output OS CAP and embedded UFS hashes equal their input hashes when all eight
payloads are already present. Independent checks cover all five partitions,
the trailer CRC, CAP stub/table, superblock CRC and 58 maintained payloads. See
`PACKAGE_CAP_VALIDATION.json` and `PACKAGE_CAP_IMAGE_VALIDATION.json`. The OS-only
input contained no radio; OS/radio preservation is exercised by synthetic tests
and the earlier real legacy batch qualification.

Synthetic CAP tests cover OS/radio rebuilds, preserved radio bytes, dependency
and ownership errors, changed locks/payloads, allocation failure, idempotence,
relative output paths and publication rollback. CI runs these on Linux, Windows
and macOS, with a manifest parser fuzz job. Hosted/native macOS results remain
separate qualification gates from local Windows and WSL checks.
