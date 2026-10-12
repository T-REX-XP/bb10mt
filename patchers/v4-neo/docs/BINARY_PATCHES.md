# File binary patches

The native patcher supports exact byte edits and compact base-to-target file
deltas offline, without SSH or a handset connection. Both apply through the
same QNX6 transaction used by full firmware builds. Existing payload overlays
and OS/radio builds retain their behavior; they are not converted automatically.

## Compact file deltas

```powershell
$tool = '.\bin\windows-amd64\bb10mt.exe'
& $tool binary diff --base 'D:\tmp\original.so' -i 'D:\tmp\patched.so' -o 'D:\tmp\library.bbd'
& $tool binary apply -i 'D:\tmp\original.so' --patch 'D:\tmp\library.bbd' -o 'D:\tmp\reconstructed.so'
```

Inputs are regular files up to 64 MiB. Outputs must be new files. The generator
serializes, decodes and reconstructs the patch before publication, comparing
every target byte. Application verifies the whole original size/SHA256 and the
whole resulting size/SHA256. A mismatch leaves no published output.

The format is **BB10MT delta v1**, not BSDIFF/VCDIFF or Red Bend OTA. Its prefix is
`BB10MT-DELTA-1` plus LF, followed by one gzip member containing a JSON document.
The document records `schemaVersion: 1`, `kind: "delta"`, `baseSha256`,
`targetSha256`, `baseSize`, `targetSize` and ordered `chunks`. Each chunk is either
`{"offset": N, "length": N}` copying original bytes, or `{"data": "BASE64"}`
inserting literal bytes. Omitted copy offset means zero. Target bytes concatenate
in chunk order. Resizing and moved spans are supported. The generator indexes
64-byte source blocks and compresses literals; it does not promise the smallest
possible patch, and unrelated inputs can produce a patch larger than the target.

## Precise byte edits

Create a UTF-8 JSON recipe, replacing the hash placeholders with actual SHA256:

```json
{
  "schemaVersion": 1,
  "kind": "edits",
  "baseSha256": "SHA256_OF_ORIGINAL_FILE",
  "targetSha256": "SHA256_OF_EXPECTED_RESULT",
  "baseSize": 4096,
  "targetSize": 4096,
  "edits": [
    {"offset": 128, "expectedHex": "0102ff00", "replacementHex": "030400ff"}
  ]
}
```

Offsets are decimal, zero-based file offsets. Edits must be sorted,
nonoverlapping, in range, nonempty and equal length. Each expected byte must
match the original. Use `binary apply` with this JSON as `--patch` to verify it
against a local file. Duplicate/unknown fields, wrong hashes, invalid ranges,
trailing data and malformed compressed patches are rejected. Maximum document
size is 96 MiB and maximum edits/chunks is 131,072.

## Firmware scripts and packages

Add this command to a firmware patch script, using the real installed app path:

```text
binarypatch /apps/com.example.opaque/native/libexample.so "patches/library.bbd"
```

The second argument accepts either format. Relative paths resolve beside the
script. The target must be an existing, unshared regular file. QNX6 ownership,
permissions and inode identity are retained. All commands remain transactional:
a failed patch publishes no new image. A raw script recipe requires the exact
original, so applying it twice fails; package builds skip an already desired
binary and remain idempotent.

For a declarative package, use a `binary-patch` operation with:

```json
{
  "type": "binary-patch",
  "path": "app:/com.example/native/libexample.so",
  "source": "patches/library.bbd",
  "patchSha256": "SHA256_OF_PATCH_FILE",
  "sha256": "SHA256_OF_RESULTING_BINARY",
  "originalSha256": ["SHA256_OF_ORIGINAL_BINARY"],
  "allowAbsent": false,
  "mode": "0755",
  "uid": 0,
  "gid": 0
}
```

Declare the path in `owns`, then validate/plan/build as in [PACKAGES.md](PACKAGES.md).
There must be exactly one original hash and it must match the recipe. Existing
package namespace, foundation, dependency and file-ownership restrictions apply.
The lock pins the patch file separately from the reconstructed file. Packages
verify final mode/uid/gid against the manifest after applying the patch.

## Relationship to the original flasher

These file patches are consumed on the build computer. The original CAP flasher
cannot apply them directly. Reconstruct/build the target firmware, then use the
experimental `autoloader delta` command if investigating block updates.

The previously measured 44,380,812-byte EXE contains a 9,252,464-byte original
flasher plus 35,127,296 bytes of changed blocks and 1,052 bytes of container/table
overhead. Even a one-byte edit includes its whole 64 KiB block; filesystem
metadata and neighboring data also contribute. Smaller file patch downloads do
not automatically shrink that executable. See [PATCH_ONLY_AND_OTA.md](PATCH_ONLY_AND_OTA.md)
for its untested flash/erase boundaries. File patch tests do not establish
handset acceptance or create an OEM-signed OTA package.
