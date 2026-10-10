# v4-neo

Fresh BB10 firmware builds using the native Go bb10mt version pinned in
`neo.lock.json`. All host
runtime libraries are embedded in the six supplied executables; no Pascal tool,
Go installation, Python, shell wrapper or separate DLL installation is needed.
macOS binaries require macOS 14 or later.

## Build fresh firmware

Keep the original firmware. Choose a new output directory on a drive with at
least 10 GiB free for a typical Z30 build; highly sparse inputs can need more.

```powershell
.\bin\windows-amd64\bb10mt.exe patcher build -i 'D:\firmware\original.exe' -o 'D:\tmp\v4-neo-z30'
```

On Linux or macOS, or from any current working directory:

```sh
/path/to/v4-neo/bin/linux-amd64/bb10mt patcher validate
/path/to/v4-neo/bin/linux-amd64/bb10mt patcher build -i /path/to/original.exe -o /path/to/new-output
```

The Go CLI checks its pinned inputs and source manifests, applies the existing
foundation, verifies the final filesystem and compares autoloader contents,
and publishes once. It checks CAP/container CRCs, embedded filesystem equality,
payload SHA256, pathname checksums, superblock CRC and service permissions.
Radio output is produced only when the source includes a radio bundle.
`neo-acceptance.json`, `container-verification.json`, `neo-build.log` and
`SHA256SUMS` accompany the Go report and firmware files. Existing outputs are
never replaced. On failure, look for `<output>.failed.log`.

App World requires the QNX6 filename checksum for
`libAppWorldStoreFront.so.1.0.0` to be valid. A checksum repair to a loose `.ufs`
does not update an already packed `_os.exe`. The final gate rejects that stale
autoloader even when its container CRC passes; acceptance records
`embeddedUFSMatchesImage: true`. Build from the original firmware into a new
directory with the command above. Existing firmware outputs are not repaired
by updating this patcher folder.

On the investigated handset, native BBID sign-in completed successfully after
certificate enrollment and trust registration. The earlier boot certificate
warning did not require an account reset or a BBID binary change. See
[the investigation evidence](docs/HANDSET_BBID_APPWORLD_INVESTIGATION_2026-10-10.json).

Progress streams live with phase names, elapsed time, real hashing percentages
and five-second heartbeats during quiet work. Errors include a stable code and
a recovery hint; PowerShell preserves that code without an exception stack.
See [ERROR_CODES.md](docs/ERROR_CODES.md). `--output` is the **new build
folder itself**, not an existing parent: use `D:\tmp\v4-neo-z30` when `D:\tmp`
already exists.

## Extend with packages

Fresh rooting stays in `foundation/`. The initial public-data catalog under
`packages/` has three manifests: installed boot assertion, shared ISRG trust and
Weather. Its `weather.json` profile explicitly selects the boot prerequisite.
For an **already provisioned compatible** UFS or CAP:

```powershell
$tool = '.\bin\windows-amd64\bb10mt.exe'
& $tool packages validate --catalog .\packages
& $tool plan -i provisioned.ufs --catalog .\packages --profile .\packages\weather.json -o plan.json
& $tool build --plan plan.json -o new-package-output
```

Use `bin/linux-amd64/bb10mt`, `bin/linux-arm64/bb10mt`,
`bin/darwin-amd64/bb10mt`, `bin/darwin-arm64/bb10mt` or the Windows ARM64 tool
for another host. On Unix, run `chmod +x` on the selected executable if your
transfer method removed its executable permission. Package commands need only
the binary and catalog. Add a directory with `manifest.json` and payloads,
declare exact dependencies and file ownership, and select it in a profile.
See [PACKAGES.md](docs/PACKAGES.md) for the contract and authoring example.
V1 supports file overlays; root installation, BAR registration changes and
executable hooks need a dedicated adapter. Existing other app overlays remain
in the foundation baseline during this migration.

## Reproduce and verify

The maintained source is `D:\Downloads\v4_new`; the Go source and assembler
are in `D:\Projects\My\bb10mt`. From the Go repository:

```powershell
bb10mt patcher assemble --pack D:/Downloads/v4_new --release RELEASE_DIRECTORY --source . --source-commit REVISION -o D:/Downloads/v4-neo-next
go test ./internal/cli ./internal/batch
```

The native assembler requires a new destination and verifies release SHA256 values.
Use the selected macOS or ARM binary on those hosts. `--root PATH` selects an
explicit pack; otherwise the CLI finds it beside its bundled executable.
Host-side source-authoring and independent reference tests remain development
tools in the source repositories. They are not shipped or required to build.
Python payloads under `foundation/patchdata` run on BB10 and remain intact.
`neo.lock.json` pins the foundation and tools. Reassemble into a new folder to
update the foundation; package changes use their own manifests and new plans.
Keep previous snapshots and original firmware for rollback by rebuilding.
See [DESIGN.md](DESIGN.md) for the migration boundaries.

**Local private pack:** the preserved firmware foundation contains its existing
SSH host key. Do not publish this folder or firmware built from it as a public
release. The handset login private key `docs/ssh.pub` is excluded entirely.
This patcher performs offline builds; no device is flashed or accessed.
Handset acceptance and native macOS/ARM execution are separate checks.
