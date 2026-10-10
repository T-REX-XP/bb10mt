# v4-neo

Fresh BB10 firmware builds using the native Go bb10mt version pinned in
`neo.lock.json`. All host
runtime libraries are embedded in the six supplied executables; no Pascal tool,
Go installation or separate DLL installation is needed. Python **3.10+** is
required for the fresh-build wrapper's source checks and independent verifier.
macOS binaries require macOS 14 or later.

## Build fresh firmware

Keep the original firmware. Choose a new output directory on a drive with at
least 10 GiB free for a typical Z30 build; highly sparse inputs can need more.

```powershell
.\build.ps1 -InputFirmware 'D:\firmware\original.exe' -OutputDirectory 'C:\firmware\v4-neo-z30'
```

On Linux or macOS, or from any current working directory:

```sh
python3 -B /path/to/v4-neo/build.py validate
python3 -B /path/to/v4-neo/build.py fresh -i /path/to/original.exe -o /path/to/new-output
```

The wrapper checks its pinned inputs, runs source preflight, applies the existing
foundation with Go, independently verifies the final filesystem and autoloaders,
and publishes once. It checks CAP/container CRCs, embedded filesystem equality,
payload SHA256, pathname checksums, superblock CRC and service permissions.
Radio output is produced only when the source includes a radio bundle.
`neo-acceptance.json`, `container-verification.json`, `neo-build.log` and
`SHA256SUMS` accompany the Go report and firmware files. Existing outputs are
never replaced. On failure, look for `<output>.failed.log`.

Progress streams live with phase names, elapsed time, real hashing percentages
and five-second heartbeats during quiet work. Errors include a stable code and
a recovery hint; PowerShell preserves that code without an exception stack.
See [ERROR_CODES.md](docs/ERROR_CODES.md). `OutputDirectory` is the **new build
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
python -B scripts/assemble_v4_neo.py --pack D:/Downloads/v4_new --release out/dist-packages -o D:/Downloads/v4-neo
python -B -m unittest discover -s patchers/v4-neo/tests
```

The assembler requires a new destination and verifies release SHA256 values.
`neo.lock.json` pins the foundation and tools. Reassemble into a new folder to
update the foundation; package changes use their own manifests and new plans.
Keep previous snapshots and original firmware for rollback by rebuilding.
See [DESIGN.md](DESIGN.md) for the migration boundaries.

**Local private pack:** the preserved firmware foundation contains its existing
SSH host key. Do not publish this folder or firmware built from it as a public
release. The handset login private key `docs/ssh.pub` is excluded entirely.
This patcher performs offline builds; no device is flashed or accessed.
Handset acceptance and native macOS/ARM execution are separate checks.
