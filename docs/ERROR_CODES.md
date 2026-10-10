# Validation, errors and progress

| Exit | Name | Meaning / recovery |
|---:|---|---|
| 0 | SUCCESS | Verified operation completed. |
| 2 | USAGE | Missing/unknown command or options; use `--help`. |
| 3 | INPUT_INVALID | Missing, unreadable or incompatible input; choose the original supported firmware. |
| 4 | OUTPUT_EXISTS | Existing output is preserved; choose a **new** file/subfolder. |
| 5 | VALIDATION_FAILED | Source, manifest, compatibility or integrity checks failed; inspect details and restore/reassemble the expected inputs. |
| 6 | DISK_SPACE | Free space or select another output/temp volume. |
| 7 | TOOL_FAILED | Child build/compiler failed; the diagnostic includes its exit status. |
| 8 | VERIFICATION_FAILED | Final artifact checks failed; do not use that output. |
| 9 | IO_FAILED | Filesystem access/publication failed; check permissions and the reported path. |
| 10 | VERSION_FAILED | Version reservation failed or attempted reuse; keep the counter state and request the next version. |
| 130 | INTERRUPTED | Build interruption requested; stop at the next safe boundary and remove private staging. |

The Go CLI uses these code meanings. Error text can become more detailed
without changing the codes. Native v4-neo builds preserve progress and failure
details in `<output>.failed.log`, without replacing an earlier log. Run the
binary directly from PowerShell, Linux or macOS; no host wrapper is required.

For example, an existing `D:\tmp` produces `ERROR [OUTPUT_EXISTS:4]` and suggests
`D:\tmp\v4-neo-z30`. Existing folders are never deleted or emptied automatically.

Before fresh builds, v4-neo checks the CAP header/table, output path, minimum
working space, pinned snapshot/tool hashes, source contracts and package
catalog. Filesystem/CRC/payload checks remain enabled during and after patching.
The final native gate compares the packed UFS, non-UFS partitions, radio,
all maintained payload hashes, pathname checksums and exact script permissions.

Progress names the current phase and elapsed time. Native batch output includes
input validation, extraction, source repair, patching, QCFM packing, OS/radio
creation and publication. The CLI streams updates immediately,
reports real hashing percentages and emits a heartbeat every five quiet seconds.
An operation with no meaningful denominator reports elapsed time rather than
a fabricated percentage. A successful fresh build saves its snapshot alongside
the acceptance report, complete log and SHA256 inventory.
