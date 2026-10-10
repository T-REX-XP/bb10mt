# Windows Z30 performance investigation

Measured on 2026-10-10 with the same 3,073,914,372-byte stock Z30 autoloader and
identical `foundation/patch.txt`. Go release **v0.7.0-go.5** includes the fixes.

| Native batch | Measured seconds | Average |
|---|---|---:|
| Original Pascal tool, clean runs | 35.7, 57.8, 49.7 | 47.7 s |
| Previous bundled Go v0.7.0-go.3 | 103.3, 205.2 | 154.3 s |
| Final bundled Go v0.7.0-go.5 | 69.9, 60.3 | 65.1 s |

The final Go build took **57.8% less time** on average than old Go
(2.37 times the throughput on this fixed workload).
It remains slower than the original in the clean runs. In the final clean reverse
pair, Go took 60.3 s and the original took 49.7 s. The original also took
87.5 s during an overlapping Linux snapshot-validation run; that observation is
retained in the raw data but excluded from the clean summary above.

These are sequential native `batch` runs, with direct stdout/stderr redirection,
new output folders, alternating order and natural OS caches. No compiler or test
suite ran during the Go timing runs. Timings include the delivered executable's
runtime verification and launch. They exclude wrapper source preflight,
independent verification and output SHA256 generation. The first timestamped,
line-by-line diagnostic runs (171/262 s) are not the comparison baseline.
Disk/cache variation is substantial: these measurements establish the regression
and improvement on this Windows machine, not universal Linux/macOS/SSD results.

## Root cause and evidence

1. Bulk `io.CopyN` transfers through `SectionReader` used small reads. The old
   profile attributed 85.5% of samples to the Windows native-call bridge and
   51.27 s to QCFM extraction. Windows `ReadAt` crosses the OS I/O boundary;
   the Go 1.27.2 `internal/poll/fd_windows.go` implementation also saves/restores
   position for blocking file handles. Repeating this for tens of thousands of
   small reads made multi-gigabyte copies expensive.
2. `Editor.writeAt` cleared the entire 512-block metadata cache for every write.
   Recursive removals repeatedly reread unchanged ancestor directories and inode
   blocks. The baseline profile attributed 34 s to recursive `Remove` calls.
3. QCFM sparse discovery and serialization issued one 64 KiB file operation per
   block. The remaining profile exposed this second small-I/O path after fixing
   the larger copies.

Filename checksum calculation itself was only **0.12%** of baseline samples.
The performance regression did not justify removing checksum or filesystem checks.

## Implemented changes

* `internal/binio/copy.go`: exact bounded transfers with pooled 4 MiB buffers;
  optional small-buffer fast paths are deliberately hidden. An 8 MiB fixture
  requires 2 reads instead of 256, with short-read/write failures preserved.
* `internal/qnx6/edit.go`: evict only cached blocks overlapping a successful
  write. A boundary-crossing test proves both touched blocks are invalidated
  and the untouched block stays cached.
* `internal/qcfm/write.go`: buffer discovery reads and serialize entire sparse
  runs in bulk. Preserve erased gaps, final partial-block padding, source-change
  detection and trailer CRC. Tests compare a multi-buffer image with a sparse
  gap and partial tail byte for byte.
* Use the bulk helper for CAP extraction/creation, filesystem transactional
  copies, source repair and CRC rereads. Retain private staging, filesystem
  checks, source/payload hashes, sync and atomic no-replace publication.

The before/after initial-fix profiles took **159.4 / 29.8 s**. UFS extraction
fell from **62.3 / 2.2 s**, source repair from **33.7 / 5.3 s**, and patching
from **32.6 / 9.1 s**. These profiles are diagnostic evidence, separate from the
repeated delivered-binary comparison above. The profile after the initial fixes
still preceded the final QCFM buffering change.

Go also performs validation and durable working-copy writes absent from raw
legacy batch. Those operations remain in the timed result and contribute to
its remaining cost; their exact share under variable disk load was not isolated.
The maintained legacy wrapper additionally repairs filename checksums and
repacks its first OS output. Raw legacy batch time therefore does not represent
that full verified workflow.

## Reproduce and inspect

With Python 3.11+, use `scripts/benchmark_batch.py --input STOCK.exe --script
PATCH.txt --tool original=ORIGINAL.exe --tool go=GO.exe --rounds 2 --output
NEW_BENCHMARK_DIRECTORY`. Keep all inputs, hardware and comparison scope equal.

For CPU profiles, set `BB10MT_PROFILE_INPUT`, `BB10MT_PROFILE_SCRIPT` and
`BB10MT_PROFILE_OUTPUT`, then run `go test ./internal/batch -run
'^TestProfileRealBuild$' -count=1 -cpuprofile PROFILE.pprof -v`.

Machine-readable records, hashes and all raw timings are in
[PERFORMANCE_VALIDATION.json](PERFORMANCE_VALIDATION.json). Logs and profiles
remain under `D:/Downloads/v4-neo-benchmark`; temporary firmware copies also remain because automatic approval review blocked
recursive cleanup. The final independent firmware acceptance report is
recorded separately in `V4_NEO_VALIDATION.json`.
