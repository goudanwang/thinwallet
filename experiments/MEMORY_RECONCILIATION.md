# Android-vs-WSL Memory Reconciliation

Status: **performance conclusions paused pending this reconciliation**.

## Conclusion

Classification: **E. Multiple causes jointly contribute**, specifically:

1. **B is the dominant cause: the measured process scopes differ.** The Phase 3
   WSL `full` run performs an additional unchanged-upstream-verifier
   preprocessing pass in the same process. This pass rebuilds the baseline
   relation, generators, and commitment while other proof objects are still
   live. The old Android A3 runner sets
   `THINWALLET_DEFER_UPSTREAM_VERIFY=1` and excludes that pass.
2. **A also applies: the code and build artifacts are not identical.** The
   Android and current WSL binary hashes and `Cargo.lock` hashes differ. The
   exact Android source-tree hash was not captured.

The causal toggle is decisive for H2:

| WSL H2 diagnostic scope | VmHWM MiB | Peak location |
| --- | ---: | --- |
| Current Phase 3 scope, 2048 MiB planner | 739.57 | `verification > commitment_prepare > commitment_local_msm` |
| Current Phase 3 scope, 224 MiB planner | 739.44 | same |
| Current Phase 3 scope plus phase-end `malloc_trim` | 739.70 | same |
| Android-equivalent scope (`DEFER_UPSTREAM_VERIFY=1`), 224 MiB planner | **204.19** | presentation path |
| Old Android H2 A3, five-run VmHWM range | **204.64--204.80** | presentation process |

Thus neither the 224-vs-2048 MiB planner setting nor allocator trimming explains
the 535 MiB gap. The extra verifier preprocessing pass does. The formal Phase 3
H1 and H2 peaks are both in the same nested verifier commitment phase:

| Formal Phase 3 run | VmHWM MiB | Anonymous RSS MiB | File RSS MiB |
| --- | ---: | ---: | ---: |
| H1 Full | 773.06 | 769.31 | 3.75 |
| H2 Full | 727.02 median; 739.57 in the diagnostic run | 735.95 diagnostic | 3.62 diagnostic |

The 727--773 MiB values must not be compared to the Android 205--210 MiB values
as if they measured the same presentation scope.

This reconciliation does **not** establish an Android OOM threshold or a minimum
phone-memory budget.

## Build And Workload Identity

`null` means that the old artifact did not record the field. It is not inferred
from a later snapshot.

| Field | Old Galaxy S23 Android A3 | Current formal WSL Full |
| --- | --- | --- |
| source-tree SHA-256 | `null` | `3e962046c1e4b1ea1b617c75ce79726315c8ea51327aca2bbbc072dc718f209a` |
| measured-run binary SHA-256 | `0b1f80eade84d1ebf2460f801ece0a1d013c6c81e333a23a38e6a4a580cc5ce9` | `2c7d00aba21816ae136aabe0e79631bd2b9173fc7330559a5d00167e52c2eeab` |
| `Cargo.lock` SHA-256 | `69f3b4aa8b4266d698f1b1e58a8d151e8670779f0586d6a95947a374df05b1af` | `c3c432c53d9a978884d3a66b6d9341611bfadec6496664ee0563ec8786d85ca0` |
| libspartan | `0.9.0`, fork label `libspartan-0.9.0-thinwallet-fs7` | `0.9.0`, PBMO backend revision `libspartan-0.9.0/curve25519-dalek-4.1.3` |
| enabled Cargo features | default plus `phase3ar2-deterministic-tests`; Android allocation tracker disabled | local patched and baseline forks with `phase3ar2-deterministic-tests` and `thinwallet-experiment` |
| runtime memory features | fixed, multi-target, active-state, transcript-recompute, streaming-dereference, credential-streaming | same six features |
| experiment mode | A3: malicious PBMO, FS7, local transport, upstream verifier deferred | Full: malicious PBMO, FS7, TCP transport, token lifecycle, upstream verifier cross-check in-process |
| instrumentation | external ADB `/proc` sampler; no in-process allocation tracker | `perf` phase/IO/memory instrumentation plus `/usr/bin/time -v` |
| allocator | Rust `System` over Android/Bionic | tracking allocator facade over glibc `System`; allocation tracing disabled unless explicitly requested |
| configured thread count | `RAYON_NUM_THREADS=1` | `RAYON_NUM_THREADS=1`, manifest thread count 1 |
| H1 constraints / padded size | 252,855 / 262,144 | 252,855 / 262,144 |
| H1 witness elements | 253,050 | 253,050 |
| H2 constraints / padded size | 223,955 / 262,144 | 223,955 / 262,144 |
| H2 witness elements | 224,170 | 224,170 |
| `q`, `m` | 512, 512 | 512, 512 |
| planner budget | 224 MiB for headline H1/H2 | 2048 MiB for Phase 3 matrix |
| temporary layout | `/data/local/tmp/thinwallet-v5a/temp/<run>/{v3a,v3b}` plus token state | WSL-native `/tmp/.../{opening,prover-state,token-store}` |
| state-store backend | file-backed V3A store and multi-object V3B store | same logical file-backed stores |
| data access | ordered `read`/`write` streaming with `posix_fadvise(DONTNEED)` | same; no production spill `mmap` |

The current reconciliation build adds only diagnostic observations. Its identity
is source-tree SHA-256
`1bdf76cd73bfc87f1ac509d5fab20c112451168988eaaa6ba0842499433dec5f`
and binary SHA-256
`b2cc8c40a0067a554c077c19bc195b7dc0f492c9298de0ba23a3ead99f295aae`.

### Android provenance limitation

The current `results/v5a/build/build_manifest.json` contains SHA-256
`760426c6...` for a `pbmo_diagnostic` artifact, while every measured Android
headline run records `0b1f80ea...` as its binary. The run records are used for
the measured binary identity; the build manifest does not close the source
provenance for that binary. Consequently, the old source-tree hash remains
`null`.

## Android Measurement Audit

The old 205--210 MiB result is a kernel `VmHWM` measurement, not Android
Profiler memory and not a lone sampled RSS value.

- The primary metric is `VmHWM` from `/proc/<pid>/status`.
- RSS, PSS, `Pss_Anon`, `Pss_File`, private dirty, and shared clean were sampled
  from `/proc/<pid>/status` and `/proc/<pid>/smaps_rollup`.
- The launcher publishes the child PID immediately after starting the binary.
  Sampling then continues until `/proc/<pid>/status` disappears.
- The first sample can occur after relation construction begins. Because
  `VmHWM` is cumulative, a peak before the first sample remains visible at every
  later successful sample.
- The monitored process covers relation construction, witness preparation,
  proving, proof serialization, patched proof verification, result writing,
  and process teardown.
- It does **not** include the deferred unchanged-upstream-verifier
  preprocessing pass.
- Host-side deletion of the temporary run directory occurs after process exit
  and is not part of process VmHWM.
- The configured sleep is 100 ms, but each iteration performs several ADB
  round trips. Effective intervals were 343.4--357.7 ms for H2 and
  365.0--375.6 ms for H1.
- The peak is read before process exit. Repeated runs report stable VmHWM:
  H1 210.04--210.11 MiB and H2 204.64--204.80 MiB.

The old Android PSS samples are not atomic with the preceding `/proc/status`
read, so PSS composition cannot be assigned to the exact instant at which
VmHWM was first established.

## WSL H2 Phase Accounting

This table is from
`reconcile-H2-full-2048-component-map`, a diagnostic-only run. For repeated
logical phases, `Calls` is the count, entry is the first entry, and exit is the
last exit. Component columns are exit values. All values are MiB.

| Phase | Calls | Entry RSS | Entry PSS | Exit RSS | Exit PSS | VmHWM | Anon PSS | File PSS | Private dirty | Shared clean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| relation setup | 1 | 2.62 | 1.47 | 137.59 | 136.34 | 152.91 | 134.55 | 1.79 | 134.55 | 1.48 |
| witness construction | 1 | 137.59 | 136.34 | 129.64 | 128.33 | 152.91 | 126.54 | 1.79 | 126.54 | 1.48 |
| prover initialization | 1 | 129.64 | 128.33 | 137.77 | 136.57 | 152.91 | 134.55 | 2.02 | 134.55 | 1.48 |
| PBMO token load | 1 | 137.89 | 136.71 | 137.89 | 136.73 | 152.91 | 134.55 | 2.19 | 134.55 | 1.48 |
| PBMO server wait | 1 | 92.06 | 91.01 | 92.06 | 91.11 | 152.91 | 88.91 | 2.20 | 88.91 | 1.48 |
| PBMO response decode | 1 | 92.06 | 91.01 | 92.06 | 91.11 | 152.91 | 88.91 | 2.20 | 88.91 | 1.48 |
| PBMO aggregate check | 1 | 92.06 | 91.11 | 92.31 | 91.34 | 152.91 | 89.14 | 2.20 | 89.14 | 1.48 |
| PBMO recovery | 1 | 92.31 | 91.34 | 92.31 | 91.34 | 152.91 | 89.14 | 2.20 | 89.14 | 1.48 |
| sumcheck | 2 | 132.31 | 131.34 | 204.31 | 203.42 | 204.31 | 201.14 | 2.29 | 201.14 | 1.48 |
| opening | 1 | 132.55 | 131.58 | 132.80 | 131.95 | 204.31 | 129.66 | 2.29 | 129.66 | 1.48 |
| external folding | 38 | 155.89 | 155.14 | 159.52 | 158.87 | 204.31 | 156.55 | 2.32 | 156.55 | 1.48 |
| proof serialization | 1 | 95.76 | 95.01 | 95.76 | 95.01 | 204.31 | 92.68 | 2.33 | 92.68 | 1.48 |
| verification | 1 | 95.76 | 95.01 | 63.25 | 62.38 | **740.38** | 59.70 | 2.67 | 59.70 | 1.48 |
| commitment prepare | 3 | 91.93 | 90.78 | 740.38 | 739.68 | **740.38** | 737.06 | 2.62 | 737.06 | 1.48 |
| local commitment MSM | 2 | 740.26 | 739.64 | 740.38 | 739.68 | **740.38** | 737.06 | 2.62 | 737.06 | 1.48 |
| native blinding | 3 | 92.31 | 91.34 | 740.38 | 739.68 | **740.38** | 737.06 | 2.62 | 737.06 | 1.48 |
| cleanup | 1 | 63.25 | 62.38 | 63.25 | 62.38 | 740.38 | 59.70 | 2.67 | 59.70 | 1.48 |

The repeated commitment phases include presentation commitments and the later
baseline-verifier encoding. The high final call is nested under
`verification`; it is not part of proof generation.

## Spill Mapping Audit

The approximately 944 MiB concurrent temporary state is **not mmap-mapped** by
the production prover path.

- `MultiObjectFileBackedStateStore` and `FileBackedStateStore` use bounded
  `read`/`write` streaming.
- `posix_fadvise(POSIX_FADV_DONTNEED)` runs after sealing, scans, and range
  reads. It is tied to object operations, not every phase boundary.
- `MmapReadOnlyStateStore` and `ReadOnlyMmapStateStore` exist as audit/test
  helpers, but no production call site opens them.
- Across every diagnostic phase-boundary map snapshot:
  - spill mapping virtual size: **0 bytes**;
  - spill mapping RSS: **0 bytes**;
  - spill mapping PSS: **0 bytes**;
  - resident spill pages: **0**;
  - lingering mapping from a completed spill phase: **none**.
- No `madvise` or explicit `munmap` is applicable to the production path.
  Rust drops open files and state-store objects at their expected lifetimes;
  state objects are truncated/unlinked by cleanup.

At the WSL diagnostic peak, all file mappings together used only 4.20 MiB RSS
and 2.81 MiB PSS. The largest were:

| Mapping | Virtual MiB | RSS MiB | Resident pages |
| --- | ---: | ---: | ---: |
| ThinWallet executable | 2.949 | 2.613--2.668 | 669--683 |
| `libc.so.6` | 2.109 | 1.219 | 312 |
| dynamic loader | 0.230 | 0.227 | 58 |
| `libgcc_s.so.1` | 0.125 | 0.082 | 21 |

## Diagnostic Controls

These controls are diagnostic only and are not paper results.

### Planner budget

Changing H2 from 2048 MiB to the Android headline value of 224 MiB changed
VmHWM from 739.57 to 739.44 MiB. The planner accepted both, but the verifier
cross-check peak was outside the streamed presentation path and was unaffected.

### Phase-end `malloc_trim`

The trim run reached 739.70 MiB VmHWM, so trimming did not prevent the peak.
It released memory only after a phase had already established the high-water
mark. Examples:

| Phase end | Pre-trim RSS MiB | Post-trim RSS MiB | Released MiB |
| --- | ---: | ---: | ---: |
| external folding | 148.51 | 66.43 | 82.08 |
| sumcheck | 204.02 | 148.04 | 55.97 |
| relation setup | 147.77 | 92.71 | 55.06 |
| local commitment MSM | 739.70 | 691.92 | 47.78 |
| verification | 50.03 | 14.31 | 35.71 |

### Explicit lifetime and unmapping

The implementation already explicitly drops the streamed relation before
proving and drops `decomm` and `inst` after patched verification. File-backed
state stores clean their objects through RAII. No spill mmap exists to unmap.
The extra baseline verifier's generators and encoded commitment necessarily
remain live until that cross-check completes; moving the cross-check to a
separate process or excluding it from presentation measurement changes
measurement scope, not the proof algorithm.

### Allocator comparison

The repository has no jemalloc or mimalloc feature, dependency, or global
allocator option. A jemalloc comparison is therefore unavailable. The tested
WSL allocator is glibc `System` behind the tracking facade. Android uses the
platform `System` allocator. The 204.19 MiB matched-scope WSL result shows that
allocator choice is not the dominant cause of the 740 MiB peak.

## Unified Memory Components

Components use PSS where available. Android values are the maximum sampled H2
PSS composition, not an atomic decomposition of its VmHWM. WSL values are from
the high verifier commitment phase. `null` is retained where the old sampler
did not capture individual mappings.

| Component | Android H2 A3 | WSL current scope | WSL Android-equivalent scope |
| --- | ---: | ---: | ---: |
| anonymous heap / allocator mappings | 196.11 MiB max sampled `Pss_Anon` | 737.06 MiB `Pss_Anon` | approximately 201 MiB aggregate anonymous RSS/PSS |
| explicit `[heap]` subset | `null` | 448.75 MiB PSS | `null` |
| thread stacks | `null` | 0.10 MiB PSS, 25 resident pages | `null` |
| code and shared libraries | at most 1.40 MiB `Pss_File` in sampled peak | 2.81 MiB file-map PSS | about 2--3 MiB |
| all file-backed mappings | 1.36--1.40 MiB around sampled peaks | 2.62--2.81 MiB PSS | about 2--3 MiB |
| spill-file resident pages | not mapped; `null` page count in old artifact | 0 MiB, 0 pages | 0 MiB, 0 pages |
| anonymous non-`[heap]` allocator mappings | not separately captured | about 288.21 MiB, derived from `Pss_Anon - [heap] - [stack]` | `null` |
| unknown / unattributed | exact simultaneous residual unavailable | below 1 MiB after aggregate accounting | exact split unavailable |

## Interpretation

The old Android and frozen desktop results already agreed closely: old desktop
H2 mean VmHWM was 204.03 MiB versus Android 204.71 MiB, and old desktop H1 was
216.85 MiB versus Android 210.08 MiB. That cross-platform agreement is
inconsistent with a 500+ MiB WSL file-cache effect.

The current Phase 3 run adds an in-process unchanged-verifier identity check.
Its baseline encoding invokes the same commitment instrumentation, and the
memory peak is observed exactly there. Deferring that check reproduces the old
Android memory level on current WSL.

Therefore:

- **D is rejected:** WSL file-backed or mmap residency is not the cause.
- **C is not supported for the matched presentation path:** current WSL returns
  to 204.19 MiB when measured with Android's verifier scope.
- **A and B remain true:** artifacts differ, and the measured lifecycle differs.
- The primary reconciliation is **measurement-scope mismatch caused by an extra
  in-process baseline verifier preprocessing pass**.

## Evidence

- `results/v5a/json/desktop_android_comparison.json`
- `results/v5a/raw/runs/headline_S_WK_k52_r1_d32_sparse_merkle_A3_224_r*/`
- `results/v5a/raw/runs/headline_S_WK_k8_r8_d32_sparse_merkle_A3_224_r*/`
- `results/raw/local-wsl-phase3/S-WK-k52-r1-d32-sparse_merkle/full/`
- `results/raw/local-wsl-phase3/S-WK-k8-r8-d32-sparse-merkle/full/`
- `results/memory-reconciliation/raw/local-wsl-memory-reconciliation/`
- `experiments/v5a-physical-android/scripts/invoke_android_workload.ps1`
- `experiments/v5a-physical-android/scripts/android_run_workload.sh`
- `experiments/libspartan/src/bin/phase_v2_pbmo.rs`
- `experiments/libspartan/vendor/spartan-0.9.0/src/state_store.rs`
- `experiments/libspartan/vendor/spartan-0.9.0/src/multi_state_store.rs`
