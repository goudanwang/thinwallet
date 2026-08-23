# Phase V3E Dereference Peak Audit

## Scope

This phase modifies the desktop WSL FS5 prover path only. It does not evaluate
Android and does not establish production-mobile feasibility.

The V3D source and evidence are frozen under
`archive/phase_v3d_transcript_recompute/` with archive SHA-256
`08334cc95f6438e29528219780a6a672cf90234663b97ea07d6b79e65b3247d9`.
Status: `PHASE_V3D_TRANSCRIPT_RECOMPUTE_FROZEN`.

## FS5 Boundary

The unchanged FS5 planner and 111 MiB runtime reserve were tested at 288, 280,
272, 264, 260, and 256 MiB. 288 through 264 MiB completed. At the exact
boundary, 264 MiB completed 5/5 with peaks
`[262524, 262444, 262524, 262524, 262372]` KiB. 260 MiB produced a controlled
planner rejection 5/5; there was no allocation failure or OOM kill.

Status: `FS5_EXACT_LOW_MEMORY_BOUNDARY_COMPLETE`.

## Peak State

At `N = 2^18`, FS5's avoidable dereference overlap consisted of 48 MiB of six
per-table Scalar copies and a 64 MiB padded joint polynomial. FS6 instead
retains two 8 MiB equality source tables. The net logical reduction is 96 MiB.
The exact object inventory, capacities, producers, consumers, and access order
are in `experiments/v3e/peak_dereference_state.json`.

The remaining dense matrix values occupy 24 MiB. They have no independent
compact source after encoding and are consumed both by dot-product circuits and
the transcript-dependent source-fused opening. Their lifetime was therefore not
shortened in this phase: `DENSE_MATRIX_VALUE_BACKEND_BLOCKED`.

## FS6 Pipeline

The canonical flow is:

```text
compact address + equality source
  -> canonical dereference scalar
  -> commitment MSM row / product hash / query accumulator
  -> release the bounded consumer buffer
```

No complete dereferenced vector or dereference file is created. Commitment uses
a 64 KiB MSM row buffer. Product construction regenerates values directly.
Dot-product construction materializes at most one row and one column table
(16 MiB total), then releases them. The late opening regenerates source values
directly into a 64 KiB prebound accumulator.

Chunk identity remains bound by the existing session, object metadata,
reconstruction version, and transcript challenge checks. Canonical table and
field-operation order are unchanged.

Statuses:

- `STREAMING_DEREFERENCE_PIPELINE_PASS`
- `DEREFERENCE_OPENING_FUSION_PASS`
- `STREAMING_QUERY_WEIGHT_GENERATION_PASS`
- `THINWALLET_PHASE_LOCAL_ARENA_PASS`

Query weights are generated one at a time in Boolean-index order and applied to
all current table accumulators. No `N`-element query-weight table is collected.
The accounted phase arena peaked at 25,165,824 bytes and returned to zero.

## Runtime Residual

The final uncapped probe used one thread, zero swap, a 135,168-byte reserved
stack mapping, and at most 3,072 KiB file RSS. The available `/proc` samples do
not separate allocator-retained pages, relation/transcript overlap, and curve
scratch precisely. The old 57,802,752-byte anonymous residual therefore remains
`FS5_ANONYMOUS_RESIDUAL_INCONCLUSIVE`; no unsupported byte attribution is made.

## Planner And Gate

The FS6 planner predicts 251,133,952 bytes. The final five 256 MiB headline
peaks were `[245444, 245432, 245200, 245568, 245364]` KiB, with mean 245,401.6
KiB. The maximum measured peak was 251,461,632 bytes, prediction error 0.13%,
and minimum safety margin 16,973,824 bytes (16.19 MiB).

All five runs completed without budget violation, allocation failure, OOM,
swap, or unbounded mmap. All tokens reached `SPENT`. The proof was 120,136 bytes
with SHA-256
`e6360f619150e8141d4645a18da7d781ee84818f273cd093a088638d97b3bf8e`.

Status: `THINWALLET_2P18_UNDER_256M_FS6_PASS`.

The planner does not predict the required 8 MiB margin at 240 MiB, so that run
was not attempted: `THINWALLET_2P18_UNDER_240M_NOT_ATTEMPTED`.

## I/O And Latency

FS5 read 1,979,649,600 bytes and wrote 989,834,432 bytes. FS6 read
1,811,877,440 bytes and wrote 989,834,432 bytes. Under the recorded definition
`(read + write) / write`, amplification fell from 3.00x to 2.83x. Source-fused
opening avoided 167,772,160 read bytes. Temporary storage fell from
578,949,319 to 411,040,768 bytes.

FS5 mean wall latency was 37,862.14 ms. Final FS6 wall times were
`[39340.855, 39238.554, 39756.899, 39219.864, 39836.397]` ms, mean
39,478.51 ms. The ordinary 40-second target passed; the 35-second strong target
did not.

## Equivalence And Security

The fixed `2^12` FS1/FS5/FS6 transcript has 6,906 events and SHA-256
`a68a34b2fe71ba5518b6b8866e16888845f623b32ca19d373532ce17ee7cdaf2`.
The fixed proof SHA-256 is
`a9b8bd3cc9f02c254e7990e81a38c5d8948383e3463970084978500cf617434a`.
The five `2^18` proofs are byte-identical to FS5, and the unchanged upstream
verifier accepts all of them.

Final regression: libspartan 54/54 plus 3/3 doc tests, PBMO 9/9, streaming
integration 4/4, and crash semantics 1/1 passed. Tampered metadata, reordered or
cross-session chunks, reconstruction-source changes, invalid proofs, token
reuse/crash behavior, and abort cleanup remain covered. The limitation
`SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED` remains in force.

Primary classification:
`PHASE_V3E_256M_STREAMING_DEREFERENCE_PASS`.
