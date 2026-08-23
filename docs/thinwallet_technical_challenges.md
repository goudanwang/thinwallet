# ThinWallet Technical-Challenge Ledger

This ledger preserves the detailed engineering record. The four paper groups
are a separate drafting view and do not replace TC1-TC18.

## TC1: EMSM Is Not a Complete Memory-Bounded Prover

**Problem.** Outsourcing MSM group work did not bound whole-prover memory.
**First observed.** Phase 2A. **Failed approach.** Treating the largest MSM as
the only peak. **Root cause.** Sumcheck, MLE and relation state remained live.
**Resolution.** Whole-prover tracing and later FS2-FS7 streaming. **Measured
effect.** The bottleneck moved from group work to field-domain state rather than
disappearing. **Residual.** Backend-wide lifetimes remain workload dependent.
**Sources.** `experiments/preprocessed-pbmo/src`, patched libspartan memory
tracing. **Artifacts.** Phase 2/V3 memory results. **Paper lesson.** Prove
end-to-end resource bounds, not operator-local savings.

## TC2: Fragmented Commitments Create Many Exact MSM Outputs

**Problem.** Hyrax/libspartan maps one vector to `q` exact small outputs.
**First observed.** Phase 3A-R2.5. **Failed approach.** Correcting one logical
aggregate MSM. **Root cause.** The verifier transcript consumes each fragmented
point. **Resolution.** PBMO models the complete output vector and exact ordering.
**Effect.** Adapter correctness became measurable; correction bandwidth exposed
as uneconomical. **Residual.** `q` remains a protocol cost. **Sources.** patched
`dense_mlpoly.rs`, PBMO commitment adapter. **Artifacts.** Phase 3A/V0 audits.
**Paper lesson.** PCS output shape constrains delegation.

## TC3: Correlated Public-Linear Masks Leak Relations

**Problem.** Identical, low-rank and publicly mixed masks reveal row relations.
**First observed.** V0/V1. **Failed approach.** Reusing a short mask basis.
**Root cause.** Public linear cancellation preserves private differences.
**Resolution.** Rejected these formats and required independently secure
preprocessed correlation. **Effect.** V1 classified the shortcuts NO-GO.
**Residual.** Preprocessing cost and lifecycle. **Sources/artifacts.** PBMO V0/V1
theory and negative tests. **Paper lesson.** Compression must be proved against
the joint output distribution.

## TC4: Matrix-RAA Remains Distinguishable

**Problem.** Keyed sparse Matrix-RAA leaked structure. **First observed.** V1.
**Failed approach.** Invertible row/column mixing. **Root cause.** Rank and
sparse-core invariants survive invertible transforms. **Resolution.** Removed it
from the mainline in favor of preprocessed PBMO. **Effect.** Prevented a false
privacy claim. **Residual.** No online public-linear replacement. **Sources.**
V1 audit. **Artifacts.** distinguishers and classification JSON. **Paper
lesson.** Obfuscating representation is not hiding the linear algebra.

## TC5: PBMO Tokens Must Be One-Time

**Problem.** Reuse cancels masks across sessions. **First observed.** V2.
**Failed approach.** Reusable preprocessing records. **Root cause.** Correlated
outputs expose differences. **Resolution.** Typed token state and duplicate-ID
rejection. **Effect.** Reuse security tests pass. **Residual.** Requires durable
state. **Sources.** `experiments/preprocessed-pbmo/src`. **Artifacts.** token
security regression. **Paper lesson.** One-time state is protocol state.

## TC6: Reservation Must Precede Network Release

**Problem.** A crash after sending masked bytes could leave a reusable token.
**First observed.** V2/V3. **Failed approach.** Mark-used after the call.
**Root cause.** External effects crossed the durability boundary. **Resolution.**
Reserve and fsync before first masked byte. **Effect.** crash-injection tests
retain spent/reserved state. **Residual.** Filesystem guarantees are platform
specific. **Sources/artifacts.** token store/journal and crash tests. **Paper
lesson.** State-machine ordering is part of malicious security.

## TC7: Complete Software Snapshot Rollback Is Undetectable

**Problem.** An attacker can restore keys, counters and valid state together.
**First observed.** V2D. **Failed approach.** A local authenticated journal alone.
**Root cause.** No non-rollbackable external anchor. **Resolution.** Explicit
`SOFTWARE_ONLY_SNAPSHOT_ROLLBACK_NOT_PREVENTED` boundary. **Effect.** Narrowed
claims. **Residual.** Needs hardware or remote monotonic state. **Sources.** token
and credential-source journals. **Artifacts.** rollback tests. **Paper lesson.**
Integrity and freshness are distinct.

## TC8: Memory Moves to Field-Domain State

**Problem.** After MSM outsourcing, Sumcheck/MLE state dominates. **First observed.**
V3A. **Failed approach.** More MSM tuning. **Root cause.** Multiple
O(N) field vectors overlap. **Resolution.** Spill, streaming folds and
recomputation. **Effect.** Approximate peak fell from 975-999 MiB to later
boundaries. **Residual.** I/O and recomputation latency. **Sources/artifacts.**
memory traces and FS2-FS7 runs. **Paper lesson.** Optimize the peak-live cut.

## TC9: Allocation-Level Attribution Is Required

**Problem.** Process RSS did not identify the failing owner. **First observed.**
V3A. **Failed approach.** Stage timers alone. **Root cause.** Lifetime overlap
and allocator/page-cache effects. **Resolution.** Tagged allocator traces and
operator graph. **Effect.** Located the actual OOM cut. **Residual.** Accounted
memory differs from RSS/PSS. **Sources.** `memory_trace` and attribution docs.
**Artifacts.** V3A/V4D snapshots. **Paper lesson.** Report both logical and OS
metrics.

## TC10: Single-Object Spill Is Insufficient

**Problem.** Spilling one vector left other targets live. **First observed.**
V3B. **Failed approach.** Largest-object-only spill. **Root cause.** Peak is a
multi-object cut. **Resolution.** Multi-target retain/spill/recompute planner.
**Effect.** FS3 reached about 502 MiB. **Residual.** Planner calibration depends
on relation shape. **Sources/artifacts.** budget planner and V3B plans. **Paper
lesson.** Memory scheduling is a global optimization problem.

## TC11: Fiat-Shamir Barriers Limit Fusion

**Problem.** Later coefficients depend on transcript challenges. **First observed.**
V3C/V3D. **Failed approach.** Fuse coefficient and fold passes
arbitrarily. **Root cause.** Challenges are unavailable before transcript
messages. **Resolution.** Barrier-aware pass scheduling. **Effect.** Preserved
transcript bytes while streaming. **Residual.** Extra passes. **Sources.**
streaming sumcheck/fold code. **Artifacts.** transcript identity fixtures.
**Paper lesson.** Cryptographic dependencies constrain systems scheduling.

## TC12: Active Layers Need External Folds

**Problem.** Active Sumcheck/product layers retained large double buffers.
**First observed.** FS4. **Failed approach.** Spill only inactive inputs.
**Root cause.** Fold outputs are themselves O(N). **Resolution.** External folds,
bounded double buffering and canonical arithmetic order. **Effect.** Peak about
366 MiB. **Residual.** Temporary I/O. **Sources/artifacts.** streaming fold and
FS4 traces. **Paper lesson.** Streaming must enter active algebraic kernels.

## TC13: Late Transcript State Needs Deterministic Recomputation

**Problem.** Some values are consumed only after later challenges. **First observed.**
FS5. **Failed approach.** Retain all late-use vectors. **Root cause.**
Transcript dependency prevents early finalization. **Resolution.** Checkpointed
deterministic recomputation. **Effect.** Reached about 256 MiB. **Residual.** CPU
and read amplification. **Sources/artifacts.** FS5 checkpoint code/results.
**Paper lesson.** Recomputation is safe only with canonical transcript replay.

## TC14: Token Durability and Spill Durability Differ

**Problem.** One durability policy over-synced regenerable state or under-synced
tokens. **First observed.** FS5. **Failed approach.** Uniform fsync. **Root cause.**
PBMO tokens are non-replayable; prover spill is regenerable. **Resolution.** Two
durability classes. **Effect.** Kept token safety without paying fsync for every
spill. **Residual.** Crash cleanup still required. **Sources/artifacts.** token
journal, state store, durability metrics. **Paper lesson.** Classify state by
security semantics before persistence policy.

## TC15: Dereferenced and Opening Vectors Must Stream

**Problem.** Full dereferenced and joint-opening vectors stayed live. **First observed.**
FS6. **Failed approach.** Materialize then consume. **Root cause.**
Producer/consumer APIs forced duplicate O(N) buffers. **Resolution.** Iterators
and consumer fusion. **Effect.** Synthetic peak about 240 MiB. **Residual.** Some
backend structures remain materialized. **Sources/artifacts.** FS6 code and
identity traces. **Paper lesson.** API shape controls attainable memory bounds.

## TC16: Memory Metrics Are Not Interchangeable

**Problem.** RSS, PSS, VmHWM, cgroup, allocator and temporary bytes disagreed,
and the V4F planner generalized poorly despite accurate earlier phase-local
measurements. **First observed.** V3/V4D; independent planner failure in V4F.
**Failed approach.** One total-memory formula and cap-saturated cgroup peaks as
regression targets. **Root cause.** Process anonymous memory, file-backed pages,
reclaimable spill cache, fixed runtime reserve and allocator state have distinct
accounting and lifetimes. **Resolution.** V4G predicts process VmHWM by phase and
uses a separate conservative cgroup admission model. Fixed reserve, file pages,
and allocator-retained state are reported separately. **Effect.** New held-out
max error is 2.802% with 0.962% MAPE; the original seven max error falls from
14.853% to 2.985%. **Residual.** The cgroup model has no 5% accuracy claim and
some kernels omit PSS detail. **Sources/artifacts.** V4G cgroup diagnostics,
frozen model, held-out tables and `v4g_cgroup_accounting_analysis.md`.
**Paper lesson.** Name the metric, phase, and cap mechanism for every result.

## TC17: Real Credential Construction Adds Peaks

**Problem.** Synthetic-size and padded-n-only relations omitted witness, sparse
R1CS, MiMC, revocation, and finalization/proving lifetime changes. **First
observed.** V4B/V4C; quantified by V4F held-out residuals of 1.20%, 1.38%,
1.87%, 14.85%, 9.04%, 11.14%, and 1.20%. **Failed approach.** Extrapolate a
single total from boolean multiplication or padded n. **Root cause.** `k`, `r`,
sparse-entry capacity, mode, and finalization overlap independently change the
peak. **Resolution.** Profiles M/S plus a V4G phase-aware workload/mode model
with explicit padding boundaries and disjoint calibration/validation sets.
**Effect.** The new precommitted ten-point set passes at 2.802% maximum error,
0.962% MAPE, and 100% phase accuracy. **Residual.** Physical-device behavior is
unmeasured. **Sources/artifacts.** Credential builders, V4G model, residual
analysis and tables. **Paper lesson.** Use useful relations and held-out phase
models before making systems claims.

## TC18: Composition and Revocation Are Independent

**Problem.** `WK(k,d)` hid how many credentials had revocation predicates.
**First observed.** V4E semantic audit. **Failed approach.** Treat depth as the
only revocation dimension. **Root cause.** Historical fixture had `k=52` but
`r=1`. **Resolution.** `WK(k,r,d,RevBackend)`, canonical `RevSet`, separate
`WC(k)` and `WR(r)`. **Effect.** Measured relation shapes now attribute 23,428
raw constraints per depth-32 check in the current fixture. **Residual.** The
V4F FS7 desktop scaling matrix is complete, but the memory planner failed its
independent 5% validation target and no physical-device evaluation exists.
**Sources.** Profile S workload, credential source, and V4F evaluation scripts.
**Artifacts.** V4E semantic audit JSON plus V4F composition/revocation and
planner-validation tables. **Paper lesson.** Parameterize orthogonal policy
dimensions explicitly and validate resource models on held-out workloads.

`PLANNER_TECHNICAL_CHALLENGE_RECORDS_UPDATED`

## V5A Physical Android Addendum

**TC16.** On the measured Galaxy S23, process VmHWM and sampled PSS differ
materially; Android page cache and system zram are separate from process
VmSwap. Every headline A3 run had process VmSwap zero. Planner budgets were
admission values, not cgroup limits. The Android held-out model passed 39
validation points over four padded sizes at 1.558% maximum error and no unsafe
admission.

**TC17.** Physical ARM64 relation construction preserved workload semantics.
Mean A3 VmHWM was 10.73 MiB (S-W1), 17.85 MiB (S-W4), 48.07 MiB (H0),
210.08 MiB (H1), and 204.71 MiB (H2). H1/H2 each used about 948 MiB observed
temporary storage, showing that low process memory does not remove external-I/O
cost.

**TC18.** Composition and revocation fixtures completed unchanged on the
device, including H1 `WK(52,1,32,SparseMerkle)` and H2
`WK(8,8,32,SparseMerkle)`. Token lifecycle diagnostics passed, but controlled
OS crash/network interruption and a real PBMO transport were unavailable.
Physical execution is established while the full mobile integration gate
remains incomplete.

`ANDROID_TECHNICAL_CHALLENGE_RECORDS_UPDATED`

## V5B Real-Network And Crash Addendum

**TC6.** On the physical Galaxy S23, durable reservation occurred before the
first masked byte. Ten required `adb shell kill -9` positions and an additional
H0 reservation kill produced the expected `AVAILABLE`, `BURNED`, or `SPENT`
restart states. Seven required real-Wi-Fi interruption points and one H1 long
upload interruption likewise burned every uncertain session. Burned and spent
token replay attempts exited nonzero without emitting a proof.

**TC14.** Real-kill recovery removed regenerable V3A/V3B prover spill while
retaining the security-critical token journal. Successful runs returned to
zero temporary bytes. Crash cases retained a documented bounded recovery store
of 23,552 bytes for S-W4, 27,648 bytes for H0, and 35,840 bytes for H1; no stale
partial prover state was reused.

**TC16.** The TCP client used 131,072-byte send and receive buffers and a
2,072-byte peak serialization buffer rather than a second full masked request.
Mean VmHWM changes relative to V5A were +0.089 MiB (S-W4), +0.119 MiB (H0),
-0.008 MiB (H1), and +0.005 MiB (H2). Server receive state remained a separate
server-side metric. Process VmHWM/PSS, transport buffers, server buffering,
temporary storage, and OS page-cache effects remain distinct measurements.

**TC18.** A standalone authenticated framed PBMO server and Android TCP client
were exercised over controlled Wi-Fi for S-W1, S-W4, H0, H1 and H2, each with
one warm-up and five measured runs. Early-abort validation withheld MSM until
the complete request, dimensions, frame/scalar counts, digest and basis were
accepted. The result is one-device integration evidence, not production
channel security, cellular evidence, or all-device Android support.

`V5B_TECHNICAL_CHALLENGE_RECORDS_UPDATED`
