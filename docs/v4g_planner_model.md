# V4G Phase-Aware Process Memory Model

## Frozen Model

`process-memory-v4g-1` predicts process `VmHWM` as:

```text
max(SourcePhase,
    RelationBuildPhase,
    InstanceFinalizationPhase,
    ProvingPhase,
    PBMOPhase,
    OpeningPhase,
    ProofAssemblyPhase)
```

The canonical coefficients, source revision, feature order, and safety values
are frozen in `planner/models/process_memory_v4g.json`; its SHA-256 is recorded
in `planner/models/process_memory_v4g.sha256`. Only V4G calibration measurements
and implementation-derived formulas were used. The original V4F seven points
and the precommitted V4G final held-out points were prohibited fitting sources.

## Phase State

`SourcePhase` covers the authenticated reader, XChaCha20-Poly1305 frame,
canonical decoding, and credential records. `RelationBuildPhase` covers active
rows, sparse entries, witness construction, MiMC/revocation state, and builder
capacities. `InstanceFinalizationPhase` covers A/B/C materialization,
sorting/finalization, and source objects still live at that barrier.

`ProvingPhase` covers FS7 retained state, Sumcheck and product layers,
address/timestamp state, dereference source, and transcript state. Its M2 and
streaming M3/M4 formulas are distinct. `PBMOPhase`, `OpeningPhase`, and
`ProofAssemblyPhase` model their bounded buffers and mode-specific state. The
model takes the maximum of phase-live overlaps; it does not sum objects from
non-overlapping lifetimes.

## Discrete Dimensions

The model records raw and padded constraints, sparse entries, witness/public
inputs, source bytes, path siblings, `q`, `m`, token/upload bytes, `k`, `r`,
revocation backend, and mode. Sparse matrix capacity uses
`next_power_of_two(max_sparse_matrix_entries)`, so transitions at 2^15, 2^16,
2^17, and 2^18 are explicit rather than treated as a smooth raw-size trend.

## Runtime And Safety

Five release-profile reserve runs measured an irreducible fixed reserve of
2,139,750 bytes and a worker/thread-stack reserve of 157,286 bytes. The measured
post-trim allocator-retained reserve was zero. Workload-dependent state remains
in the phase formulas rather than being folded into the fixed constant.

Expected `VmHWM` is used for the accuracy gate. Execution approval uses:

```text
safe = expected + 604,299 bytes calibrated one-sided residual
                + 8,388,608 bytes required execution margin
```

A process cap is never approved from the expected value alone. Cgroup planning
is separately reported and has no 5% accuracy claim. Its admission policy adds
a 4 MiB service/accounting reserve to the expected process working set and uses
a page-cache policy allowance of `4 MiB + 48 * padded_n` bytes on top of the
safe process bound. This bounded allowance is an empirical admission reserve,
not a prediction of the unconstrained spill cache. Both process and cgroup
bounds must fit the cap.

Markers: `PHASE_AWARE_PROCESS_MEMORY_MODEL_IMPLEMENTED`,
`PLANNER_PADDING_BOUNDARY_MODEL_PASS`,
`PLANNER_WORKLOAD_MODE_FEATURES_PASS`,
`FINAL_RUNTIME_RESERVE_RECALIBRATED`, and
`V4G_PROCESS_MEMORY_MODEL_FROZEN`.
