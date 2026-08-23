# libspartan Peak Live State

The canonical uncapped native run at `2^18` reached 1,013,972,992 logical
live bytes (967.0 MiB) and a 998,712 KiB VmHWM. The largest independently
observed component peaks were 558.0 MiB for Sumcheck folded tables,
324.69 MiB for sparse polynomial structures, 296.0 MiB for dense
multilinear polynomials, and 116.0 MiB for the R1CS instance. Component
peaks are not additive because their lifetimes differ.

The largest individual allocation was the public, replayable 128 MiB
`SparseMatPolynomial::multi_sparse_to_dense_rep:comb_ops` table. It survives
from dense materialization through commitment and sparse polynomial proof
evaluation. It overlaps a 64 MiB folded table at the decisive late peak.
`comb_ops` is therefore selected as `STREAMING_TARGET_DENSE_MLE_TABLE`:
it is large, deterministically replayable, spillable, and can be consumed in
the original row order without changing transcript or verifier behavior.

The operator/lifetime graph, exact peak cut, edge sizes, regeneration rules,
privacy classes, and transcript dependencies are recorded in
`experiments/v3a_memory/live_operator_graph.json`. Empirical profiles for
`2^12`, `2^14`, `2^16`, and `2^18` are in
`experiments/v3a_memory/memory_component_profile.json`. Model fits are
descriptive only; no model is promoted where the four measured points do not
support it reliably.

```text
LIBSPARTAN_MEMORY_COMPONENT_PROFILE_COMPLETE
LIBSPARTAN_PEAK_LIVE_STATE_IDENTIFIED
STREAMING_TARGET_DENSE_MLE_TABLE
```
