# V3D Transcript-Dependent Object Audit

Status: `TRANSCRIPT_DEPENDENT_OBJECT_AUDIT_COMPLETE`

All byte counts below are for the `2^18` relation. Transcript challenges are
not known during encoding, so late evaluations cannot be computed eagerly.

| Object | Producer and lifetime | Later dependency and access | Bytes | Decision |
| --- | --- | --- | ---: | --- |
| Dense matrix values | Sparse-to-dense encoding; commitment through dot-product/hash opening | `rand_ops`; sequential product construction and one late MLE query | 25,165,824 | `RETAIN` |
| Row/column operation addresses as Scalars | Address encoding through late hash proof | `rand_ops`; sequential product construction and late MLE query | 50,331,648 | `CHECKPOINT_AND_RECOMPUTE` |
| Row/column read timestamps as Scalars | Timestamp construction through late hash proof | `rand_ops`; sequential product construction and late MLE query | 50,331,648 | `CHECKPOINT_AND_RECOMPUTE` |
| Row/column audit timestamps as Scalars | Timestamp construction through late hash proof | `rand_mem`; sequential audit product and late MLE query | 33,554,432 | `CHECKPOINT_AND_RECOMPUTE` |
| Compact address source | Sparse relation encoding through proof completion | Deterministic canonical scalar regeneration | 12,582,912 | `RETAIN` |
| Compact read/audit timestamp source | Timestamp construction through proof completion | Deterministic canonical scalar regeneration | 20,971,520 | `RETAIN` |
| `comb_ops` opening polynomial | Encoding commitment through late polynomial opening | Transcript-derived joint opening point; two sequential scans | 134,217,728 on disk | `FUSE_WITH_OPENING` |
| `comb_mem` opening polynomial | Encoding commitment through late polynomial opening | Transcript-derived joint opening point; two sequential scans | 33,554,432 on disk | `FUSE_WITH_OPENING` |
| Active product/hash layers | Request-independent source plus `r_mem_check`, then Sumcheck | Round-by-round transcript barriers | Measured in state-store totals | `STREAM_QUERY_ORDER` |
| Dereferenced row/column values | Equality-table dereference through commitment and product proof | `rand_ops` and dot-product claims | Not independently isolated | `RETAIN` |

The checkpoint stores no regenerated Scalar table. It contains a layer ID,
polynomial ID, SHA-256 source digest, table dimensions, and canonical
reconstruction version. The compact source arrays are the deterministic source
reference. On product construction, values are converted to Scalars in the
original canonical order and consumed immediately. After `rand_ops` and
`rand_mem` exist, only the required MLE evaluations are regenerated.

Gross removed Scalar state is 134,217,728 bytes. The newly retained compact
read/audit source is 20,971,520 bytes, giving a 113,246,208-byte logical
reduction. The measured FS4-to-FS5 peak reduction is 115,381,862 bytes against
the frozen FS4 mean. The instrumented FS5 run spent 459.40 ms in the explicitly
timed recomputation sections.

Checkpoint source modification, state truncation, cross-session metadata swap,
wrong fold challenge binding, and corrupted reconstruction source are rejected
by regression tests. Exact proof and transcript equality remains the final
semantic check.

Outputs: `THINWALLET_CHECKPOINT_RECOMPUTE_PASS`,
`DENSE_MLE_LATE_USE_RECOMPUTATION_PASS`,
`ADDRESS_HASH_OPENING_RECOMPUTATION_PASS`, and
`FS5_BUFFER_OVERLAP_REDUCTION_PASS`.
