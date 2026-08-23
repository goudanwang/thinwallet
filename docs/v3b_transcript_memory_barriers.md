# Phase V3B Transcript Barriers And Target Selection

## Barriers

Sumcheck round messages must be absorbed before each Fiat-Shamir challenge, so a folded table cannot be replayed across that challenge with a different traversal order. FS3 preserves the native order: it loads exactly one precomputed product layer, emits the same batched round polynomial, absorbs the same claims, derives the challenge, then deletes that layer.

PBMO output points and the malicious batch-integrity response are also transcript-bound. FS3 leaves this path unchanged and does not queue unbounded masked scalars or responses. The external `comb_ops` and `comb_mem` tables are immutable canonical scalar streams; their commitment and opening scans preserve native scalar order.

## Decisions

| State | Decision | Reason |
| --- | --- | --- |
| `comb_ops` | SPILL | 128 MiB at `2^18`, two sequential reads, byte-identical FS2 precedent. |
| `comb_mem` | SPILL | 32 MiB, same commitment/opening access pattern as `comb_ops`. |
| Inactive product-circuit layers | SPILL | Dominant FS2 peak; only the current layer is needed by each Sumcheck round. |
| Relation and R1CS instance after last use | RECOMPUTE | Public deterministic state can be dropped before the opening proof and rebuilt for the baseline-verifier check. |
| Sumcheck round message | RETAIN | Small and is the immediate Fiat-Shamir barrier. |
| PBMO token/mask | NOT_SAFE_TO_EXTERNALIZE | Secret, single-use lifecycle and crash semantics outweigh its small memory footprint. |
| Proof fields | RETAIN | Small public output assembled after all dominant state has been released. |

FS3 therefore uses four streamed/spilled/recomputed state classes. The verifier source and API are unchanged.

Status: `THINWALLET_MULTI_TARGET_SELECTION_PASS` and `THINWALLET_FULL_MEMORY_OPERATOR_GRAPH_PASS`.
