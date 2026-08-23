# Phase V1 Decision

Primary classification:

```text
PHASE_V1_KEYED_MATRIX_RAA_STRUCTURALLY_BROKEN
```

## Gate Evaluation

| Gate | Result |
| --- | --- |
| Algebraic correctness | pass for all five toy transform families |
| Correction below `q*t` | pass in the optimistic row-weight-four symbolic model |
| No immediate structural distinguisher | fail: rank deficiency distinguishes every family |
| Multi-sample analysis | completed for 128 samples per reused key |
| Streaming feasibility | `KEYED_MATRIX_RAA_STREAMING_FEASIBLE` with `q` replay passes |
| Existing assumption/reduction | fail: `KEYED_MATRIX_RAA_REQUIRES_NEW_ASSUMPTION` |

The failure is not caused by a public transform. For every invertible secret
`A_s,B_s`, `rank(A_s E B_s^T)=rank(E)`. The low-weight source selected to obtain
the correction advantage has an efficiently visible support-induced rank
distribution. Secret transforms cannot remove it.

The online Matrix-RAA direction is therefore stopped for the ThinWallet
mainline. The recommended system baseline remains authenticated, non-reusable
preprocessed PBMO with explicit rollback protection. A future research branch
may reconsider a substantially denser source, but it must begin with new
parameters, rerun all structural tests, and supply a chosen-matrix reduction;
it does not inherit a Phase V1 security claim.

This classification is not a production-security claim.

