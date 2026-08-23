# Keyed Matrix-RAA Streaming

Result: `KEYED_MATRIX_RAA_STREAMING_FEASIBLE`

Rows of `R=A_s E B_s^T` can be emitted without retaining `Theta(qm)` field
elements in RAM. The tested baseline emits one output row at a time:

1. replay the session-unique deterministic sparse `E` stream;
2. accumulate `u_j=sum_a A_s[j,a]E_a` in one `m`-element row;
3. compute `R_j=B_s u_j` and emit it;
4. discard both rows and repeat for `j+1`.

This uses `2m+O(w_E)` live field elements, zero temporary matrix storage, and
`q` passes over replayable `E`. Its field cost is `q*nnz(E)` plus `q`
applications of `B_s`, so it is a feasibility baseline rather than the fastest
algorithm. Layer-by-layer butterfly or convolution execution can reduce
arithmetic and passes by using external `Theta(qm)` temporary storage; that
tradeoff is recorded separately.

The toy experiment validates every family against a materialized reference and
measures Python allocation at `64 x 64`. Timings use dense toy matrix applies
and are not performance claims. Replay requires a deterministic seed bound to
the current session and request; seed reuse would repeat `E` and break privacy.

