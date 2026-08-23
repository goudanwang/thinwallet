# Credential Workload Parameterization

The canonical workload is:

`WK(k, r, d, RevBackend)`

| Parameter | Meaning |
| --- | --- |
| `k` | Total credentials jointly presented in one proof. |
| `r` | Credentials whose policy requires a revocation predicate. |
| `d` | Merkle depth; zero for a non-Merkle backend. |
| `RevBackend` | `None`, `ExpiryOnly`, or `SparseMerkle`. Future identifiers are reserved but unimplemented. |

Valid current shapes require `0 <= r <= k`. `SparseMerkle` requires `r > 0`
and `d > 0`; `None` and `ExpiryOnly` require `r = d = 0` in this experiment.

The historical `WK(52,32)` fixture had 52 credential commitments and exactly
one depth-32 revocation path. Its corrected name is
`WK(52,1,32,SparseMerkle)`. The compatibility lookup
`WK_52_32_LEGACY` maps to that shape and must not appear in new claims.

Two suites isolate different effects:

* `WC(k) = WK(k,1,32,SparseMerkle)`, `k in {1,4,10,25,52}`, measures composition.
* `WR(r) = WK(8,r,32,SparseMerkle)`, `r in {1,2,4,8}`, with
  `WK(8,0,0,None)` as its no-revocation baseline, measures policy-selected
  revocation cost.

Result filenames use forms such as `WK_k52_r1_d32_sparse_merkle` and
`WK_k8_r0_d0_none`. Composition and revocation scaling are not interchangeable.
