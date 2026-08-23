# Structured Matrix-RAA Candidate

Algebraic status: `MATRIX_RAA_ALGEBRAIC_CANDIDATE_FOUND`

Security status: `OPEN_NO_MATRIX_PSEUDORANDOMNESS_REDUCTION`

## Equations

Consider

```text
R = G_out E G_in^T,
```

where `G_out in F^(q x a)`, sparse `E in F^(a x b)`, and
`G_in in F^(m x b)`. For the shared group basis `(G_i)`, define

```text
H_b = sum_i G_in[i,b] G_i,
K_a = sum_b E[a,b] H_b,
D_j = sum_a G_out[j,a] K_a.
```

Then, by bilinearity of scalar multiplication and associativity,

```text
D_j
= sum_a G_out[j,a] sum_b E[a,b] sum_i G_in[i,b]G_i
= sum_i (sum_a sum_b G_out[j,a]E[a,b]G_in[i,b])G_i
= sum_i R[j,i]G_i.
```

Therefore server evaluation on `V=Z+R` recovers the exact outputs as
`C_j=MSM(V_j,G)-D_j`. The finite-field additive-group identity test passes in
`experiments/matrix_raa_cost_model/results.json`.

For privacy, `E` (or the entropy from which it is generated) must be fresh and
hidden from the server. If it is public, `R` is public. With persistent
`H=(H_b)`, deriving `K` costs `nnz(E)` client group scalar terms; deriving `D`
then costs the stated `G_out` transform. Thus the non-preprocessed correction
cost is `nnz(E)+cost(G_out*K)`, not only the latter term.

## Structure Audit

| `G_out` family | Client correction work | Setup/storage | Streaming | Required privacy argument | Immediate concern |
| --- | --- | --- | --- | --- | --- |
| Dense random | `nnz(E)+q*a` group scalar terms | `b` persistent `H`, dense descriptor, optional `a` session `K` | row streaming | full matrix-mask pseudorandomness | compression `a<q` gives rank leakage; public factors are invertible/testable |
| Sparse row weight `w` | `nnz(E)+q*w` terms | persistent `H`, sparse descriptor, optional session `K` | yes | matrix dual-LPN/RAA reduction | no reduction here; low rank is immediately broken |
| Circulant/Toeplitz | `nnz(E)+q^2` naive; hoped `nnz(E)+O(q log q)` | `O(q)` descriptor + persistent `H` | block convolution plausible | structured-noisy-code pseudorandomness | public spectrum supplies efficient distinguishing/inversion tests |
| Fast transform | `nnz(E)+O(q log q)` nominal | transform descriptor + persistent `H` | butterfly streaming plausible | full-rank secret entropy and computational hiding | public invertible transform preserves deficient entropy |
| Product code | target `nnz(E)+O(q*w_component)` | component descriptors + persistent `H` | row/block plausible | noisy product-code pseudorandomness | public parity checks expose code relations unless noise closes them |

Here correction work is online when fresh `E` is sampled and `K,D` are derived
per request. If `K` or all `D_j` are precomputed and stored, they are
request-token state; if all `D_j` are stored, the construction has become a
one-time-token baseline with `q` online subtractions and `q` stored group
points; that cost must not be credited to a new online Matrix-RAA reduction.

## Security Gap

Algebraic factorization alone gives no privacy. If the server knows every
factor, it knows `R` and recovers `Z`. If a public factor compresses the row
dimension, the left-kernel attack applies. If the secret entropy is merely
passed through a public invertible transform, distinguishability is unchanged.

A promising construction would need a precisely parameterized matrix
dual-LPN/RAA assumption showing that the complete `q x m` mask is
computationally indistinguishable from the required fresh distribution, while
supporting correction below `q*t`. Phase V0 supplies neither that reduction nor
validated parameters. The candidate is algebraically useful but not promoted
to a secure construction.
