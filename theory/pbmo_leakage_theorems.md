# PBMO Linear Leakage Theorems

The accompanying deterministic experiment is in
`experiments/pbmo_leakage/run.py`. It demonstrates the relations over a small
prime field; the proofs below are field-independent.

## Theorem A: Identical Masks

If `V_j=Z_j+r` and `V_k=Z_k+r`, then

```text
V_j - V_k = (Z_j+r) - (Z_k+r) = Z_j-Z_k.
```

Thus the server learns every row difference relative to one row, giving `q-1`
vector relations. Marker: `PBMO_IDENTICAL_MASK_ATTACK_PASS`.

## Theorem B: Rank-k Masks

Let `V=Z+AB`, where `A in F^(q x k)` and `rank(A)<=k<q`. For any
`c in left_kernel(A)`, `c^T A=0`, so

```text
c^T V = c^T Z + c^T A B = c^T Z.
```

Rank-nullity gives `dim(left_kernel(A))=q-rank(A)>=q-k`. Therefore at least
`q-k` independent linear combinations of complete secret rows are exposed.
Marker: `PBMO_LOW_RANK_MASK_ATTACK_PASS`.

## Theorem C: Public Invertible Mixing

Let the server receive `W=T V` for a public invertible `T`. It computes
`V=T^-1 W`; all attacks on `V` remain available. Equivalently, if the deficient
mask is transformed, invertible multiplication preserves its rank. Public
mixing can reorganize leakage but cannot add secret entropy.
Marker: `PBMO_PUBLIC_MIXING_ATTACK_PASS`.

These theorems rule out identical and deficient-row-rank linear masks. They do
not rule out every computationally pseudorandom structured matrix distribution.

