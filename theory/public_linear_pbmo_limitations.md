# Limits Of Public-Linear PBMO Masking

Status: `PBMO_PUBLIC_LINEAR_LIMITATION_THEOREM_COMPLETE`

## Recognizable-Family Theorem

Let `S` be a public mask distribution over `F^(q x m)`. It is efficiently
recognizable for this theorem if an efficient invariant `f` satisfies

```text
f(R) = 0 for every R in the support of S.
```

Suppose there is a public matrix `Delta` such that

```text
Pr_R<-S[f(R + Delta) != 0] >= 1 - negligible(lambda).
```

Then additive masking `V=Z+R` fails chosen-matrix privacy. The adversary chooses
`Z0=0` and `Z1=Delta`, receives the challenge encoding `V`, and returns zero
when `f(V)=0` and one otherwise. It is always correct for `b=0` and correct
with overwhelming probability for `b=1`; its distinguishing advantage is
overwhelming. This proof concerns information leakage, not group-operation
lower bounds.

## Public Linear Subspaces

If `S` is a public linear subspace and `Delta notin S`, then `S` and
`Delta+S` are disjoint cosets. Efficient public membership testing distinguishes
them perfectly. Indeed, an intersection would give `R0=Delta+R1` and hence
`Delta=R0-R1 in S`, a contradiction.

This argument also applies to any efficiently recognizable public affine
family after translating its fixed offset.

## Applications

### Identical rows

The family `R_1=...=R_q` is a public subspace. The invariant can be all row
differences. Any `Delta` with unequal rows lies in a disjoint coset. This is the
same leakage exposed by `V_j-V_k=Z_j-Z_k`.

### Public rank-k row masks

For a fixed public `A in F^(q x k)`, masks `{A B : B in F^(k x m)}` form a
public linear subspace. A left-kernel basis `c` gives invariants `c^T R=0`.
Choosing `Delta` outside that image gives perfect distinguishing.

For the larger nonlinear family of all matrices of rank at most `k`, all
`(k+1)`-minors vanish. The recognizable-family theorem applies to any `Delta`
for which a selected minor of `R+Delta` is nonzero with overwhelming
probability. In particular, if `min(q,m)>2k`, choosing
`rank(Delta)>=2k+1` forces `rank(R+Delta)>k` for every `rank(R)<=k` by the
rank inequality. No stronger claim is made for every parameter regime.

### Public output mixing

For public invertible `T`, the image `T S` is recognizable by
`f_T(X)=f(T^-1 X)`. Public mixing maps disjoint cosets to disjoint cosets and
cannot repair the privacy failure.

### Public product-code masks

If rows or columns must satisfy a public parity-check matrix, such as
`H_out R=0` or `R H_in^T=0`, the valid masks form a public linear subspace.
The syndrome is an efficient invariant. A chosen `Delta` with nonzero syndrome
is perfectly distinguishable. Adding a noise distribution may change this
conclusion, but then privacy needs a separate noisy-code reduction and concrete
parameters.

### Public circulant and Toeplitz masks

Circulant matrices satisfy public cyclic diagonal relations and commute with
the public shift matrix. Toeplitz matrices have constant diagonals and low
displacement rank under standard public shift operators. The pure circulant
and Toeplitz families are public linear subspaces, so a matrix violating those
relations selects a disjoint coset. More elaborate products are covered only
when an efficient invariant remains visible.

## Boundary

The theorem rules out public, efficiently recognizable additive mask families.
It does not prove that a keyed family is private, does not prove a lower bound
on correction work, and does not justify treating a hidden structured family
as pseudorandom. Key reuse may expose new invariants even when one sample does
not.

