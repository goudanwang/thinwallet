# Keyed Two-Sided Matrix-RAA

Status: `KEYED_MATRIX_RAA_MODEL_COMPLETE`

This is an algebraic candidate and cost model, not a secure construction.

## Algorithms

`Setup(1^lambda,q,m,G)` samples secret invertible transforms
`A_s in F^(q x q)` and `B_s in F^(m x m)` from a named transform family. It
computes and stores on the client

```text
G_hat = B_s^T G,
G_hat[b] = sum_i B_s[i,b] G_i.
```

The transform keys, `G_hat`, basis digest, dimensions, and protocol version are
client setup state. Any implementation that exposes `G_hat` to the server must
include it in the security game and justify the resulting related-basis
assumption.

For each session, `ClientEncode` samples a fresh sparse
`E in F^(q x m)`, computes

```text
R = A_s E B_s^T,
V = Z + R,
```

and streams `V` with session/request binding. `ServerEvaluate` returns
`Y_j=MSM(V_j,G)`. The client computes

```text
K_a = sum_b E[a,b] G_hat[b],
D_j = sum_a A_s[j,a] K_a,
C_j = Y_j - D_j.
```

Fresh `E` is mandatory. Reusing `E` exposes plaintext differences even if the
transform key remains secret.

## Algebraic Correctness

For every row `j`,

```text
D_j
= sum_a A_s[j,a] sum_b E[a,b] sum_i B_s[i,b]G_i
= sum_i (sum_a sum_b A_s[j,a]E[a,b]B_s[i,b])G_i
= sum_i (A_s E B_s^T)[j,i]G_i
= MSM(R_j,G).
```

Therefore `Y_j-D_j=MSM(Z_j,G)`. This uses no discrete logarithm and preserves
all `q` ordered outputs.

## Cost Identity

With `w_E=nnz(E)/q`, online correction costs

```text
nnz(E)                  group scalar terms for K
+ cost_A_group(q)       group operations for D=A_s K
+ q                     final group subtractions.
```

Setup costs `cost_B_group(m)` to form `G_hat` and stores `m` group points.
Mask generation costs `q` applications of `B_s` to row vectors and `m`
applications of `A_s` to column vectors. These field operations and setup work
must be reported separately.

## Claim Boundary

Invertibility preserves correctness and rank; it does not imply privacy.
Security would require the distribution of one or many
`A_s E B_s^T` samples under a reused hidden key to withstand chosen-matrix and
known-plaintext attacks. Phase V1 evaluates that requirement but does not
establish it.

