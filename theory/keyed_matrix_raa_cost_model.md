# Keyed Matrix-RAA Cost Model

Status: `KEYED_MATRIX_RAA_COST_MODEL_COMPLETE`

The machine-readable table evaluates `q=m` in
`{64,128,256,512,1024}` with exactly four nonzero entries per row of fresh
`E`. The values `t=100` and `t=128` are comparative EMSM correction weights,
not independently validated security parameters.

## Accounting

For every family the table separately records:

```text
nnz(E)                         K correction terms
cost_A_group(q)                D transform terms
cost_B_group(m)                one-time G_hat setup
m                              persistent G_hat group points
q*cost_B_field(m)
  + m*cost_A_field(q) + q*m    mask generation field operations
```

The first two terms are compared to `q*t`; final `q` output subtractions are
reported but excluded from both sides of that comparison. Transform keys are
counted as field scalars.

## Symbolic Family Costs

| Family | Key | Apply over field/group | Inversion | Visible structure |
| --- | --- | --- | --- | --- |
| Random butterfly | `Theta(n log n)` | `Theta(n log n)` | reverse layers | low-dimensional factor network |
| Sparse invertible product, depth `d` | `Theta(dn)` | `Theta(dn)` | reverse elementary layers | bounded dependency expansion |
| Block-circulant, block `b` | `Theta(n)` | target `Theta(n log b)`, naive `Theta(nb)` | block spectral solve | public block partition |
| Toeplitz | `2n-1` | convolution target `Theta(n log n)`, naive `Theta(n^2)` | naive `Theta(n^2)` | displacement rank two for key |
| Sparse quasi-cyclic | about `2n` | target `Theta(n log b)`, naive `Theta(nb)` | block back-substitution | circulant block algebra |

The structured group counts are optimistic algorithmic models. This phase does
not implement optimized group FFT/convolution paths, so cost advantage alone
cannot satisfy the Phase V1 `PROMISING` gate.

For butterfly transforms, for example, comparable online correction work is

```text
q*(4 + 2 log2(q)),
```

which is below `q*100` for every evaluated size. Mask generation still performs
`Theta(qm(log q+log m))` field work. The gap is therefore specifically in client
group operations, not total arithmetic.

