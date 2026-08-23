# Preprocessed PBMO Correctness

For every row `j`, masking and server evaluation give

```text
Y_j = sum_i (Z[j,i] + R[j,i]) G_i
    = sum_i Z[j,i]G_i + sum_i R[j,i]G_i
    = C_j + D_j.
```

Therefore client recovery yields `Y_j-D_j=C_j`. Chunking does not change the
result because each row's disjoint column intervals partition `[0,m)` and group
addition is associative. The binary server rejects gaps, overlap, duplicate
intervals, wrong order, wrong dimensions, or wrong context digest.

For the malicious batch check,

```text
T = sum_i (sum_j rho_j V[j,i]) G_i
  = sum_j rho_j (sum_i V[j,i] G_i)
  = sum_j rho_j Y_j
  = Y_rho
```

for honest outputs. If returned outputs have a fixed nonzero ordered error
vector `E`, acceptance requires `sum_j rho_j E_j=0`. With `rho` sampled only
after all outputs are committed and modeled as random field challenges, this
holds with probability at most `1/|Fr|`. This check provides output integrity;
it is not the privacy mask.

In the libspartan adapter, PBMO returns exactly the ordered unblinded row points.
The existing source then computes `(C_j + r_j h).compress()` in the upstream
order. No proof field, transcript label/order, verifier source, verifier API, or
R1CS relation is changed.

```text
PREPROCESSED_PBMO_BATCH_INTEGRITY_PASS
GENERIC_PREPROCESSED_PBMO_API_PASS
```

