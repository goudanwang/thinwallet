# Keyed Matrix-RAA Structural Attack Analysis

The executable suite uses `F_65537`, `16 x 16` matrices, four nonzeros per row
of `E`, 128 samples under one key, and fixed seeds. It tests single samples and
reused-key samples. The experiment is evidence of attacks, not evidence of
security when an attack remains `OPEN`.

## Family Results

```text
RANDOM_BUTTERFLY_STRUCTURAL_DISTINGUISHER_FOUND
SPARSE_INVERTIBLE_PRODUCT_STRUCTURAL_DISTINGUISHER_FOUND
BLOCK_CIRCULANT_STRUCTURAL_DISTINGUISHER_FOUND
TOEPLITZ_STRUCTURAL_DISTINGUISHER_FOUND
QUASI_CYCLIC_STRUCTURAL_DISTINGUISHER_FOUND
```

All five preserve the exact rank of `E`. Observed rank-deficiency rates were:

| Family | Deficient masks | Dense random baseline | Rank-test chosen-matrix accuracy |
| --- | ---: | ---: | ---: |
| Random butterfly | 16.41% | 0% | 58.20% |
| Sparse invertible product | 18.75% | 0% | 59.38% |
| Block-circulant | 14.06% | 0% | 57.03% |
| Toeplitz | 21.09% | 0% | 60.55% |
| Quasi-cyclic | 19.53% | 0% | 59.77% |

These constant advantages are already non-negligible. The sparse invertible
product additionally exposed coordinate-zero and minor-zero distributions; the
block-circulant family exposed public zero-block patterns.

## Attack Inventory

- Matrix rank: successful for every family because invertible transforms
  preserve sparse-source rank.
- Row/column spaces: measured across same-key samples; full-rank samples make
  this test vacuous, while deficient samples expose transformed null spaces.
- Low-weight preimage and sparse-basis recovery: the correct inverse is easily
  validated by sparsity; random wrong-key search did not recover it. Efficient
  hidden-dictionary recovery remains `OPEN`.
- Displacement rank and Toeplitz/circulant relations: no universal extra
  distinguisher beyond the reported family-specific block pattern.
- Minors/determinants: determinant-zero is the rank attack; sparse-product
  samples also had excess zero minors.
- Known/chosen plaintext: known plaintext yields raw `R` samples. With
  `Z0=0`, a full-rank shift and the rank test give a chosen-matrix distinguisher.
- Key reuse, covariance, and higher moments: zero rates, minor rates, block
  incidence, and pair differences were measured across 128 samples.
- Butterfly recovery, tensor/Kronecker decomposition, and full
  linearization/Jacobian recovery remain `OPEN`; equation counting identifies
  attack surface but is not a recovery algorithm.

## Scaling Result

The BN254 support experiment found at least one empty column in 62.11%, 89.06%,
99.22%, 100%, and 100% of fixed-seed trials for sizes 64 through 1024 at row
weight four. Empty columns force rank deficiency before field values or
transforms are considered.

Increasing row weight can suppress this particular attack, but the computed
weights only bound empty columns and do not prove full rank, chosen-matrix
privacy, or a code-based reduction.

