# Keyed Matrix-RAA Over A Large Prime Field

Status: `KEYED_MATRIX_RAA_LARGE_FIELD_ANALYSIS_COMPLETE`

The eventual scalar field is large, such as the BN254 scalar field. Binary LPN
noise rates and attack estimates therefore cannot be copied into this model.

## Sparse Values And Rank

Nonzero entries of `E` should be sampled from a specified high-entropy
distribution, ideally uniform in `F*` for this analysis. Large nonzero values do
not repair sparse-support defects. Because `A_s` and `B_s` are invertible,

```text
rank(A_s E B_s^T) = rank(E).
```

For exactly `w` uniformly selected positions per row, a fixed column is empty
with probability `(1-w/m)^q`. The expected number of empty columns is

```text
m (1-w/m)^q,
```

which is approximately `n exp(-w)` for square `n x n` matrices. Thus constant
`w` eventually produces visible rank deficiency with high probability,
irrespective of the large field or secret transforms.

To make the union bound on any empty column at most `2^-lambda`, it is necessary
for this particular failure mode that

```text
m (1-w/m)^q <= 2^-lambda.
```

For square matrices this requires approximately
`w >= ln(m)+lambda ln(2)`. This is only an empty-column condition, not a
full-rank or pseudorandomness proof.

## Attack Consequences

- Gaussian elimination directly exposes `rank(R)` from known-plaintext mask
  samples and can distinguish the `Z0=0` branch in a chosen-matrix game.
- Empty rows/columns, support collisions, and Hall-type support defects survive
  all invertible transforms as rank defects.
- Over a large field, accidental cancellation of a nonzero determinant is less
  likely than over `F_2`, but combinatorial support defects remain unchanged.
- If transform-key samples become known, support recovery is a sparse coding
  problem over `F_p`, not binary syndrome decoding.
- Linear tests over `F_p`, determinant/minor tests, and hidden-dictionary
  attacks require fresh analysis; binary Walsh/noise estimates do not transfer.

The executable support experiment records fixed-seed empty-column rates for all
required sizes and computes the exact union-bound weights for 100- and 128-bit
comparative targets. Those weights are not security parameters.

