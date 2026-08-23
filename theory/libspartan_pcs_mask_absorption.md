# libspartan PCS Mask Absorption Audit

Result: `PCS_AWARE_MASK_ABSORPTION_BLOCKED`

Scope: vendored libspartan 0.9.0 dense multilinear commitment code. No proof
system code was modified.

## Native Commitment

For row `j`, the source computes

```text
Com(Z_j; blind_j) = MSM(Z_j,G) + blind_j*h.
```

`commit_inner` partitions the polynomial into `L_size=q` rows, creates one
independent scalar blind per row, and retains `PolyCommitment.C` as an ordered
vector. Every compressed row point is absorbed into the transcript in order.
The evaluation prover later forms

```text
LZ       = sum_j L_j Z_j
LZ_blind = sum_j L_j blind_j,
```

and the unchanged verifier forms `C_LZ=sum_j L_j C_j` before checking the
native dot-product opening.

Source anchors:

- `experiments/libspartan/vendor/spartan-upstream-0.9.0/src/commitments.rs:80`
- `experiments/libspartan/vendor/spartan-upstream-0.9.0/src/dense_mlpoly.rs:149`
- `experiments/libspartan/vendor/spartan-upstream-0.9.0/src/dense_mlpoly.rs:292`
- `experiments/libspartan/vendor/spartan-upstream-0.9.0/src/dense_mlpoly.rs:347`
- `experiments/libspartan/vendor/spartan-upstream-0.9.0/src/dense_mlpoly.rs:381`

## Why Absorption Fails

An outsourcing mask changes the server point by

```text
Delta_j = MSM(R_j,G).
```

Native PCS blinding can absorb only a known scalar multiple of `h`. For an
arbitrary `R_j`, representing `Delta_j` as `delta_j*h` would require a known
discrete-log relation between the `G`-basis combination and `h`; no such legal
scalar is available. Subtracting `Delta_j` externally recovers the exact native
commitment, which is ordinary PBMO correction rather than mask absorption.

Keeping the masked commitment changes all transcript points and makes the
opening proof concern `Z+R`, not the original witness polynomial. Correcting
only a later aggregate does not restore each exact ordered commitment on which
the transcript and verifier operate. Permitting arbitrary vector masks as
native randomness would require new commitment/opening equations and a changed
soundness proof, violating the unchanged-verifier requirement.

Thus native one-dimensional Pedersen blinding is useful for zero knowledge but
does not supply the vector-valued mask freedom needed by PBMO outsourcing.

