# Phase 2D Crypto Backend

Selected production group:

```text
PRODUCTION_GROUP_BACKEND_SELECTED
```

Backend:

- curve/group: BN254 G1;
- scalar field: BN254 Fr;
- library: Arkworks 0.4;
- compressed point bytes: 32;
- cofactor: 1 for the selected prime-order G1 subgroup representation;
- security estimate: roughly 100-bit classical security;
- serialization: `CanonicalSerialize::serialize_compressed`;
- deserialization: `CanonicalDeserialize::deserialize_compressed`;
- subgroup validation: `is_on_curve` and `is_in_correct_subgroup_assuming_on_curve`;
- MSM: real G1 projective scalar multiplication and accumulation.

This replaces the Phase 2A/2B additive-field group model in the Phase 2D
production-group execution path.

The selected Sumcheck backend remains:

```text
INTERNAL_FFT_FREE_MULTILINEAR_SUMCHECK_PHASE1_BACKEND
```

so the proof-system backend is still architectural, even though the EMSM group
layer now uses real elliptic-curve points.

