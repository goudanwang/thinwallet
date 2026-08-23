# Phase 2D Group Security

Implemented checks:

```text
CANONICAL_GROUP_ENCODING_PASS
SUBGROUP_VALIDATION_PASS
REAL_GROUP_STREAMING_MSM_PASS
PHASE2D_PRODUCTION_NEGATIVE_TESTS_PASS
```

The Phase 2D decoder accepts only exact-length compressed BN254 G1 encodings
that deserialize canonically, lie on the curve, pass subgroup validation, and
satisfy the identity-point policy.

Rejected cases include:

- trailing bytes;
- damaged compressed bytes;
- identity when forbidden;
- non-canonical encodings;
- malformed server/setup outputs by negative-test inventory.

Remaining caveats:

- BN254 is not a 128-bit-security curve;
- the harness uses naive projective accumulation rather than an optimized
  backend MSM scheduler;
- side-channel resistance is not claimed;
- Android production security is not claimed.

