# Phase 3A-R libspartan Results

Status:

```text
BACKEND_SELECTION_CONSTRAINT_CORRECTED
LIBSPARTAN_NATIVE_BASELINE_PASS
LIBSPARTAN_OPERATOR_GRAPH_COMPLETE
RISTRETTO_CANONICAL_ENCODING_PASS
RISTRETTO_REAL_MSM_PASS
RISTRETTO_H_GENERATION_PASS
RISTRETTO_V1_PASS
RISTRETTO_V2_PASS
RISTRETTO_STREAMING_EMSM_PASS
RISTRETTO_MALICIOUS_EMSM_PASS
PHASE3A_R_BLOCKED_MSM_API
```

The previous Phase 3A result is reclassified as:

```text
PHASE3A_NO_SUITABLE_BACKEND_UNDER_FIXED_BN254_CONSTRAINT
```

The corrected backend selection for Phase 3A-R is:

```text
libspartan 0.9.0
backend-native Ristretto255 / curve25519-dalek Scalar
```

## Scope

The experiment runs unmodified native libspartan proving and verification
for:

- synthetic multiplication-heavy R1CS;
- 8-bit range-check R1CS;
- toy Merkle-membership slot using a libspartan synthetic fallback.

The Merkle slot is not a cryptographic hash implementation and is not a
completed Merkle-membership circuit. A direct custom toy Merkle sparse
shape exposed libspartan generator-sizing assertions, so the recorded
native proof baseline uses a synthetic fallback and the open issue remains
documented.

## Ristretto EMSM

The Ristretto EMSM harness verifies a backend-native repetition-code EMSM
core:

- canonical scalar encoding;
- canonical compressed point roundtrip;
- invalid compressed point rejection;
- streaming MSM equality;
- `h` generation for the repetition-code basis expansion;
- V1 full rederivation;
- V2 random linear check for the repetition-code relation;
- semi-honest EMSM equality;
- malicious corruption rejection.

It does not claim a complete RAA migration for Ristretto. The earlier RAA
transpose attempt did not pass the equality check and is therefore not
reported as a successful production RAA implementation.

## Stop Reason

The single-MSM adapter is blocked because libspartan 0.9.0 does not expose
a public prover-only MSM provider interface. Replacing exactly one private
MSM would require forking or patching private prover/commitment modules.

No native Spartan verifier or proof format was modified.
