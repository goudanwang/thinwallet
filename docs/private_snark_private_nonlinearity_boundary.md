# Private Nonlinearity Boundary

The redesign audit uses abstract circuit profiles to separate private nonlinear
work from work that might be delegated.

## Definitions

`private_private_mul` is the hardest case. The server cannot compute it from a
masked witness without a private multiplication protocol, preprocessing, or a
different proof system.

`private_public_mul` may be easier. Depending on representation, the server may
be able to compute it if the private value is masked or committed.

`public_public_mul` can be computed by the server.

`linear_constraints` are P1/P4-style offload candidates.

Hash, signature, Merkle, and range constraints are treated as private nonlinear
unless redesigned.

## Profile Results

| Profile | Total constraints | Private nonlinear | Ratio | Linearizable | Classification |
| --- | ---: | ---: | ---: | ---: | --- |
| toy_linear_only | 1,024 | 0 | 0.000 | 1,024 | LINEAR_OFFLOAD_FRIENDLY |
| toy_multiplication_heavy | 4,096 | 3,072 | 0.750 | 1,024 | PHONE_LIGHT_UNLIKELY |
| age_predicate_simple | 98 | 97 | 0.990 | 1 | PHONE_LIGHT_UNLIKELY |
| range_proof_32bit | 32 | 32 | 1.000 | 0 | PHONE_LIGHT_UNLIKELY |
| poseidon_hash_preimage | 850 | 730 | 0.859 | 120 | PHONE_LIGHT_UNLIKELY |
| merkle_path_depth_20 | 16,000 | 14,000 | 0.875 | 2,000 | PHONE_LIGHT_UNLIKELY |
| eddsa_verification | 4,504 | 4,504 | 1.000 | 0 | PHONE_LIGHT_UNLIKELY |
| credential_presentation_small | 804 | 418 | 0.520 | 180 | PRIVATE_NONLINEARITY_HEAVY |
| credential_presentation_realistic | 100,000 | 74,000 | 0.740 | 26,000 | PHONE_LIGHT_UNLIKELY |

Only the toy linear-only profile is clearly offload-friendly. The small
Candidate A-style presentation is better than the old in-circuit holder
authorization path, but it remains private-nonlinearity heavy.
