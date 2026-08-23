# Curve, field, and library compatibility

| Component | ThinWallet | Official EMSM artifact | Compatible | Conversion required | Security effect | Performance effect |
| --- | --- | --- | --- | --- | --- | --- |
| scalar field | Ristretto255 scalar field | generic `PrimeField`; benches use BN254 Fr | algebraically plausible, not parameter-validated | faithful field-generic port | published 100-bit table is tied to the paper's BN254 evaluation target; Ristretto transfer is unverified | official timings cannot transfer |
| group | Ristretto255 | Arkworks `CurveGroup`; benches BN254 G1 | no direct Rust type compatibility | implement Ristretto adapter | must preserve prime-order group assumptions | MSM/backend behavior changes |
| point encoding | canonical compressed Ristretto, 32 bytes | no EMSM wire protocol; Arkworks affine types | no direct wire compatibility | define canonical Ristretto wire format | decompression/subgroup rejection must remain enforced | encoded sizes differ by chosen curve |
| scalar encoding | canonical 32-byte little endian | no EMSM request serialization | no direct wire compatibility | use existing ThinWallet canonical decoder | prevents malleable/non-canonical requests | small decode overhead |
| subgroup checks | Ristretto decompression | delegated to Arkworks types where serialization is used | conceptually | preserve native decoder | required for sound group operations | not measured |
| MSM backend | dalek variable-time MSM | Arkworks `G::msm` | no | call existing dalek MSM in adapter | no intended semantic change | must be measured independently |
| endomorphisms | none assumed by adapter | backend dependent | yes at protocol level | none | do not add an assumption | backend-specific |
| Fiat--Shamir | Merlin in libspartan | EMSM itself uses no FS transcript | yes | keep EMSM outside transcript until native point is recovered | transcript remains unchanged | none intended |
| RNG | ThinWallet CSPRNG/domain-separated PBMO paths | `thread_rng` in artifact | interface-level only | define fresh per-row CSPRNG sampling | reuse would break privacy | not measured |

## Direct answers

1. The current `G_i` points cannot be passed directly to the official Arkworks
   artifact because they are Ristretto types. They can be consumed by a
   Ristretto-native faithful port.
2. `h=G^T g` uses only field-controlled group addition and can be computed on
   Ristretto. The unresolved issue is concrete parameter security, not the
   group algebra.
3. The artifact's source is generic, but its EMSM benchmarks and paper
   evaluation are concretely BN254. It is not a ready Ristretto artifact.
4. Paper performance results do not survive a backend port as evidence.
   Parameter transfer to Ristretto is also not established by an official
   table or generator audit.
5. Replacing libspartan's proof group with BN254 would change the native proof
   and verifier and is forbidden for a native-compatible baseline.
6. A future EMSM port can be contained inside the prover commitment adapter:
   recover the exact Ristretto point, then continue native blinding,
   serialization, transcript, and verification unchanged.

The conclusion is not `BACKEND_INCOMPATIBLE`: a local adapter port is
algebraically possible. It is not `INTEGRATE_OFFICIAL_ARTIFACT` because direct
types, encodings, parameter evidence, and ordered-row interfaces are absent.

