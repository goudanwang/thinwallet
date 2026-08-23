# ThinWallet Credential Authentication Profiles

## Frozen Profile M

Profile M is the optimized symmetric-key credential-authentication profile.
It uses the existing 91-round native-field MiMC7 PRF-MAC, a symmetric issuer
secret, and an externally authenticated commitment to that secret. It is not a
standard digital-signature credential and does not provide public issuer
verification without the external key-commitment authority.

## Profile S

Profile S is the public-key issuer-authenticated commitment profile. The issuer
signs a hiding native-field credential commitment. The application verifies the
signature and issuer registry entry outside the SNARK. The SNARK proves
knowledge of the commitment opening and evaluates credential predicates over
the same hidden fields.

Output: `THINWALLET_DUAL_AUTHENTICATION_PROFILES_DEFINED`.

## Signature Audit

| Candidate | Audited Rust implementation | Encoding and strictness | Deployment/interoperability | Decision |
| --- | --- | --- | --- | --- |
| Ed25519 | `ed25519-dalek 2.2.0` | RFC 8032, 32-byte key, 64-byte signature; `verify_strict` rejects weak keys and known non-canonical/malleable cases | Mature RFC format, pure Rust/no_std path; suitable for an Android ARM64 Rust build, but no device build was run | Selected |
| ECDSA P-256 | RustCrypto `p256 0.14.0` was audited as an available maintained implementation | SEC1 key encoding and fixed/DER signature choices require an explicit low-S and encoding policy | FIPS 186-5 and broad platform/KMS support | Not selected for this prototype because it adds encoding policy surface without improving the measured external boundary |
| Ristretto Schnorr | `schnorrkel 0.11.5` | Ristretto compressed points and transcript contexts | Useful Rust ecosystem support, but less cross-platform credential interoperability than RFC 8032 Ed25519 | Not selected |

Primary references are [RFC 8032](https://www.rfc-editor.org/info/rfc8032/),
the [`ed25519-dalek` 2.2.0 source and validation tests](https://docs.rs/crate/ed25519-dalek/2.2.0),
[NIST FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final), and the
[`schnorrkel` documentation](https://docs.rs/schnorrkel/0.11.5/schnorrkel/).

The selected backend is pinned by `Cargo.lock`. Profile S performs individual
strict verification only; batch verification is disabled so batch-equation
policy cannot weaken per-credential acceptance. Protocol domain separation is
provided by a fixed prefix in the signed message. Invalid or weak public keys,
malformed signatures, non-canonical package encodings, and trailing bytes are
rejected before proving. Android compatibility is a source-level assessment,
not a physical-device result.

Output: `PUBLIC_KEY_SIGNATURE_BACKEND_SELECTED`.

## Comparison

| Property | Profile M | Profile S |
| --- | --- | --- |
| Issuer key | Symmetric secret | Ed25519 public/private key |
| Public verifiability | Requires external symmetric-key commitment authority | Issuer signature can be checked by any party with the authenticated registry key |
| Circuit authentication | MiMC7 PRF-MAC and key-commitment recomputation | Hiding commitment opening; no Ed25519 gadget |
| Standardization | Project-specific MiMC profile | RFC 8032 signature over a project-specific commitment package |
| Issuance | Native-field MAC; separately timed cost unavailable | External Ed25519 signing measured separately |
| Wallet private storage | Credential fields and issuer-MAC material | Credential fields, random salt, and issuer signature package |
| Registry | Authenticated issuer symmetric-key commitment | Authenticated issuer public-key ID and signed revocation-state key |
| Main caveat | Symmetric trust and non-standard authentication | Commitment hash is project-specific and not independently audited |

Neither profile dominates every deployment model. Profile M minimizes public-key
machinery; Profile S offers standard public-key issuer semantics while retaining
a project-specific native-field commitment assumption.

Output: `PROFILE_M_PROFILE_S_COMPARISON_COMPLETE`.
