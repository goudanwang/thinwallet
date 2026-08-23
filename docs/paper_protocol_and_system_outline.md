# Protocol and System Outline

## Implemented Experimental Path

Profile S authenticates issuer records with Ed25519 (`ed25519-dalek` 2.2.0,
RFC 8032 canonical encoding, `verify_strict`, one signature at a time) outside
the SNARK. The private relation opens a 91-round MiMC7 commitment over the
Ristretto255 scalar field and evaluates credential predicates. The Spartan
proof is generated with the preprocessed malicious PBMO provider and accepted
by the unchanged libspartan 0.9.0 verifier.

FS7 preserves FS6 transcript order while adding file-cache control, direct
external matrix-value construction, chunk-generated product-layer inputs,
compact `u32` address/timestamp tables, explicit relation/prover lifetime
separation, and a credential-shape-aware planner.

## Measured Result

WK(52,32) has 252,855 useful constraints padded to 262,144, `q=m=512`, a
155,632-byte proof, a 16,767-byte token, and an 8,601,600-byte upload. Five
malicious runs succeed under a 248 MiB cgroup limit with zero OOM, zero swap,
byte-identical proofs, and unchanged verifier acceptance.

## Security Scope

The experiment relies on Ed25519 EUF-CMA security, an authenticated issuer
registry, MiMC7 binding/hiding assumptions, Spartan knowledge soundness and
zero knowledge, and Fiat-Shamir assumptions. MiMC7 has not received an
independent audit in this project. Software-only snapshot rollback remains
unprevented.

## Incomplete V4D Work

The relation builder still retains all credential rows before finalization;
there is no authenticated/session-bound compact witness replay source; the WK
fixture has only one revocation path; and the backend still requires complete
A/B/C slices at `Instance::new`. Consequently the primary classification is
`PHASE_V4D_MEMORY_REDUCTION_ONLY`, not the Phase V4D PASS classification.

This is not an Android, W3C VC interoperability, production-wallet, or
independently audited cryptography claim.
