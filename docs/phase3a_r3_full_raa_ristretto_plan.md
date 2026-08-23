# Phase 3A-R3 Full RAA/Ristretto Plan

## Objective

Replace `RepetitionCodeIntegrationMsmProvider` with a complete RAA/dual-LPN
EMSM construction over the Ristretto255 scalar field while preserving the R2
prover-only provider boundary, proof bytes, transcript semantics, and original
libspartan verifier.

No privacy, malicious-security, performance, or system claim is permitted
until the full construction and its assumptions are implemented and audited.

## Frozen Integration Boundary

Keep the R2 selected call and request binding fixed:

- `msm_id = dense_mlpoly.private_commit.0.chunk.0`;
- 64 witness-dependent scalars for the 4,096-constraint regression relation;
- ordered Ristretto basis digest;
- session, proof, transcript-phase, scalar-count, and request-digest binding;
- one compressed Ristretto point returned before transcript absorption.

The native and plaintext-remote providers remain regression oracles.

## Required RAA Work

1. Specify the exact dual-LPN/RAA encoder over the Ristretto scalar field,
   including dimensions, sparse operators, domain separation, and parameter
   derivation.
2. Implement streaming generation and validation of encoded scalars and basis
   material without discrete-log access or non-canonical encodings.
3. Prove and test the algebraic identity between the native MSM and recovered
   RAA MSM for arbitrary scalar/base vectors, including zero, repeated, and
   malformed cases.
4. Add the production malicious check from the selected construction rather
   than the current equality probe.
5. Bind every correlation artifact, chunk, response, and check challenge to
   the R2 session envelope and reject replay, mixing, truncation, and
   reordering.
6. Measure client work, server work, persistent correlation storage, upload,
   download, and peak RSS separately from libspartan proving.

## Acceptance Gates

- Paper-faithful parameter and equation mapping is complete.
- Native MSM equality passes deterministic and randomized vectors.
- Corrupted scalar, basis, correlation, response, and session material is
  rejected by the production malicious check.
- Exactly one real libspartan private MSM is migrated first; its proof remains
  byte-compatible and the original verifier accepts.
- Security assumptions and concrete parameters are reviewed before scaling to
  all eligible MSMs.
- `INTEGRATION_ONLY_NOT_SECURITY_CLAIM` is removed only after every gate above
  passes; until then it remains mandatory.

The first R3 deliverable is a standalone, paper-mapped RAA/dual-LPN Ristretto
test vector that reproduces the selected native MSM point without using the
repetition-code construction.
