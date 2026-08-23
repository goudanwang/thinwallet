# Paper Outline

1. Problem and malicious-server threat model for private, memory-bounded,
   single-server proving.
2. Spartan/Sumcheck background and the selected fragmented private commitment.
3. Preprocessed PBMO and FS1-FS6 memory architecture.
4. Dual credential authentication: optimized symmetric Profile M and
   public-key signed-commitment Profile S.
5. Canonical Ed25519 issuance, authenticated issuer registry, signed revocation
   roots, and the external-verification/SNARK binding boundary.
6. Profile S R1CS: commitment opening, holder/nonce binding, disclosure,
   predicates, revocation, and cross-credential relations.
7. Proof/transcript byte identity and unchanged upstream verification.
8. Evaluation: M/S W1-W4, useful `2^14..2^18` padding boundaries, cap matrix,
   latency decomposition, variance, temporary storage, and communication bytes.
9. Security regressions, project-specific MiMC commitment assumptions, and
   software snapshot rollback limitation.
10. Related work using the separately maintained evidence files.
11. Limitations: no W3C interoperability, in-SNARK public-key verification,
   physical Android result, independent audit, or production readiness.
12. Reproducibility and artifact evaluation.
