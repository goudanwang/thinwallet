# Native Proof Compatibility

The unchanged native verifier is the correctness source of truth for Phase 1.

Measured marker: `NATIVE_SUMCHECK_PROOF_COMPATIBILITY_PASS`.

Modes:

- E0 local native proof: accepted by native verifier.
- E1 local native proof plus insecure plaintext remote MSM plumbing: accepted by native verifier.
- E2 streaming Sumcheck plus insecure remote MSM plumbing: transcript verified and compatible with the Phase 1 native proof shape.
- E3 streaming EMSM: not implemented.
- E4 streaming EMSM plus remote authenticated parameters: not implemented.

This is native compatibility for the internal Phase 1 backend only. It is not compatibility with a production Spartan, HyperPlonk, Nova, or Groth16 verifier.

