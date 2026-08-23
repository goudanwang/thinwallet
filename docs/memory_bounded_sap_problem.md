# Problem

The target problem is to let a memory-constrained client participate in proof generation while a single server performs most heavy work, without revealing the private witness to that server.

Phase 1 studies the following subproblems:

- FFT-free prover path.
- Streaming witness generation.
- Streaming Sumcheck transcript generation.
- External fold storage.
- Remote MSM boundary.
- Remote proving-parameter retrieval and integrity.
- Compatibility with an unchanged native verifier.

The experiment uses ordinary synthetic and credential-like inputs. It does not use issuer-signed A/T objects, Android code, revocation, or a complete credential presentation.

Success requires bounded client memory, native-proof compatibility, and a privacy-preserving outsourced MSM or equivalent commitment backend. Phase 1 reached native Sumcheck compatibility but remains blocked on streaming EMSM.

